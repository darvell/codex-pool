package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Account struct {
	mu sync.Mutex

	ID           string
	File         string
	Label        string
	AccessToken  string
	RefreshToken string
	IDToken      string
	// AccountID corresponds to Codex `auth.json` field `tokens.account_id`.
	// Codex uses this value as the `ChatGPT-Account-ID` header.
	AccountID string
	// IDTokenChatGPTAccountID is the `chatgpt_account_id` claim extracted from the ID token.
	// We keep it for debugging/fallback but prefer AccountID when present.
	IDTokenChatGPTAccountID string
	PlanType                string
	Disabled                bool
	Inflight                int64
	ExpiresAt               time.Time
	LastRefresh             time.Time
	Usage                   UsageSnapshot
	Penalty                 float64
	LastPenalty             time.Time
	Dead                    bool
	LastUsed                time.Time

	// Aggregated token counters (in-memory for now; persist later)
	Totals AccountUsage
}

func (a *Account) applyRateLimitObject(rl map[string]interface{}) {
	primaryUsed := readUsedPercent(rl, "primary_window")
	secondaryUsed := readUsedPercent(rl, "secondary_window")
	if primaryUsed == 0 && secondaryUsed == 0 {
		return
	}
	newSnap := UsageSnapshot{
		PrimaryUsed:          primaryUsed,
		SecondaryUsed:        secondaryUsed,
		PrimaryUsedPercent:   primaryUsed,
		SecondaryUsedPercent: secondaryUsed,
		RetrievedAt:          time.Now(),
		Source:               "body",
	}
	a.mu.Lock()
	a.Usage = mergeUsage(a.Usage, newSnap)
	a.mu.Unlock()
}

func readUsedPercent(rl map[string]interface{}, key string) float64 {
	v, ok := rl[key]
	if !ok {
		return 0
	}
	obj, ok := v.(map[string]interface{})
	if !ok {
		return 0
	}
	if up, ok := obj["used_percent"]; ok {
		switch t := up.(type) {
		case float64:
			return t / 100.0
		case int:
			return float64(t) / 100.0
		}
	}
	return 0
}

// UsageSnapshot captures Codex usage headroom and optional credit info.
// PrimaryUsed/SecondaryUsed are kept for backward compatibility; values are 0-1.
type UsageSnapshot struct {
	PrimaryUsed            float64
	SecondaryUsed          float64
	PrimaryUsedPercent     float64
	SecondaryUsedPercent   float64
	PrimaryWindowMinutes   int
	SecondaryWindowMinutes int
	PrimaryResetAt         time.Time
	SecondaryResetAt       time.Time
	CreditsBalance         float64
	HasCredits             bool
	CreditsUnlimited       bool
	RetrievedAt            time.Time
	Source                 string
}

// RequestUsage captures per-request token consumption parsed from SSE events.
type RequestUsage struct {
	Timestamp         time.Time
	AccountID         string
	UserID            string
	PromptCacheKey    string
	RequestID         string
	InputTokens       int64
	CachedInputTokens int64
	OutputTokens      int64
	BillableTokens    int64
}

// AccountUsage stores simple aggregates for an account.
type AccountUsage struct {
	TotalInputTokens    int64
	TotalCachedTokens   int64
	TotalOutputTokens   int64
	TotalBillableTokens int64
}

// applyRequestUsage increments aggregate counters for the account.
func (a *Account) applyRequestUsage(u RequestUsage) {
	a.mu.Lock()
	a.Totals.TotalInputTokens += u.InputTokens
	a.Totals.TotalCachedTokens += u.CachedInputTokens
	a.Totals.TotalOutputTokens += u.OutputTokens
	a.Totals.TotalBillableTokens += u.BillableTokens
	a.mu.Unlock()
}

type AuthJSON struct {
	OpenAIKey   *string    `json:"OPENAI_API_KEY"`
	Tokens      *TokenData `json:"tokens"`
	LastRefresh *time.Time `json:"last_refresh"`
}

type TokenData struct {
	IDToken      string  `json:"id_token"`
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token"`
	AccountID    *string `json:"account_id"`
}

func loadPool(dir string) ([]*Account, error) {
	var accs []*Account
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read pool dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var aj AuthJSON
		if err := json.Unmarshal(data, &aj); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if aj.Tokens == nil {
			continue
		}
		acc := &Account{
			ID:           strings.TrimSuffix(e.Name(), filepath.Ext(e.Name())),
			File:         path,
			AccessToken:  aj.Tokens.AccessToken,
			RefreshToken: aj.Tokens.RefreshToken,
			IDToken:      aj.Tokens.IDToken,
		}
		if aj.Tokens.AccountID != nil {
			acc.AccountID = strings.TrimSpace(*aj.Tokens.AccountID)
		}
		claims := parseClaims(aj.Tokens.IDToken)
		acc.IDTokenChatGPTAccountID = claims.ChatGPTAccountID
		if acc.AccountID == "" && acc.IDTokenChatGPTAccountID != "" {
			acc.AccountID = acc.IDTokenChatGPTAccountID
		}
		acc.PlanType = claims.PlanType
		acc.ExpiresAt = claims.ExpiresAt
		if acc.ExpiresAt.IsZero() && aj.LastRefresh != nil {
			acc.ExpiresAt = aj.LastRefresh.Add(20 * time.Hour)
		}
		if aj.LastRefresh != nil {
			acc.LastRefresh = *aj.LastRefresh
		}
		accs = append(accs, acc)
	}
	return accs, nil
}

type jwtClaims struct {
	ExpiresAt        time.Time
	ChatGPTAccountID string
	PlanType         string
}

func parseClaims(idToken string) jwtClaims {
	var out jwtClaims
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return out
	}
	payloadB64 := parts[1]
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return out
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return out
	}
	if exp, ok := payload["exp"].(float64); ok {
		out.ExpiresAt = time.Unix(int64(exp), 0)
	}
	// account id may live at top-level or under auth claim
	if acc, ok := payload["chatgpt_account_id"].(string); ok {
		out.ChatGPTAccountID = acc
	}
	if auth, ok := payload["https://api.openai.com/auth"].(map[string]interface{}); ok {
		if acc, ok := auth["chatgpt_account_id"].(string); ok && acc != "" {
			out.ChatGPTAccountID = acc
		}
		if plan, ok := auth["chatgpt_plan_type"].(string); ok {
			out.PlanType = plan
		}
	}
	if out.PlanType == "" {
		out.PlanType = "pro"
	}
	return out
}

// poolState wraps accounts with a mutex.
type poolState struct {
	mu       sync.RWMutex
	accounts []*Account
	convPin  map[string]string // conversation_id -> account ID
	debug    bool
	rr       uint64
}

func newPoolState(accs []*Account, debug bool) *poolState {
	return &poolState{accounts: accs, convPin: map[string]string{}, debug: debug}
}

// replace swaps the pool accounts (used on reload).
func (p *poolState) replace(accs []*Account) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.accounts = accs
	p.convPin = map[string]string{}
	p.rr = 0
}

func (p *poolState) count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.accounts)
}

func (p *poolState) candidate(conversationID string, exclude map[string]bool) *Account {
	p.mu.Lock()
	defer p.mu.Unlock()

	if conversationID != "" {
		if id, ok := p.convPin[conversationID]; ok {
			if exclude != nil && exclude[id] {
				// pinned excluded; fall through to selection
			} else if a := p.getLocked(id); a != nil {
				a.mu.Lock()
				ok := !a.Dead && !a.Disabled
				a.mu.Unlock()
				if ok {
					return a
				}
			}
		}
	}

	var best *Account
	bestScore := math.Inf(-1)
	now := time.Now()
	n := len(p.accounts)
	if n == 0 {
		return nil
	}
	start := int(p.rr % uint64(n))
	for i := 0; i < n; i++ {
		a := p.accounts[(start+i)%n]
		if exclude != nil && exclude[a.ID] {
			continue
		}
		a.mu.Lock()
		if a.Dead || a.Disabled {
			a.mu.Unlock()
			continue
		}
		score := scoreAccountLocked(a, now)
		a.mu.Unlock()
		// Slightly prefer less-loaded accounts to reduce tail latency.
		score -= float64(atomic.LoadInt64(&a.Inflight)) * 0.02
		if score > bestScore {
			bestScore = score
			best = a
		}
	}
	if best != nil {
		p.rr++
	}
	return best
}

func scoreAccount(a *Account, now time.Time) float64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return scoreAccountLocked(a, now)
}

func scoreAccountLocked(a *Account, now time.Time) float64 {
	decayPenaltyLocked(a, now)
	primaryUsed := a.Usage.PrimaryUsedPercent
	secondaryUsed := a.Usage.SecondaryUsedPercent
	if primaryUsed == 0 && a.Usage.PrimaryUsed > 0 {
		primaryUsed = a.Usage.PrimaryUsed
	}
	if secondaryUsed == 0 && a.Usage.SecondaryUsed > 0 {
		secondaryUsed = a.Usage.SecondaryUsed
	}
	headroom := 1.0
	if primaryUsed > 0 {
		headroom = math.Min(headroom, 1.0-primaryUsed)
	}
	if secondaryUsed > 0 {
		headroom = math.Min(headroom, 1.0-secondaryUsed)
	}
	// expiry risk
	if !a.ExpiresAt.IsZero() {
		ttl := a.ExpiresAt.Sub(now).Minutes()
		if ttl < 0 {
			headroom -= 1
		} else if ttl < 30 {
			headroom -= 0.5
		} else if ttl < 60 {
			headroom -= 0.2
		}
	}
	headroom -= a.Penalty
	if headroom < 0.01 {
		headroom = 0.01
	}

	// plan/credits bonuses
	planBonus := 1.0
	switch a.PlanType {
	case "pro":
		planBonus = 1.1
	case "enterprise":
		planBonus = 1.2
	}
	creditBonus := 1.0
	if a.Usage.CreditsUnlimited || a.Usage.HasCredits {
		creditBonus = 1.1
	}

	return headroom * planBonus * creditBonus
}

func (p *poolState) pin(conversationID, accountID string) {
	if conversationID == "" || accountID == "" {
		return
	}
	p.mu.Lock()
	p.convPin[conversationID] = accountID
	p.mu.Unlock()
}

// saveAccount persists the account back to its auth.json file.
func saveAccount(a *Account) error {
	if a == nil {
		return fmt.Errorf("nil account")
	}
	if strings.TrimSpace(a.File) == "" {
		return fmt.Errorf("account %s has empty file path", a.ID)
	}

	// Preserve ALL fields in the original auth.json by modifying only token fields that
	// refresh updates. If we can't parse the existing file, fail closed to avoid
	// clobbering user-provided auth.json content.
	raw, err := os.ReadFile(a.File)
	if err != nil {
		return err
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("parse %s: %w", a.File, err)
	}

	tokensAny := root["tokens"]
	tokens, ok := tokensAny.(map[string]any)
	if !ok || tokens == nil {
		tokens = map[string]any{}
		root["tokens"] = tokens
	}

	// Only update the minimum set of fields we own.
	if a.AccessToken != "" {
		tokens["access_token"] = a.AccessToken
	}
	if a.RefreshToken != "" {
		tokens["refresh_token"] = a.RefreshToken
	}
	if a.IDToken != "" {
		tokens["id_token"] = a.IDToken
	}

	// Preserve tokens.account_id unless it is missing and we have a value.
	if _, exists := tokens["account_id"]; !exists && strings.TrimSpace(a.AccountID) != "" {
		tokens["account_id"] = strings.TrimSpace(a.AccountID)
	}

	if !a.LastRefresh.IsZero() {
		root["last_refresh"] = a.LastRefresh.UTC().Format(time.RFC3339Nano)
	}

	updated, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}

	// Atomic write: write to temp file then rename.
	dir := filepath.Dir(a.File)
	tmp, err := os.CreateTemp(dir, "auth.json.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(updated); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, a.File)
}

// mergeUsage blends a newer usage snapshot with prior data, preserving meaningful
// fields that were absent or zeroed in the new payload.
func mergeUsage(prev, next UsageSnapshot) UsageSnapshot {
	res := next
	hardSource := res.Source == "body" || res.Source == "headers" || res.Source == "wham"
	hardReset := res.PrimaryUsedPercent == 0 && res.SecondaryUsedPercent == 0

	if res.PrimaryUsedPercent == 0 && prev.PrimaryUsedPercent > 0 && !(hardSource && hardReset) {
		res.PrimaryUsedPercent = prev.PrimaryUsedPercent
	}
	if res.SecondaryUsedPercent == 0 && prev.SecondaryUsedPercent > 0 && !(hardSource && hardReset) {
		res.SecondaryUsedPercent = prev.SecondaryUsedPercent
	}
	if res.PrimaryUsed == 0 && prev.PrimaryUsed > 0 && !(hardSource && hardReset) {
		res.PrimaryUsed = prev.PrimaryUsed
	}
	if res.SecondaryUsed == 0 && prev.SecondaryUsed > 0 && !(hardSource && hardReset) {
		res.SecondaryUsed = prev.SecondaryUsed
	}
	if res.PrimaryWindowMinutes == 0 && prev.PrimaryWindowMinutes > 0 {
		res.PrimaryWindowMinutes = prev.PrimaryWindowMinutes
	}
	if res.SecondaryWindowMinutes == 0 && prev.SecondaryWindowMinutes > 0 {
		res.SecondaryWindowMinutes = prev.SecondaryWindowMinutes
	}
	if res.PrimaryResetAt.IsZero() && !prev.PrimaryResetAt.IsZero() {
		res.PrimaryResetAt = prev.PrimaryResetAt
	}
	if res.SecondaryResetAt.IsZero() && !prev.SecondaryResetAt.IsZero() {
		res.SecondaryResetAt = prev.SecondaryResetAt
	}
	if res.CreditsBalance == 0 && prev.CreditsBalance > 0 {
		res.CreditsBalance = prev.CreditsBalance
	}
	res.HasCredits = res.HasCredits || prev.HasCredits
	res.CreditsUnlimited = res.CreditsUnlimited || prev.CreditsUnlimited

	if res.RetrievedAt.IsZero() || (!prev.RetrievedAt.IsZero() && prev.RetrievedAt.After(res.RetrievedAt)) {
		res.RetrievedAt = prev.RetrievedAt
	}
	if res.Source == "" {
		res.Source = prev.Source
	}
	return res
}

func (p *poolState) getLocked(id string) *Account {
	for _, a := range p.accounts {
		if a.ID == id {
			return a
		}
	}
	return nil
}

// averageUsage produces a synthetic usage payload across all alive accounts.
func (p *poolState) averageUsage() UsageSnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var totalP, totalS float64
	var totalPW, totalSW float64
	var nP, nS float64
	var n float64
	for _, a := range p.accounts {
		if a.Dead {
			continue
		}
		usedP := a.Usage.PrimaryUsedPercent
		if usedP == 0 {
			usedP = a.Usage.PrimaryUsed
		}
		usedS := a.Usage.SecondaryUsedPercent
		if usedS == 0 {
			usedS = a.Usage.SecondaryUsed
		}
		totalP += usedP
		totalS += usedS
		n += 1
		if a.Usage.PrimaryWindowMinutes > 0 {
			totalPW += float64(a.Usage.PrimaryWindowMinutes)
			nP += 1
		}
		if a.Usage.SecondaryWindowMinutes > 0 {
			totalSW += float64(a.Usage.SecondaryWindowMinutes)
			nS += 1
		}
	}
	if n == 0 {
		return UsageSnapshot{}
	}
	return UsageSnapshot{
		PrimaryUsed:            totalP / n,
		SecondaryUsed:          totalS / n,
		PrimaryUsedPercent:     totalP / n,
		SecondaryUsedPercent:   totalS / n,
		PrimaryWindowMinutes:   int(totalPW / max(1, nP)),
		SecondaryWindowMinutes: int(totalSW / max(1, nS)),
		RetrievedAt:            time.Now(),
	}
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// decayPenalty slowly reduces penalties over time to avoid permanent punishment.
func decayPenalty(a *Account, now time.Time) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	decayPenaltyLocked(a, now)
}

func decayPenaltyLocked(a *Account, now time.Time) {
	if a.LastPenalty.IsZero() {
		a.LastPenalty = now
		return
	}
	if now.Sub(a.LastPenalty) < 5*time.Minute {
		return
	}
	// decay 20% every 5 minutes.
	a.Penalty *= 0.8
	if a.Penalty < 0.01 {
		a.Penalty = 0
	}
	a.LastPenalty = now
}

func (p *poolState) debugf(format string, args ...any) {
	if p == nil || !p.debug {
		return
	}
	log.Printf(format, args...)
}
