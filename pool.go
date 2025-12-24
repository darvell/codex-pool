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

// AccountType distinguishes between different API backends.
type AccountType string

const (
	AccountTypeCodex  AccountType = "codex"
	AccountTypeGemini AccountType = "gemini"
	AccountTypeClaude AccountType = "claude"
)

type Account struct {
	mu sync.Mutex

	Type         AccountType // codex, gemini, or claude
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

// applyRateLimitsFromTokenCount updates account usage from Codex token_count rate_limits.
// Format: {primary: {used_percent: 26.5, ...}, secondary: {used_percent: 14.5, ...}}
func (a *Account) applyRateLimitsFromTokenCount(rl map[string]any) {
	if a == nil || rl == nil {
		return
	}
	var primaryPct, secondaryPct float64
	if primary, ok := rl["primary"].(map[string]any); ok {
		if up, ok := primary["used_percent"]; ok {
			switch t := up.(type) {
			case float64:
				primaryPct = t / 100.0
			case int:
				primaryPct = float64(t) / 100.0
			}
		}
	}
	if secondary, ok := rl["secondary"].(map[string]any); ok {
		if up, ok := secondary["used_percent"]; ok {
			switch t := up.(type) {
			case float64:
				secondaryPct = t / 100.0
			case int:
				secondaryPct = float64(t) / 100.0
			}
		}
	}
	if primaryPct == 0 && secondaryPct == 0 {
		return
	}
	newSnap := UsageSnapshot{
		PrimaryUsed:          primaryPct,
		SecondaryUsed:        secondaryPct,
		PrimaryUsedPercent:   primaryPct,
		SecondaryUsedPercent: secondaryPct,
		RetrievedAt:          time.Now(),
		Source:               "token_count",
	}
	a.mu.Lock()
	a.Usage = mergeUsage(a.Usage, newSnap)
	a.mu.Unlock()
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
	PlanType          string
	UserID            string
	PromptCacheKey    string
	RequestID         string
	InputTokens       int64
	CachedInputTokens int64
	OutputTokens      int64
	ReasoningTokens   int64
	BillableTokens    int64
	// Rate limit snapshot after this request
	PrimaryUsedPct   float64
	SecondaryUsedPct float64
}

// AccountUsage stores aggregates for an account with time windows.
type AccountUsage struct {
	TotalInputTokens    int64 `json:"total_input_tokens"`
	TotalCachedTokens   int64 `json:"total_cached_tokens"`
	TotalOutputTokens   int64 `json:"total_output_tokens"`
	TotalReasoningTokens int64 `json:"total_reasoning_tokens"`
	TotalBillableTokens int64 `json:"total_billable_tokens"`
	RequestCount        int64 `json:"request_count"`
	// For calculating tokens-per-percent
	LastPrimaryPct   float64   `json:"last_primary_pct"`
	LastSecondaryPct float64   `json:"last_secondary_pct"`
	LastUpdated      time.Time `json:"last_updated"`
}

// TokenCapacity tracks tokens-per-percent for capacity analysis.
type TokenCapacity struct {
	PlanType               string  `json:"plan_type"`
	SampleCount            int64   `json:"sample_count"`
	TotalTokens            int64   `json:"total_tokens"`
	TotalPrimaryPctDelta   float64 `json:"total_primary_pct_delta"`
	TotalSecondaryPctDelta float64 `json:"total_secondary_pct_delta"`

	// Raw token type totals for weighted estimation
	TotalInputTokens     int64 `json:"total_input_tokens"`
	TotalCachedTokens    int64 `json:"total_cached_tokens"`
	TotalOutputTokens    int64 `json:"total_output_tokens"`
	TotalReasoningTokens int64 `json:"total_reasoning_tokens"`

	// Derived: raw billable tokens per 1% of quota
	TokensPerPrimaryPct   float64 `json:"tokens_per_primary_pct,omitempty"`
	TokensPerSecondaryPct float64 `json:"tokens_per_secondary_pct,omitempty"`

	// Derived: weighted effective tokens per 1% (accounts for token cost differences)
	// Formula: effective = input + (cached * 0.1) + (output * OutputMultiplier) + (reasoning * ReasoningMultiplier)
	EffectivePerPrimaryPct   float64 `json:"effective_per_primary_pct,omitempty"`
	EffectivePerSecondaryPct float64 `json:"effective_per_secondary_pct,omitempty"`

	// Estimated multipliers (refined over time with more data)
	OutputMultiplier    float64 `json:"output_multiplier,omitempty"`    // How much more output costs vs input (typically 3-5x)
	ReasoningMultiplier float64 `json:"reasoning_multiplier,omitempty"` // How much reasoning costs vs input
}

// applyRequestUsage increments aggregate counters for the account.
func (a *Account) applyRequestUsage(u RequestUsage) {
	a.mu.Lock()
	a.Totals.TotalInputTokens += u.InputTokens
	a.Totals.TotalCachedTokens += u.CachedInputTokens
	a.Totals.TotalOutputTokens += u.OutputTokens
	a.Totals.TotalReasoningTokens += u.ReasoningTokens
	a.Totals.TotalBillableTokens += u.BillableTokens
	a.Totals.RequestCount++
	if u.PrimaryUsedPct > 0 {
		a.Totals.LastPrimaryPct = u.PrimaryUsedPct
	}
	if u.SecondaryUsedPct > 0 {
		a.Totals.LastSecondaryPct = u.SecondaryUsedPct
	}
	a.Totals.LastUpdated = u.Timestamp
	a.mu.Unlock()
}

// CodexAuthJSON is the format for Codex auth.json files.
type CodexAuthJSON struct {
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

// GeminiAuthJSON is the format for Gemini oauth_creds.json files.
// Files should be named gemini_*.json in the pool folder.
type GeminiAuthJSON struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiryDate   int64  `json:"expiry_date"` // Unix timestamp in milliseconds
}

// ClaudeAuthJSON is the format for Claude auth files.
// Files should be named claude_*.json in the pool folder.
// Supports both API key format and OAuth format (from Claude Code).
type ClaudeAuthJSON struct {
	// API key format
	APIKey   string `json:"api_key,omitempty"`
	PlanType string `json:"plan_type,omitempty"` // optional: pro, max, etc.

	// OAuth format (from Claude Code keychain)
	ClaudeAiOauth *ClaudeOAuthData `json:"claudeAiOauth,omitempty"`
}

// ClaudeOAuthData is the OAuth token structure from Claude Code.
type ClaudeOAuthData struct {
	AccessToken      string   `json:"accessToken"`
	RefreshToken     string   `json:"refreshToken"`
	ExpiresAt        int64    `json:"expiresAt"` // Unix timestamp in milliseconds
	Scopes           []string `json:"scopes"`
	SubscriptionType string   `json:"subscriptionType"` // pro, max, etc.
	RateLimitTier    string   `json:"rateLimitTier"`
}

func loadPool(dir string, registry *ProviderRegistry) ([]*Account, error) {
	var accs []*Account

	// Load accounts from provider subdirectories: pool/codex/, pool/claude/, pool/gemini/
	providerDirs := map[string]AccountType{
		"codex":  AccountTypeCodex,
		"claude": AccountTypeClaude,
		"gemini": AccountTypeGemini,
	}

	for subdir, accountType := range providerDirs {
		providerDir := filepath.Join(dir, subdir)
		entries, err := os.ReadDir(providerDir)
		if os.IsNotExist(err) {
			continue // Skip if provider directory doesn't exist
		}
		if err != nil {
			return nil, fmt.Errorf("read pool dir %s: %w", providerDir, err)
		}

		provider := registry.ForType(accountType)
		if provider == nil {
			continue
		}

		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			path := filepath.Join(providerDir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", path, err)
			}

			acc, err := provider.LoadAccount(e.Name(), path, data)
			if err != nil {
				return nil, err
			}
			if acc != nil {
				accs = append(accs, acc)
			}
		}
	}

	return accs, nil
}

// Note: Individual account loading functions are now in the provider files:
// - provider_codex.go: CodexProvider.LoadAccount
// - provider_claude.go: ClaudeProvider.LoadAccount
// - provider_gemini.go: GeminiProvider.LoadAccount

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

// candidate selects the best account, optionally filtering by type.
// If accountType is empty, all account types are considered.
func (p *poolState) candidate(conversationID string, exclude map[string]bool, accountType AccountType) *Account {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()

	if conversationID != "" {
		if id, ok := p.convPin[conversationID]; ok {
			if exclude != nil && exclude[id] {
				// pinned excluded; fall through to selection
			} else if a := p.getLocked(id); a != nil {
				a.mu.Lock()
				ok := !a.Dead && !a.Disabled && (accountType == "" || a.Type == accountType)
				// Don't use pinned account if it's overloaded (>70% weekly usage)
				// This prevents conversation pinning from hammering one account
				secondaryUsed := a.Usage.SecondaryUsedPercent
				if secondaryUsed == 0 {
					secondaryUsed = a.Usage.SecondaryUsed
				}
				if secondaryUsed > 0.60 {
					ok = false
					if p.debug {
						log.Printf("unpinning conversation %s from overloaded account %s (%.0f%% weekly)",
							conversationID, id, secondaryUsed*100)
					}
				}
				// Also unpin if token is expired - don't wait for a failed request
				if ok && a.ExpiresAt.Before(now) {
					ok = false
					if p.debug {
						log.Printf("unpinning conversation %s from expired account %s",
							conversationID, id)
					}
				}
				a.mu.Unlock()
				if ok {
					return a
				}
			}
		}
	}

	var best *Account
	bestScore := math.Inf(-1)
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
		if a.Dead || a.Disabled || (accountType != "" && a.Type != accountType) {
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

// countByType returns the number of accounts of a given type (or all if empty).
func (p *poolState) countByType(accountType AccountType) int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if accountType == "" {
		return len(p.accounts)
	}
	count := 0
	for _, a := range p.accounts {
		if a.Type == accountType {
			count++
		}
	}
	return count
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

	// Calculate headroom primarily based on weekly (secondary) usage.
	// Weekly is the real capacity constraint - 5hr resets frequently.
	headroom := 1.0 - secondaryUsed

	// 5hr usage only penalizes when getting critically high (>80%)
	// to avoid immediate rate limits
	if primaryUsed > 0.8 {
		primaryPenalty := (primaryUsed - 0.8) * 2.0 // Scales 0.8->1.0 to 0->0.4 penalty
		headroom -= primaryPenalty
	}

	// expiry risk - be gentle since access tokens often outlive ID token expiry.
	// Accounts that truly fail will get marked dead via 401/403 handling.
	if !a.ExpiresAt.IsZero() {
		ttl := a.ExpiresAt.Sub(now).Minutes()
		if ttl < 0 {
			headroom -= 0.3 // Expired but may still work - mild penalty
		} else if ttl < 30 {
			headroom -= 0.2
		} else if ttl < 60 {
			headroom -= 0.1
		}
	}
	headroom -= a.Penalty
	if headroom < 0.01 {
		headroom = 0.01
	}

	// Plan preference: Drain Plus accounts first (until 80% used), then fall back to Pro/Team.
	planPreference := planPreferenceMultiplier(a.PlanType, secondaryUsed)

	// credits bonuses
	creditBonus := 1.0
	if a.Usage.CreditsUnlimited || a.Usage.HasCredits {
		creditBonus = 1.1
	}

	return headroom * planPreference * creditBonus
}

// planPreferenceMultiplier returns a multiplier that affects account selection preference.
// We drain Plus accounts first (until 80% used), then fall back to Pro/Team.
// Higher value = more preferred.
func planPreferenceMultiplier(planType string, secondaryUsedPct float64) float64 {
	switch planType {
	case "plus":
		// Drain Plus first - prefer until 80% used
		if secondaryUsedPct < 0.8 {
			return 1.4 // Highest preference when has capacity
		}
		return 0.8 // Deprioritize when nearly full
	case "pro":
		return 1.0 // Normal preference - save for when Plus is drained
	case "team":
		return 1.0 // Same as Pro
	case "enterprise":
		return 1.1 // Slight preference for enterprise
	case "gemini":
		return 1.0 // Gemini has its own quota system
	default:
		return 1.0
	}
}

func (p *poolState) pin(conversationID, accountID string) {
	if conversationID == "" || accountID == "" {
		return
	}
	p.mu.Lock()
	p.convPin[conversationID] = accountID
	p.mu.Unlock()
}

// allAccounts returns a copy of all accounts for stats/reporting.
func (p *poolState) allAccounts() []*Account {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*Account, len(p.accounts))
	copy(out, p.accounts)
	return out
}

// saveAccount persists the account back to its auth.json file.
func saveAccount(a *Account) error {
	if a == nil {
		return fmt.Errorf("nil account")
	}
	if strings.TrimSpace(a.File) == "" {
		return fmt.Errorf("account %s has empty file path", a.ID)
	}

	if a.Type == AccountTypeGemini {
		return saveGeminiAccount(a)
	}
	return saveCodexAccount(a)
}

func saveCodexAccount(a *Account) error {
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

	return atomicWriteJSON(a.File, root)
}

func saveGeminiAccount(a *Account) error {
	// Preserve existing fields in the file
	raw, err := os.ReadFile(a.File)
	if err != nil {
		return err
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("parse %s: %w", a.File, err)
	}

	// Update token fields
	if a.AccessToken != "" {
		root["access_token"] = a.AccessToken
	}
	if a.RefreshToken != "" {
		root["refresh_token"] = a.RefreshToken
	}
	if !a.ExpiresAt.IsZero() {
		root["expiry_date"] = a.ExpiresAt.UnixMilli()
	}

	return atomicWriteJSON(a.File, root)
}

func atomicWriteJSON(filePath string, data any) error {
	updated, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	// Atomic write: write to temp file then rename.
	dir := filepath.Dir(filePath)
	tmp, err := os.CreateTemp(dir, "*.tmp")
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
	return os.Rename(tmpName, filePath)
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

// UsagePoolStats contains aggregate stats about the pool for the usage endpoint.
type UsagePoolStats struct {
	TotalCount       int            `json:"total_count"`
	HealthyCount     int            `json:"healthy_count"`
	DeadCount        int            `json:"dead_count"`
	CodexCount       int            `json:"codex_count"`
	GeminiCount      int            `json:"gemini_count"`
	ClaudeCount      int            `json:"claude_count"`
	AvgPrimaryUsed   float64        `json:"avg_primary_used"`
	AvgSecondaryUsed float64        `json:"avg_secondary_used"`
	MinSecondaryUsed float64        `json:"min_secondary_used"`
	MaxSecondaryUsed float64        `json:"max_secondary_used"`
	Accounts         []AccountBrief `json:"accounts"`
}

// AccountBrief is a summary of an account for the usage endpoint.
type AccountBrief struct {
	ID           string  `json:"id"`
	Type         string  `json:"type"`
	Plan         string  `json:"plan"`
	Status       string  `json:"status"` // "healthy", "dead", "disabled"
	PrimaryPct   int     `json:"primary_pct"`
	SecondaryPct int     `json:"secondary_pct"`
	Score        float64 `json:"score"`
}

// getPoolStats returns aggregate stats about the pool.
func (p *poolState) getPoolStats() UsagePoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := time.Now()
	stats := UsagePoolStats{
		TotalCount:       len(p.accounts),
		MinSecondaryUsed: 1.0,
	}

	var totalP, totalS float64
	var healthyCount int

	for _, a := range p.accounts {
		a.mu.Lock()

		// Count by type
		switch a.Type {
		case AccountTypeCodex:
			stats.CodexCount++
		case AccountTypeGemini:
			stats.GeminiCount++
		case AccountTypeClaude:
			stats.ClaudeCount++
		}

		// Determine status
		status := "healthy"
		if a.Dead {
			status = "dead"
			stats.DeadCount++
		} else if a.Disabled {
			status = "disabled"
		} else {
			stats.HealthyCount++
		}

		// Get usage
		primaryUsed := a.Usage.PrimaryUsedPercent
		if primaryUsed == 0 {
			primaryUsed = a.Usage.PrimaryUsed
		}
		secondaryUsed := a.Usage.SecondaryUsedPercent
		if secondaryUsed == 0 {
			secondaryUsed = a.Usage.SecondaryUsed
		}

		// Track min/max for healthy accounts
		if !a.Dead && !a.Disabled {
			healthyCount++
			totalP += primaryUsed
			totalS += secondaryUsed
			if secondaryUsed < stats.MinSecondaryUsed {
				stats.MinSecondaryUsed = secondaryUsed
			}
			if secondaryUsed > stats.MaxSecondaryUsed {
				stats.MaxSecondaryUsed = secondaryUsed
			}
		}

		score := 0.0
		if !a.Dead && !a.Disabled {
			score = scoreAccountLocked(a, now)
		}

		stats.Accounts = append(stats.Accounts, AccountBrief{
			ID:           a.ID,
			Type:         string(a.Type),
			Plan:         a.PlanType,
			Status:       status,
			PrimaryPct:   int(primaryUsed * 100),
			SecondaryPct: int(secondaryUsed * 100),
			Score:        score,
		})

		a.mu.Unlock()
	}

	if healthyCount > 0 {
		stats.AvgPrimaryUsed = totalP / float64(healthyCount)
		stats.AvgSecondaryUsed = totalS / float64(healthyCount)
	}
	if stats.MinSecondaryUsed > stats.MaxSecondaryUsed {
		stats.MinSecondaryUsed = 0
	}

	return stats
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
