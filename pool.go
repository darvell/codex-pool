package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AccountType distinguishes between different API backends.
type AccountType string

const (
	AccountTypeCodex       AccountType = "codex"
	AccountTypeGemini      AccountType = "gemini"
	AccountTypeAntigravity AccountType = "antigravity"
	AccountTypeClaude      AccountType = "claude"
	AccountTypeKimi        AccountType = "kimi"
	AccountTypeMinimax     AccountType = "minimax"
	AccountTypeZAI         AccountType = "zai"
	AccountTypeXiaomi      AccountType = "xiaomi"
	AccountTypeGrok        AccountType = "grok"
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
	RateLimitTier           string
	Disabled                bool
	Inflight                int64
	ImageGenerationSupport  int32
	ImageGenerationFailures int32
	ImageGenerationRetryAt  int64
	ExpiresAt               time.Time
	LastRefresh             time.Time
	AddedAt                 time.Time
	Usage                   UsageSnapshot
	Penalty                 float64
	LastPenalty             time.Time
	Dead                    bool
	LastUsed                time.Time
	RateLimitUntil          time.Time
	BackoffLevel            int // exponent: cooldown = min(1s * 2^level, 30m)
	AllowedSourceIPs        []string
	AccountUUID             string // Anthropic internal account UUID, learned from /api/claude_cli/bootstrap
	CyberAccess             bool
	CodexCookies            map[string]string
	RateLimitResetCredits   []RateLimitResetCredit
	ResetCreditsAvailable   int
	ResetCreditsRetrievedAt time.Time
	ResetCreditRedeeming    bool
	Email                   string
	ProjectID               string
	ModelRateLimits         map[string]time.Time
	NeedsVerification       bool
	VerificationURL         string
	HealthError             string

	// Aggregated token counters (in-memory for now; persist later)
	Totals AccountUsage
}

type RateLimitResetCredit struct {
	ID        string
	ExpiresAt time.Time
}

type accountUsageSnapshot struct {
	Type           AccountType
	Dead           bool
	Disabled       bool
	RateLimitUntil time.Time
	Usage          UsageSnapshot
}

func snapshotAccountUsage(a *Account) accountUsageSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	return accountUsageSnapshot{
		Type:           a.Type,
		Dead:           a.Dead,
		Disabled:       a.Disabled,
		RateLimitUntil: a.RateLimitUntil,
		Usage:          a.Usage,
	}
}

func (a *Account) applyRateLimitObject(rl map[string]any) {
	if a == nil {
		return
	}
	newSnap, ok := parseCodexRateLimitMap(rl, time.Now(), "body")
	if !ok {
		return
	}
	a.mu.Lock()
	a.Usage = mergeUsage(a.Usage, newSnap)
	a.mu.Unlock()
}

// applyRateLimitsFromTokenCount updates account usage from Codex token_count rate_limits.
func (a *Account) applyRateLimitsFromTokenCount(rl map[string]any) {
	if a == nil {
		return
	}
	newSnap, ok := parseCodexRateLimitMap(rl, time.Now(), "token_count")
	if !ok {
		return
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
	primarySet             bool
	secondarySet           bool
	creditsSet             bool
}

// RequestUsage captures per-request token consumption parsed from SSE events.
type RequestUsage struct {
	Timestamp           time.Time
	AccountID           string
	PlanType            string
	UserID              string
	OriginID            string
	PromptCacheKey      string
	RequestID           string
	InputTokens         int64
	CachedInputTokens   int64 // cache_read_input_tokens (cheap reads from cache)
	CacheCreationTokens int64 // cache_creation_input_tokens (expensive writes to cache)
	OutputTokens        int64
	ReasoningTokens     int64
	BillableTokens      int64
	// Rate limit snapshot after this request
	PrimaryUsedPct   float64
	SecondaryUsedPct float64
	// Model and provider info
	Model       string      `json:"model,omitempty"`        // e.g., "claude-sonnet-4-5-20250929", "o4-mini"
	AccountType AccountType `json:"account_type,omitempty"` // "claude", "codex", "gemini"
}

// AccountUsage stores aggregates for an account with time windows.
type AccountUsage struct {
	TotalInputTokens     int64   `json:"total_input_tokens"`
	TotalCachedTokens    int64   `json:"total_cached_tokens"`
	TotalOutputTokens    int64   `json:"total_output_tokens"`
	TotalReasoningTokens int64   `json:"total_reasoning_tokens"`
	TotalBillableTokens  int64   `json:"total_billable_tokens"`
	TotalCostEstimate    float64 `json:"total_cost_estimate"`
	RequestCount         int64   `json:"request_count"`
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
	OpenAIKey        *string           `json:"OPENAI_API_KEY"`
	Tokens           *TokenData        `json:"tokens"`
	LastRefresh      *time.Time        `json:"last_refresh"`
	Dead             bool              `json:"dead"`
	AllowedIP        string            `json:"allowed_ip"`
	AllowedSourceIPs []string          `json:"allowed_source_ips"`
	CyberAccess      bool              `json:"cyber_access"`
	CodexCookies     map[string]string `json:"cookies"`
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
	ExpiryDate   int64  `json:"expiry_date"`  // Unix timestamp in milliseconds
	PlanType     string `json:"plan_type"`    // e.g., "ultra", "gemini"
	LastRefresh  string `json:"last_refresh"` // RFC3339 timestamp of last refresh attempt
}

// AntigravityAuthJSON is the durable Google Antigravity OAuth credential.
// The optional model snapshot keeps the public catalog stable when Google's
// discovery endpoint is temporarily unavailable.
type AntigravityAuthJSON struct {
	Type              string                      `json:"type"`
	AccessToken       string                      `json:"access_token"`
	RefreshToken      string                      `json:"refresh_token"`
	TokenType         string                      `json:"token_type,omitempty"`
	Scope             string                      `json:"scope,omitempty"`
	ExpiresAt         string                      `json:"expired,omitempty"`
	ExpiryDate        int64                       `json:"expiry_date,omitempty"`
	Email             string                      `json:"email,omitempty"`
	ProjectID         string                      `json:"project_id"`
	PlanType          string                      `json:"plan_type,omitempty"`
	LastRefresh       string                      `json:"last_refresh,omitempty"`
	Disabled          bool                        `json:"disabled,omitempty"`
	Dead              bool                        `json:"dead,omitempty"`
	ModelSnapshot     *AntigravityAccountSnapshot `json:"model_snapshot,omitempty"`
	ModelCooldowns    map[string]string           `json:"model_rate_limits,omitempty"`
	NeedsVerification bool                        `json:"needs_verification,omitempty"`
	VerificationURL   string                      `json:"verification_url,omitempty"`
	HealthError       string                      `json:"health_error,omitempty"`
}

// ClaudeAuthJSON is the format for Claude auth files.
// Files should be named claude_*.json in the pool folder.
// Supports both API key format and OAuth format (from Claude Code).
type ClaudeAuthJSON struct {
	// API key format
	APIKey   string `json:"api_key,omitempty"`
	PlanType string `json:"plan_type,omitempty"` // optional: pro, max, etc.

	AllowedIP        string   `json:"allowed_ip,omitempty"`
	AllowedSourceIPs []string `json:"allowed_source_ips,omitempty"`

	// OAuth format (from Claude Code keychain)
	ClaudeAiOauth *ClaudeOAuthData `json:"claudeAiOauth,omitempty"`

	// Learned from Anthropic's bootstrap endpoint
	AccountUUID string `json:"account_uuid,omitempty"`
	AddedAt     string `json:"added_at,omitempty"`
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
	antigravityModels.Reset()

	// Load accounts from provider subdirectories: pool/codex/, pool/claude/, pool/gemini/
	providerDirs := map[string]AccountType{
		"codex":       AccountTypeCodex,
		"claude":      AccountTypeClaude,
		"gemini":      AccountTypeGemini,
		"antigravity": AccountTypeAntigravity,
		"kimi":        AccountTypeKimi,
		"minimax":     AccountTypeMinimax,
		"zai":         AccountTypeZAI,
		"xiaomi":      AccountTypeXiaomi,
		"grok":        AccountTypeGrok,
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
				applyCommonAccountFileState(acc, data)
				accs = append(accs, acc)
			}
		}
	}

	return accs, nil
}

func applyCommonAccountFileState(account *Account, data []byte) {
	var root map[string]any
	if json.Unmarshal(data, &root) != nil {
		return
	}
	if disabled, ok := root["disabled"].(bool); ok {
		account.Disabled = disabled
	}
	if dead, ok := root["dead"].(bool); ok {
		account.Dead = dead
	}
	if raw, ok := root["added_at"].(string); ok {
		if addedAt, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			account.AddedAt = addedAt.UTC()
		}
	}
	if account.AddedAt.IsZero() {
		if info, err := os.Stat(account.File); err == nil {
			// Legacy account files predate durable admission timestamps. Their
			// original file timestamp is the best locally available boundary and
			// gets persisted as added_at on the next account save.
			account.AddedAt = info.ModTime().UTC()
		}
	}
}

// Note: Individual account loading functions are now in the provider files:
// - provider_codex.go: CodexProvider.LoadAccount
// - provider_claude.go: ClaudeProvider.LoadAccount
// - provider_gemini.go: GeminiProvider.LoadAccount

// poolState wraps accounts with a mutex.
type poolState struct {
	mu            sync.RWMutex
	accounts      []*Account
	convPin       map[string]string // conversation_id -> account ID
	debug         bool
	rr            uint64
	tierThreshold float64 // secondary usage % at which we stop preferring a tier (default 0.50)
}

func newPoolState(accs []*Account, debug bool) *poolState {
	return &poolState{accounts: accs, convPin: map[string]string{}, debug: debug, tierThreshold: 0.50}
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

// accountTier returns the preference tier for an account (1 = best, 2 = mid, 3 = last resort).
// Claude: tier 1 = max/team/max_team, tier 2 = unknown/other, tier 3 = pro
// Codex: tier 1 = pro/prolite, tier 2 = everything else
// Gemini: tier 1 = ultra, tier 2 = everything else
func accountTier(accType AccountType, planType string) int {
	switch accType {
	case AccountTypeClaude:
		p := strings.ToLower(strings.TrimSpace(planType))
		switch p {
		case "max", "team", "max_team":
			return 1
		case "pro":
			return 3
		default:
			return 2
		}
	case AccountTypeCodex:
		if isCodexProAccessPlan(planType) {
			return 1
		}
		return 2
	case AccountTypeGemini, AccountTypeAntigravity:
		plan := strings.ToLower(strings.TrimSpace(planType))
		if strings.Contains(plan, "ultra") || strings.Contains(plan, "pro") || strings.Contains(plan, "paid") {
			return 1
		}
		return 2
	}
	return 2
}

func isCodexProAccessPlan(planType string) bool {
	switch strings.ToLower(strings.TrimSpace(planType)) {
	case "pro", "prolite":
		return true
	default:
		return false
	}
}

func accountAllowsClientIPLocked(a *Account, clientIP string) bool {
	if a == nil || len(a.AllowedSourceIPs) == 0 {
		return true
	}
	clientIP = strings.TrimSpace(clientIP)
	if clientIP == "" {
		return false
	}
	for _, allowedIP := range a.AllowedSourceIPs {
		if strings.EqualFold(strings.TrimSpace(allowedIP), clientIP) {
			return true
		}
	}
	return false
}

// nearestCooldown returns how long until the next rate-limited account of the
// given type becomes available. Returns 0 if no accounts are cooling down.
// This lets the retry loop wait briefly instead of returning 503 immediately.
func (p *poolState) nearestCooldown(accountType AccountType, exclude map[string]bool) time.Duration {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := time.Now()
	var nearest time.Duration
	for _, a := range p.accounts {
		if exclude != nil && exclude[a.ID] {
			continue
		}
		a.mu.Lock()
		if a.Dead || a.Disabled || (accountType != "" && a.Type != accountType) {
			a.mu.Unlock()
			continue
		}
		if !a.RateLimitUntil.IsZero() && a.RateLimitUntil.After(now) {
			wait := a.RateLimitUntil.Sub(now)
			if nearest == 0 || wait < nearest {
				nearest = wait
			}
		}
		a.mu.Unlock()
	}
	return nearest
}

// candidate selects the best account using tiered selection, optionally filtering by type.
// If accountType is empty, all account types are considered.
//
// Selection strategy:
//  1. Conversation pinning (stickiness) — only unpin at hard limits
//  2. Split eligible accounts into Tier 1 and Tier 2
//  3. If any Tier 1 account has secondary < tierThreshold → pick best Tier 1 below threshold
//  4. Else if Tier 1 accounts exist above threshold → still prefer best Tier 1 by score
//     (only fall to Tier 2 if it has significantly better score)
//  5. Else pick best Tier 2 by threshold then score
//  6. Within a tier, use score as tiebreaker (headroom, drain urgency, recency, inflight)
//  7. If all non-codex candidates are rate-limited, pick the best rate-limited account as fallback
//     to avoid hard 503 failures during transient exhaustion.
func (p *poolState) candidateByID(id string, accountType AccountType, requiredPlan string, clientIP string) *Account {
	if id == "" {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	a := p.getLocked(id)
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if a.Dead || a.Disabled || (accountType != "" && a.Type != accountType) || !planMatchesRequired(a.PlanType, requiredPlan) || !accountAllowsClientIPLocked(a, clientIP) {
		return nil
	}
	if !a.ExpiresAt.IsZero() && a.ExpiresAt.Before(now) {
		return nil
	}
	if accountPrimaryUsageLocked(a) >= primaryHardExcludeThreshold || accountSecondaryUsageLocked(a) >= secondaryHardExcludeThreshold {
		return nil
	}
	return a
}

func (p *poolState) candidateWithCyberAccess(exclude map[string]bool, accountType AccountType, requiredPlan string, clientIP string) *Account {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	var best *Account
	bestScore := -1e9
	for _, a := range p.accounts {
		if exclude != nil && exclude[a.ID] {
			continue
		}
		a.mu.Lock()
		if a.Dead || a.Disabled || !a.CyberAccess || (accountType != "" && a.Type != accountType) || !planMatchesRequired(a.PlanType, requiredPlan) || !accountAllowsClientIPLocked(a, clientIP) {
			a.mu.Unlock()
			continue
		}
		// Note: we deliberately do NOT skip accounts with an expired
		// access_token here. The cyber-access pool is small (often a
		// single account) and idle expirations are common; the
		// caller's request flow will lazy-refresh the token before
		// using it. Skipping expired accounts here would leak
		// cyber_policy errors to the client when the only cyber
		// account happens to have just expired.
		primaryUsed := accountPrimaryUsageLocked(a)
		secondaryUsed := accountSecondaryUsageLocked(a)
		if primaryUsed >= primaryHardExcludeThreshold || secondaryUsed >= secondaryHardExcludeThreshold {
			a.mu.Unlock()
			continue
		}
		score := scoreAccountLocked(a, now)
		a.mu.Unlock()
		score -= float64(atomic.LoadInt64(&a.Inflight)) * 0.02
		if best == nil || score > bestScore {
			best = a
			bestScore = score
		}
	}
	if best != nil {
		p.rr++
	}
	return best
}

func (p *poolState) candidate(conversationID string, exclude map[string]bool, accountType AccountType, requiredPlan string, clientIP string) *Account {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()

	// Conversation pinning — keep using the same account unless at hard limits
	if conversationID != "" {
		if id, ok := p.convPin[conversationID]; ok {
			if exclude != nil && exclude[id] {
				// pinned excluded; fall through to selection
			} else if a := p.getLocked(id); a != nil {
				a.mu.Lock()
				ok := !a.Dead && !a.Disabled && (accountType == "" || a.Type == accountType) && planMatchesRequired(a.PlanType, requiredPlan) && accountAllowsClientIPLocked(a, clientIP)
				if ok && a.Type == AccountTypeCodex && !isCodexProAccessPlan(a.PlanType) {
					ok = false
					if p.debug {
						log.Printf("unpinning conversation %s from non-pro codex account %s", conversationID, id)
					}
				}
				if ok && !a.RateLimitUntil.IsZero() && a.RateLimitUntil.After(now) {
					ok = false
					if p.debug {
						log.Printf("unpinning conversation %s from rate-limited account %s (until %s)",
							conversationID, id, a.RateLimitUntil.Format(time.RFC3339))
					}
				}
				// Unpin at 95% secondary (raised from 90% for better stickiness)
				secondaryUsed := accountSecondaryUsageLocked(a)
				if ok && secondaryUsed >= secondaryHardExcludeThreshold {
					ok = false
					if p.debug {
						log.Printf("unpinning conversation %s from exhausted account %s (%.0f%% secondary >= %.0f%%)",
							conversationID, id, secondaryUsed*100, secondaryHardExcludeThreshold*100)
					}
				}
				// Also unpin if primary usage is at/above 95% (hard limit)
				primaryUsed := accountPrimaryUsageLocked(a)
				if ok && primaryUsed >= primaryHardExcludeThreshold {
					ok = false
					if p.debug {
						log.Printf("unpinning conversation %s from account %s (%.0f%% primary >= %.0f%%)",
							conversationID, id, primaryUsed*100, primaryHardExcludeThreshold*100)
					}
				}
				// Also unpin if token is expired - don't wait for a failed request
				if ok && !a.ExpiresAt.IsZero() && a.ExpiresAt.Before(now) {
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

	n := len(p.accounts)
	if n == 0 {
		return nil
	}

	// Collect eligible accounts with their tier and score
	type scoredAccount struct {
		acc          *Account
		tier         int
		secondaryPct float64
		score        float64
	}
	var eligible []scoredAccount
	var rateLimited []scoredAccount

	start := int(p.rr % uint64(n))
	for i := 0; i < n; i++ {
		a := p.accounts[(start+i)%n]
		if exclude != nil && exclude[a.ID] {
			continue
		}
		a.mu.Lock()
		if a.Dead || a.Disabled || (accountType != "" && a.Type != accountType) || !planMatchesRequired(a.PlanType, requiredPlan) || !accountAllowsClientIPLocked(a, clientIP) {
			a.mu.Unlock()
			continue
		}
		if !a.RateLimitUntil.IsZero() && a.RateLimitUntil.After(now) {
			secondaryUsed := accountSecondaryUsageLocked(a)
			tier := accountTier(a.Type, a.PlanType)
			score := scoreAccountLocked(a, now)
			a.mu.Unlock()
			// Prefer less-loaded accounts
			score -= float64(atomic.LoadInt64(&a.Inflight)) * 0.02
			rateLimited = append(rateLimited, scoredAccount{acc: a, tier: tier, secondaryPct: secondaryUsed, score: score})
			if p.debug {
				log.Printf("skipping account %s: rate limited until %s", a.ID, a.RateLimitUntil.Format(time.RFC3339))
			}
			continue
		}
		// Hard exclusion: >=95% primary usage
		primaryUsed := accountPrimaryUsageLocked(a)
		if primaryUsed >= primaryHardExcludeThreshold {
			a.mu.Unlock()
			if p.debug {
				log.Printf("excluding account %s: primary usage %.1f%% >= %.0f%%", a.ID, primaryUsed*100, primaryHardExcludeThreshold*100)
			}
			continue
		}
		// Hard exclusion: >=99% secondary usage
		secondaryUsed := accountSecondaryUsageLocked(a)
		if secondaryUsed >= secondaryHardExcludeThreshold {
			a.mu.Unlock()
			if p.debug {
				log.Printf("excluding account %s: secondary usage %.1f%% >= %.0f%%", a.ID, secondaryUsed*100, secondaryHardExcludeThreshold*100)
			}
			continue
		}
		tier := accountTier(a.Type, a.PlanType)
		score := scoreAccountLocked(a, now)
		a.mu.Unlock()
		// Prefer less-loaded accounts
		score -= float64(atomic.LoadInt64(&a.Inflight)) * 0.02
		eligible = append(eligible, scoredAccount{acc: a, tier: tier, secondaryPct: secondaryUsed, score: score})
	}

	selectCandidate := func(accounts []scoredAccount) *Account {
		threshold := p.tierThreshold
		// Try Tier 1 accounts below threshold
		var bestTier1Below *scoredAccount
		var bestTier1Any *scoredAccount
		for i := range accounts {
			sa := &accounts[i]
			if sa.tier == 1 {
				if bestTier1Any == nil || sa.score > bestTier1Any.score {
					bestTier1Any = sa
				}
				if sa.secondaryPct < threshold {
					if bestTier1Below == nil || sa.score > bestTier1Below.score {
						bestTier1Below = sa
					}
				}
			}
		}
		if bestTier1Below != nil {
			p.rr++
			return bestTier1Below.acc
		}

		// Try Tier 2 accounts below threshold
		var bestTier2Below *scoredAccount
		var bestTier2Any *scoredAccount
		for i := range accounts {
			sa := &accounts[i]
			if sa.tier == 2 {
				if bestTier2Any == nil || sa.score > bestTier2Any.score {
					bestTier2Any = sa
				}
				if sa.secondaryPct < threshold {
					if bestTier2Below == nil || sa.score > bestTier2Below.score {
						bestTier2Below = sa
					}
				}
			}
		}

		// If tier 1 accounts exist above threshold, prefer them over tier 2 below threshold.
		// Only fall to tier 2 if no tier 1 accounts at all.
		if bestTier1Any != nil {
			// Tier 1 exists but all above threshold. Still prefer tier 1 by score
			// unless a tier 2 below threshold has significantly better score.
			if accountType != AccountTypeCodex && bestTier2Below != nil && bestTier2Below.score > bestTier1Any.score+0.3 {
				p.rr++
				return bestTier2Below.acc
			}
			p.rr++
			return bestTier1Any.acc
		}
		if bestTier2Below != nil {
			p.rr++
			return bestTier2Below.acc
		}
		if bestTier2Any != nil {
			p.rr++
			return bestTier2Any.acc
		}

		// Tier 3: last resort (e.g. Claude pro accounts)
		var bestTier3Below *scoredAccount
		var bestTier3Any *scoredAccount
		for i := range accounts {
			sa := &accounts[i]
			if sa.tier == 3 {
				if bestTier3Any == nil || sa.score > bestTier3Any.score {
					bestTier3Any = sa
				}
				if sa.secondaryPct < threshold {
					if bestTier3Below == nil || sa.score > bestTier3Below.score {
						bestTier3Below = sa
					}
				}
			}
		}
		if bestTier3Below != nil {
			p.rr++
			return bestTier3Below.acc
		}
		if bestTier3Any != nil {
			p.rr++
			return bestTier3Any.acc
		}

		// Absolute fallback — pick the one with highest score (most headroom)
		var bestAll *scoredAccount
		for i := range accounts {
			sa := &accounts[i]
			if bestAll == nil || sa.score > bestAll.score {
				bestAll = sa
			}
		}
		if bestAll != nil {
			p.rr++
			return bestAll.acc
		}
		return nil
	}

	if len(eligible) == 0 {
		if len(rateLimited) > 0 && p.debug {
			log.Printf("no non-rate-limited %s accounts available; refusing to route to rate-limited accounts", accountType)
		}
		return nil
	}

	return selectCandidate(eligible)
}

func (p *poolState) excludeInflightWhenIdleAvailable(accountType AccountType, exclude map[string]bool) {
	if p == nil || exclude == nil {
		return
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	hasIdle := false
	for _, account := range p.accounts {
		if account != nil && account.Type == accountType && atomic.LoadInt64(&account.Inflight) == 0 {
			hasIdle = true
			break
		}
	}
	if !hasIdle {
		return
	}
	for _, account := range p.accounts {
		if account != nil && account.Type == accountType && atomic.LoadInt64(&account.Inflight) > 0 {
			exclude[account.ID] = true
		}
	}
}

func (p *poolState) excludeImageIncapable(exclude map[string]bool) {
	if p == nil || exclude == nil {
		return
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, account := range p.accounts {
		if account == nil || account.Type != AccountTypeCodex || atomic.LoadInt32(&account.ImageGenerationSupport) >= 0 {
			continue
		}
		retryAt := atomic.LoadInt64(&account.ImageGenerationRetryAt)
		if retryAt > 0 && time.Now().Unix() >= retryAt {
			atomic.StoreInt32(&account.ImageGenerationSupport, 0)
			atomic.StoreInt32(&account.ImageGenerationFailures, 0)
			atomic.StoreInt64(&account.ImageGenerationRetryAt, 0)
			continue
		}
		exclude[account.ID] = true
	}
}

func recordImageGenerationResult(account *Account, success bool) {
	if account == nil {
		return
	}
	if success {
		atomic.StoreInt32(&account.ImageGenerationFailures, 0)
		atomic.StoreInt32(&account.ImageGenerationSupport, 1)
		atomic.StoreInt64(&account.ImageGenerationRetryAt, 0)
		return
	}
	atomic.AddInt32(&account.ImageGenerationFailures, 1)
	atomic.StoreInt32(&account.ImageGenerationSupport, -1)
	atomic.StoreInt64(&account.ImageGenerationRetryAt, time.Now().Add(10*time.Minute).Unix())
}

func (p *poolState) imageFanoutCandidate(index int, exclude map[string]bool, requiredPlan string, clientIP string) *Account {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	ids := make([]string, 0, len(p.accounts))
	for _, account := range p.accounts {
		if account != nil && account.Type == AccountTypeCodex && !exclude[account.ID] {
			ids = append(ids, account.ID)
		}
	}
	p.mu.RUnlock()
	if len(ids) == 0 {
		return nil
	}
	sort.Strings(ids)
	start := index % len(ids)
	if start < 0 {
		start += len(ids)
	}
	for offset := 0; offset < len(ids); offset++ {
		id := ids[(start+offset)%len(ids)]
		if account := p.candidateByID(id, AccountTypeCodex, requiredPlan, clientIP); account != nil {
			return account
		}
	}
	return nil
}

func planMatchesRequired(planType, requiredPlan string) bool {
	if requiredPlan == "" {
		return true
	}
	plan := strings.ToLower(strings.TrimSpace(planType))
	required := strings.ToLower(strings.TrimSpace(requiredPlan))
	if required == requiredPlanClaudePremium {
		return strings.HasPrefix(plan, "max") || strings.HasPrefix(plan, "team")
	}
	if required == "pro" {
		return isCodexProAccessPlan(plan)
	}
	return plan == required
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

type scoreBreakdown struct {
	Score              float64
	PrimaryUsed        float64
	SecondaryUsed      float64
	PrimaryAvailable   bool
	SecondaryAvailable bool
	BaseWindow         string
	BaseHeadroom       float64
	DrainMultiplier    float64
	PrimaryPaceBonus   float64
	PrimaryPenalty     float64
	ExpiryPenalty      float64
	PenaltyRaw         float64
	PenaltyFactor      float64
	PenaltyApplied     float64
	ClampedToFloor     bool
	RecentUseBonus     float64
	CreditBonus        float64
	HeadroomPreCredit  float64
}

func scoreAccountBreakdownLocked(a *Account, now time.Time) scoreBreakdown {
	var out scoreBreakdown

	decayPenaltyLocked(a, now)
	primaryUsed := a.Usage.PrimaryUsedPercent
	secondaryUsed := a.Usage.SecondaryUsedPercent
	if primaryUsed == 0 && a.Usage.PrimaryUsed > 0 {
		primaryUsed = a.Usage.PrimaryUsed
	}
	if secondaryUsed == 0 && a.Usage.SecondaryUsed > 0 {
		secondaryUsed = a.Usage.SecondaryUsed
	}
	out.PrimaryUsed = primaryUsed
	out.SecondaryUsed = secondaryUsed
	out.PrimaryAvailable = usagePrimaryWindowAvailable(a.Usage)
	out.SecondaryAvailable = usageSecondaryWindowAvailable(a.Usage)

	// Prefer the weekly window as the long-term balancing signal. If OpenAI
	// temporarily exposes only a five-hour window, use that instead of treating
	// the missing weekly window as unlimited headroom.
	headroom := 1.0
	switch {
	case out.SecondaryAvailable:
		headroom = 1.0 - secondaryUsed
		out.BaseWindow = "7d"
	case out.PrimaryAvailable:
		headroom = 1.0 - primaryUsed
		out.BaseWindow = "5h"
	default:
		out.BaseWindow = "none"
	}
	out.BaseHeadroom = headroom
	out.DrainMultiplier = 1.0

	// Accounts closer to a weekly reset can absorb more traffic right now.
	if out.SecondaryAvailable && !a.Usage.SecondaryResetAt.IsZero() && a.Usage.SecondaryResetAt.After(now) {
		hoursRemaining := a.Usage.SecondaryResetAt.Sub(now).Hours()
		totalHours := 168.0
		if hoursRemaining > 1 && hoursRemaining < totalHours {
			sustainableBurnRate := headroom / hoursRemaining
			baselineBurnRate := 1.0 / totalHours
			burnRateRatio := sustainableBurnRate / baselineBurnRate

			maxMultiplier := 3.0
			if hoursRemaining < 6 && headroom > 0.1 {
				maxMultiplier = 8.0
			}

			if burnRateRatio > maxMultiplier {
				burnRateRatio = maxMultiplier
			} else if burnRateRatio < 0.3 {
				burnRateRatio = 0.3
			}

			out.DrainMultiplier = burnRateRatio
			headroom *= burnRateRatio
		}
	}

	// Cap drain multiplier for accounts with no primary window data.
	// Pro/Team plans lack a 5hr window; don't let phantom headroom inflate their score.
	if !out.PrimaryAvailable {
		if out.DrainMultiplier > 1.0 {
			out.DrainMultiplier = 1.0
			headroom = out.BaseHeadroom
		}
	}

	// When both windows exist, use five-hour headroom as the burst signal on
	// top of the weekly base. If five-hour is the only window, it is already the
	// base and must not be counted twice.
	if out.PrimaryAvailable && out.SecondaryAvailable {
		if !a.Usage.PrimaryResetAt.IsZero() && a.Usage.PrimaryResetAt.After(now) {
			hoursRemaining := a.Usage.PrimaryResetAt.Sub(now).Hours()
			primaryHeadroom := 1.0 - primaryUsed
			if hoursRemaining > 0.1 && hoursRemaining <= 5.0 && primaryHeadroom > 0.05 {
				timeWeight := hoursRemaining / 3.0
				if timeWeight > 1.0 {
					timeWeight = 1.0
				}
				out.PrimaryPaceBonus = primaryHeadroom * 0.5 * timeWeight
			}
		} else if primaryUsed < 0.5 {
			out.PrimaryPaceBonus = (1.0 - primaryUsed) * 0.15
		}
		headroom += out.PrimaryPaceBonus

		if primaryUsed > 0.8 {
			out.PrimaryPenalty = (primaryUsed - 0.8) * 2.0
			headroom -= out.PrimaryPenalty
		}
	}

	// Mild expiry penalty.
	if !a.ExpiresAt.IsZero() {
		ttl := a.ExpiresAt.Sub(now).Minutes()
		if ttl < 0 {
			out.ExpiryPenalty = 0.3
		} else if ttl < 30 {
			out.ExpiryPenalty = 0.2
		} else if ttl < 60 {
			out.ExpiryPenalty = 0.1
		}
	}
	headroom -= out.ExpiryPenalty

	out.PenaltyFactor = 1.0
	if !a.Usage.SecondaryResetAt.IsZero() {
		hoursRemaining := a.Usage.SecondaryResetAt.Sub(now).Hours()
		secondaryHeadroom := 1.0 - secondaryUsed
		if hoursRemaining > 0 && hoursRemaining < 6 && secondaryHeadroom > 0.1 {
			out.PenaltyFactor = 0.3
		}
	}
	out.PenaltyRaw = a.Penalty
	out.PenaltyApplied = a.Penalty * out.PenaltyFactor
	headroom -= out.PenaltyApplied

	if headroom < 0.01 {
		headroom = 0.01
		out.ClampedToFloor = true
	}

	if !a.LastUsed.IsZero() && now.Sub(a.LastUsed) < 5*time.Minute {
		out.RecentUseBonus = 0.1
		headroom += out.RecentUseBonus
	}

	out.CreditBonus = 1.0
	if a.Usage.CreditsUnlimited || a.Usage.HasCredits {
		out.CreditBonus = 1.1
	}

	out.HeadroomPreCredit = headroom
	out.Score = headroom * out.CreditBonus
	return out
}

func scoreAccountLocked(a *Account, now time.Time) float64 {
	return scoreAccountBreakdownLocked(a, now).Score
}

func scoreTooltipFromBreakdownLocked(a *Account, now time.Time, breakdown scoreBreakdown) string {
	if a.Disabled {
		return "Not scored because this account is disabled."
	}
	if a.Dead {
		return "Not scored because this account is marked dead."
	}

	lines := make([]string, 0, 12)
	lines = append(lines, fmt.Sprintf("Final score: %.2f", breakdown.Score))
	switch breakdown.BaseWindow {
	case "7d":
		lines = append(lines, fmt.Sprintf("7d headroom: %.2f from %.0f%% weekly usage", breakdown.BaseHeadroom, breakdown.SecondaryUsed*100))
	case "5h":
		lines = append(lines, fmt.Sprintf("5h headroom: %.2f from %.0f%% five-hour usage", breakdown.BaseHeadroom, breakdown.PrimaryUsed*100))
	default:
		lines = append(lines, "No current Codex usage window data; neutral headroom used")
	}
	if !breakdown.PrimaryAvailable && breakdown.SecondaryAvailable {
		lines = append(lines, "5h window is not currently exposed")
	}

	if breakdown.DrainMultiplier != 1.0 {
		lines = append(lines, fmt.Sprintf("Drain multiplier: x%.2f", breakdown.DrainMultiplier))
	}
	if breakdown.PrimaryPaceBonus > 0 {
		lines = append(lines, fmt.Sprintf("5h pace bonus: +%.2f", breakdown.PrimaryPaceBonus))
	}
	if breakdown.PrimaryPenalty > 0 {
		lines = append(lines, fmt.Sprintf("5h high-usage penalty: -%.2f at %.0f%%", breakdown.PrimaryPenalty, breakdown.PrimaryUsed*100))
	}
	if breakdown.ExpiryPenalty > 0 {
		lines = append(lines, fmt.Sprintf("Expiry penalty: -%.2f", breakdown.ExpiryPenalty))
	}
	if breakdown.PenaltyApplied > 0 {
		lines = append(lines, fmt.Sprintf("Penalty applied: -%.2f (raw %.2f x %.2f)", breakdown.PenaltyApplied, breakdown.PenaltyRaw, breakdown.PenaltyFactor))
	}
	if breakdown.ClampedToFloor {
		lines = append(lines, "Headroom floor applied: 0.01")
	}
	if breakdown.RecentUseBonus > 0 {
		lines = append(lines, fmt.Sprintf("Recent-use bonus: +%.2f", breakdown.RecentUseBonus))
	}
	if breakdown.CreditBonus > 1.0 {
		lines = append(lines, fmt.Sprintf("Credits multiplier: x%.2f", breakdown.CreditBonus))
	}
	if accountCoolingDownLocked(a, now) {
		lines = append(lines, "Cooldown is separate from score; this account is currently cooling down.")
	}

	lines = append(lines, fmt.Sprintf("Pre-credit headroom: %.2f", breakdown.HeadroomPreCredit))
	return strings.Join(lines, "\n")
}

func scoreTooltipLocked(a *Account, now time.Time) string {
	return scoreTooltipFromBreakdownLocked(a, now, scoreAccountBreakdownLocked(a, now))
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

	switch a.Type {
	case AccountTypeGemini:
		return saveGeminiAccount(a)
	case AccountTypeAntigravity:
		return saveAntigravityAccount(a)
	case AccountTypeClaude:
		return saveClaudeAccount(a)
	case AccountTypeKimi:
		return saveAPIKeyAccount(a)
	case AccountTypeMinimax:
		return saveAPIKeyAccount(a)
	case AccountTypeZAI:
		return saveAPIKeyAccount(a)
	case AccountTypeXiaomi:
		return saveAPIKeyAccount(a)
	case AccountTypeGrok:
		return saveGrokAccount(a)
	default:
		return saveCodexAccount(a)
	}
}

func persistAccountAddedAt(root map[string]any, a *Account) {
	if a.AddedAt.IsZero() {
		a.AddedAt = time.Now().UTC()
	}
	root["added_at"] = a.AddedAt.UTC().Format(time.RFC3339Nano)
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
	persistAccountAddedAt(root, a)

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
	if len(a.AllowedSourceIPs) > 0 {
		root["allowed_source_ips"] = a.AllowedSourceIPs
		if len(a.AllowedSourceIPs) == 1 {
			root["allowed_ip"] = a.AllowedSourceIPs[0]
		} else {
			delete(root, "allowed_ip")
		}
	} else {
		delete(root, "allowed_source_ips")
		delete(root, "allowed_ip")
	}

	if a.CyberAccess {
		root["cyber_access"] = true
	} else {
		delete(root, "cyber_access")
	}

	if len(a.CodexCookies) > 0 {
		root["cookies"] = a.CodexCookies
	} else {
		delete(root, "cookies")
	}
	// Persist dead flag so accounts stay dead across restarts
	if a.Dead {
		root["dead"] = true
	} else {
		delete(root, "dead")
	}
	if a.Disabled {
		root["disabled"] = true
	} else {
		delete(root, "disabled")
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
	persistAccountAddedAt(root, a)

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
	if !a.LastRefresh.IsZero() {
		root["last_refresh"] = a.LastRefresh.UTC().Format(time.RFC3339Nano)
	}
	if a.Dead {
		root["dead"] = true
	} else {
		delete(root, "dead")
	}
	if a.Disabled {
		root["disabled"] = true
	} else {
		delete(root, "disabled")
	}

	return atomicWriteJSON(a.File, root)
}

// saveAPIKeyAccount saves an API-key-based account (kimi, minimax, etc.)
func saveAPIKeyAccount(a *Account) error {
	raw, err := os.ReadFile(a.File)
	if err != nil {
		return err
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("parse %s: %w", a.File, err)
	}
	persistAccountAddedAt(root, a)

	if a.AccessToken != "" {
		root["api_key"] = a.AccessToken
	}
	if a.Dead {
		root["dead"] = true
	} else {
		delete(root, "dead")
	}
	if a.Disabled {
		root["disabled"] = true
	} else {
		delete(root, "disabled")
	}
	return atomicWriteJSON(a.File, root)
}

func saveGrokAccount(a *Account) error {
	raw, err := os.ReadFile(a.File)
	if err != nil {
		return err
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("parse %s: %w", a.File, err)
	}
	persistAccountAddedAt(root, a)

	if _, ok := root["access"]; ok {
		applyGrokTokenFields(root, a, "access", "refresh", "expires", "tokenEndpoint", true)
		return atomicWriteJSON(a.File, root)
	}

	if _, ok := root["access_token"]; ok {
		applyGrokTokenFields(root, a, "access_token", "refresh_token", "expires_at", "token_endpoint", false)
		return atomicWriteJSON(a.File, root)
	}

	for key, value := range root {
		entry, ok := value.(map[string]any)
		if !ok {
			continue
		}
		if _, hasKey := entry["key"]; !hasKey {
			if _, hasRefresh := entry["refresh_token"]; !hasRefresh {
				continue
			}
		}
		applyGrokTokenFields(entry, a, "key", "refresh_token", "expires_at", "", false)
		root[key] = entry
		return atomicWriteJSON(a.File, root)
	}

	return fmt.Errorf("grok account %s has no recognized token entry", a.ID)
}

func applyGrokTokenFields(target map[string]any, a *Account, accessKey, refreshKey, expiresKey, endpointKey string, expiresAsMillis bool) {
	if a.AccessToken != "" {
		target[accessKey] = a.AccessToken
	}
	if a.RefreshToken != "" {
		target[refreshKey] = a.RefreshToken
	}
	if expiresKey != "" && !a.ExpiresAt.IsZero() {
		if expiresAsMillis {
			target[expiresKey] = a.ExpiresAt.UnixMilli()
		} else {
			target[expiresKey] = a.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
	}
	if endpointKey != "" {
		if endpoint := strings.TrimSpace(a.AccountID); endpoint != "" {
			target[endpointKey] = endpoint
		}
	}
	if a.Dead {
		target["dead"] = true
	} else {
		delete(target, "dead")
	}
	if a.Disabled {
		target["disabled"] = true
	} else {
		delete(target, "disabled")
	}
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
	authoritativeZero := res.Source == "claude-api" || res.Source == "wham"
	hardReset := res.PrimaryUsedPercent == 0 && res.SecondaryUsedPercent == 0

	if !res.primarySet {
		if res.PrimaryUsedPercent == 0 && prev.PrimaryUsedPercent > 0 && !authoritativeZero && !(hardSource && hardReset) {
			res.PrimaryUsedPercent = prev.PrimaryUsedPercent
		}
		if res.PrimaryUsed == 0 && prev.PrimaryUsed > 0 && !authoritativeZero && !(hardSource && hardReset) {
			res.PrimaryUsed = prev.PrimaryUsed
		}
		if res.PrimaryWindowMinutes == 0 && prev.PrimaryWindowMinutes > 0 {
			res.PrimaryWindowMinutes = prev.PrimaryWindowMinutes
		}
		if res.PrimaryResetAt.IsZero() && !prev.PrimaryResetAt.IsZero() {
			res.PrimaryResetAt = prev.PrimaryResetAt
		}
	}
	if !res.secondarySet {
		if res.SecondaryUsedPercent == 0 && prev.SecondaryUsedPercent > 0 && !authoritativeZero && !(hardSource && hardReset) {
			res.SecondaryUsedPercent = prev.SecondaryUsedPercent
		}
		if res.SecondaryUsed == 0 && prev.SecondaryUsed > 0 && !authoritativeZero && !(hardSource && hardReset) {
			res.SecondaryUsed = prev.SecondaryUsed
		}
		if res.SecondaryWindowMinutes == 0 && prev.SecondaryWindowMinutes > 0 {
			res.SecondaryWindowMinutes = prev.SecondaryWindowMinutes
		}
		if res.SecondaryResetAt.IsZero() && !prev.SecondaryResetAt.IsZero() {
			res.SecondaryResetAt = prev.SecondaryResetAt
		}
	}
	if !res.creditsSet {
		if res.CreditsBalance == 0 && prev.CreditsBalance > 0 {
			res.CreditsBalance = prev.CreditsBalance
		}
		res.HasCredits = res.HasCredits || prev.HasCredits
		res.CreditsUnlimited = res.CreditsUnlimited || prev.CreditsUnlimited
	}

	res.primarySet = res.primarySet || prev.primarySet
	res.secondarySet = res.secondarySet || prev.secondarySet
	res.creditsSet = res.creditsSet || prev.creditsSet
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
	return p.averageUsageByType("")
}

// averageUsageByType produces a synthetic usage payload for accounts of a specific type.
// If accountType is empty, averages across all accounts.
func (p *poolState) averageUsageByType(accountType AccountType) UsageSnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var totalP, totalS float64
	var totalPW, totalSW float64
	var nP, nS float64
	var primaryCount, secondaryCount float64
	var n float64
	var latestPrimaryReset, latestSecondaryReset time.Time
	for _, a := range p.accounts {
		account := snapshotAccountUsage(a)
		if account.Dead {
			continue
		}
		if accountType != "" && account.Type != accountType {
			continue
		}
		usedP := account.Usage.PrimaryUsedPercent
		if usedP == 0 {
			usedP = account.Usage.PrimaryUsed
		}
		usedS := account.Usage.SecondaryUsedPercent
		if usedS == 0 {
			usedS = account.Usage.SecondaryUsed
		}
		if usagePrimaryWindowAvailable(account.Usage) {
			totalP += usedP
			primaryCount++
		}
		if usageSecondaryWindowAvailable(account.Usage) {
			totalS += usedS
			secondaryCount++
		}
		n++
		if account.Usage.PrimaryWindowMinutes > 0 {
			totalPW += float64(account.Usage.PrimaryWindowMinutes)
			nP += 1
		}
		if account.Usage.SecondaryWindowMinutes > 0 {
			totalSW += float64(account.Usage.SecondaryWindowMinutes)
			nS += 1
		}
		// Track latest reset times
		if !account.Usage.PrimaryResetAt.IsZero() && account.Usage.PrimaryResetAt.After(latestPrimaryReset) {
			latestPrimaryReset = account.Usage.PrimaryResetAt
		}
		if !account.Usage.SecondaryResetAt.IsZero() && account.Usage.SecondaryResetAt.After(latestSecondaryReset) {
			latestSecondaryReset = account.Usage.SecondaryResetAt
		}
	}
	if n == 0 {
		return UsageSnapshot{}
	}
	return UsageSnapshot{
		PrimaryUsed:            totalP / max(1, primaryCount),
		SecondaryUsed:          totalS / max(1, secondaryCount),
		PrimaryUsedPercent:     totalP / max(1, primaryCount),
		SecondaryUsedPercent:   totalS / max(1, secondaryCount),
		PrimaryWindowMinutes:   int(totalPW / max(1, nP)),
		SecondaryWindowMinutes: int(totalSW / max(1, nS)),
		PrimaryResetAt:         latestPrimaryReset,
		SecondaryResetAt:       latestSecondaryReset,
		RetrievedAt:            time.Now(),
	}
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// PoolUtilization contains time-weighted utilization metrics for a provider or the whole pool.
type PoolUtilization struct {
	Provider                 string  `json:"provider"`
	TimeWeightedPrimaryPct   float64 `json:"time_weighted_primary_pct"`
	TimeWeightedSecondaryPct float64 `json:"time_weighted_secondary_pct"`
	AvailableAccounts        int     `json:"available_accounts"`
	TotalAccounts            int     `json:"total_accounts"`
	NextSecondaryResetIn     string  `json:"next_secondary_reset_in,omitempty"`
	ResetsIn24h              int     `json:"resets_in_24h"`
}

const (
	primaryWindowDuration   = 5 * time.Hour
	secondaryWindowDuration = 7 * 24 * time.Hour
)

// timeWeightedUsage produces a time-weighted usage snapshot across all alive accounts.
func (p *poolState) timeWeightedUsage() UsageSnapshot {
	return p.timeWeightedUsageByType("")
}

// timeWeightedUsageByType produces a time-weighted usage snapshot for accounts of a specific type.
// Instead of simple averaging, it weights each account's utilization by how much time remains
// until its window resets. An account at 80% that resets in 2 hours contributes almost nothing,
// while one at 80% that resets in 6 days contributes heavily.
//
// Formula: effective_util = used_pct × min(time_to_reset, window_length) / window_length
func (p *poolState) timeWeightedUsageByType(accountType AccountType) UsageSnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := time.Now()
	var totalEffP, totalEffS float64
	var totalPW, totalSW float64
	var nP, nS float64
	var primaryCount, secondaryCount float64
	var n float64
	var earliestPrimaryReset, earliestSecondaryReset time.Time

	for _, a := range p.accounts {
		account := snapshotAccountUsage(a)
		if account.Dead {
			continue
		}
		if accountType != "" && account.Type != accountType {
			continue
		}

		usedP := account.Usage.PrimaryUsedPercent
		if usedP == 0 {
			usedP = account.Usage.PrimaryUsed
		}
		usedS := account.Usage.SecondaryUsedPercent
		if usedS == 0 {
			usedS = account.Usage.SecondaryUsed
		}

		// Compute time weight for primary window
		primaryWeight := 1.0 // default: no reset info, use full weight (conservative)
		if !account.Usage.PrimaryResetAt.IsZero() && account.Usage.PrimaryResetAt.After(now) {
			timeToReset := account.Usage.PrimaryResetAt.Sub(now)
			if timeToReset > primaryWindowDuration {
				timeToReset = primaryWindowDuration
			}
			primaryWeight = float64(timeToReset) / float64(primaryWindowDuration)
		}

		// Compute time weight for secondary window
		secondaryWeight := 1.0 // default: no reset info, use full weight (conservative)
		if !account.Usage.SecondaryResetAt.IsZero() && account.Usage.SecondaryResetAt.After(now) {
			timeToReset := account.Usage.SecondaryResetAt.Sub(now)
			if timeToReset > secondaryWindowDuration {
				timeToReset = secondaryWindowDuration
			}
			secondaryWeight = float64(timeToReset) / float64(secondaryWindowDuration)
		}

		if usagePrimaryWindowAvailable(account.Usage) {
			totalEffP += usedP * primaryWeight
			primaryCount++
		}
		if usageSecondaryWindowAvailable(account.Usage) {
			totalEffS += usedS * secondaryWeight
			secondaryCount++
		}
		n++

		if account.Usage.PrimaryWindowMinutes > 0 {
			totalPW += float64(account.Usage.PrimaryWindowMinutes)
			nP += 1
		}
		if account.Usage.SecondaryWindowMinutes > 0 {
			totalSW += float64(account.Usage.SecondaryWindowMinutes)
			nS += 1
		}

		// Track earliest reset times (soonest capacity refill)
		if !account.Usage.PrimaryResetAt.IsZero() && account.Usage.PrimaryResetAt.After(now) {
			if earliestPrimaryReset.IsZero() || account.Usage.PrimaryResetAt.Before(earliestPrimaryReset) {
				earliestPrimaryReset = account.Usage.PrimaryResetAt
			}
		}
		if !account.Usage.SecondaryResetAt.IsZero() && account.Usage.SecondaryResetAt.After(now) {
			if earliestSecondaryReset.IsZero() || account.Usage.SecondaryResetAt.Before(earliestSecondaryReset) {
				earliestSecondaryReset = account.Usage.SecondaryResetAt
			}
		}
	}

	if n == 0 {
		return UsageSnapshot{}
	}
	return UsageSnapshot{
		PrimaryUsed:            totalEffP / max(1, primaryCount),
		SecondaryUsed:          totalEffS / max(1, secondaryCount),
		PrimaryUsedPercent:     totalEffP / max(1, primaryCount),
		SecondaryUsedPercent:   totalEffS / max(1, secondaryCount),
		PrimaryWindowMinutes:   int(totalPW / max(1, nP)),
		SecondaryWindowMinutes: int(totalSW / max(1, nS)),
		PrimaryResetAt:         earliestPrimaryReset,
		SecondaryResetAt:       earliestSecondaryReset,
		RetrievedAt:            now,
	}
}

// getPoolUtilization computes per-provider time-weighted utilization stats.
func (p *poolState) getPoolUtilization() []PoolUtilization {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := time.Now()
	in24h := now.Add(24 * time.Hour)

	type provAccum struct {
		totalEffP, totalEffS   float64
		nPrimary, nSecondary   float64
		available, total       int
		earliestSecondaryReset time.Time
		resetsIn24h            int
	}

	accums := map[AccountType]*provAccum{
		AccountTypeCodex:       {},
		AccountTypeClaude:      {},
		AccountTypeGemini:      {},
		AccountTypeAntigravity: {},
	}

	for _, a := range p.accounts {
		account := snapshotAccountUsage(a)
		if account.Dead || account.Disabled {
			continue
		}

		pa := accums[account.Type]
		if pa == nil {
			continue
		}
		pa.total++

		usedP := account.Usage.PrimaryUsedPercent
		if usedP == 0 {
			usedP = account.Usage.PrimaryUsed
		}
		usedS := account.Usage.SecondaryUsedPercent
		if usedS == 0 {
			usedS = account.Usage.SecondaryUsed
		}

		if (account.RateLimitUntil.IsZero() || !account.RateLimitUntil.After(now)) &&
			usedP < primaryHardExcludeThreshold && usedS < secondaryHardExcludeThreshold {
			pa.available++
		}

		// Primary time weight
		primaryWeight := 1.0
		if !account.Usage.PrimaryResetAt.IsZero() && account.Usage.PrimaryResetAt.After(now) {
			ttr := account.Usage.PrimaryResetAt.Sub(now)
			if ttr > primaryWindowDuration {
				ttr = primaryWindowDuration
			}
			primaryWeight = float64(ttr) / float64(primaryWindowDuration)
		}

		// Secondary time weight
		secondaryWeight := 1.0
		if !account.Usage.SecondaryResetAt.IsZero() && account.Usage.SecondaryResetAt.After(now) {
			ttr := account.Usage.SecondaryResetAt.Sub(now)
			if ttr > secondaryWindowDuration {
				ttr = secondaryWindowDuration
			}
			secondaryWeight = float64(ttr) / float64(secondaryWindowDuration)

			if pa.earliestSecondaryReset.IsZero() || account.Usage.SecondaryResetAt.Before(pa.earliestSecondaryReset) {
				pa.earliestSecondaryReset = account.Usage.SecondaryResetAt
			}
			if account.Usage.SecondaryResetAt.Before(in24h) {
				pa.resetsIn24h++
			}
		}

		if usagePrimaryWindowAvailable(account.Usage) {
			pa.totalEffP += usedP * primaryWeight
			pa.nPrimary++
		}
		if usageSecondaryWindowAvailable(account.Usage) {
			pa.totalEffS += usedS * secondaryWeight
			pa.nSecondary++
		}
	}

	var results []PoolUtilization
	for _, accType := range []AccountType{AccountTypeCodex, AccountTypeClaude, AccountTypeGemini, AccountTypeAntigravity} {
		pa := accums[accType]
		if pa.total == 0 {
			continue
		}

		pu := PoolUtilization{
			Provider:          string(accType),
			AvailableAccounts: pa.available,
			TotalAccounts:     pa.total,
			ResetsIn24h:       pa.resetsIn24h,
		}
		if pa.nPrimary > 0 {
			pu.TimeWeightedPrimaryPct = (pa.totalEffP / pa.nPrimary) * 100
		}
		if pa.nSecondary > 0 {
			pu.TimeWeightedSecondaryPct = (pa.totalEffS / pa.nSecondary) * 100
		}
		if !pa.earliestSecondaryReset.IsZero() && pa.earliestSecondaryReset.After(now) {
			pu.NextSecondaryResetIn = formatDuration(pa.earliestSecondaryReset.Sub(now))
		}

		results = append(results, pu)
	}
	return results
}

func earliestReset(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() {
		return a
	}
	if a.Before(b) {
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
	ZAICount         int            `json:"zai_count"`
	AvgPrimaryUsed   float64        `json:"avg_primary_used"`
	AvgSecondaryUsed float64        `json:"avg_secondary_used"`
	MinSecondaryUsed float64        `json:"min_secondary_used"`
	MaxSecondaryUsed float64        `json:"max_secondary_used"`
	Accounts         []AccountBrief `json:"accounts"`
	// Provider-specific usage summaries
	Providers *ProviderUsageSummary `json:"providers,omitempty"`
}

// ProviderUsageSummary contains usage summaries for each provider type.
type ProviderUsageSummary struct {
	Codex  *CodexUsageSummary  `json:"codex,omitempty"`
	Claude *ClaudeUsageSummary `json:"claude,omitempty"`
	Gemini *GeminiUsageSummary `json:"gemini,omitempty"`
}

// CodexUsageSummary contains Codex-specific usage info.
type CodexUsageSummary struct {
	HealthyCount int              `json:"healthy_count"`
	TotalCount   int              `json:"total_count"`
	FiveHour     UsageWindowStats `json:"five_hour"` // Primary window
	Weekly       UsageWindowStats `json:"weekly"`    // Secondary window
}

// ClaudeUsageSummary contains Claude-specific usage info.
type ClaudeUsageSummary struct {
	HealthyCount int              `json:"healthy_count"`
	TotalCount   int              `json:"total_count"`
	Tokens       UsageWindowStats `json:"tokens"`   // Token rate limit
	Requests     UsageWindowStats `json:"requests"` // Request rate limit
}

// GeminiUsageSummary contains Gemini-specific usage info.
type GeminiUsageSummary struct {
	HealthyCount int              `json:"healthy_count"`
	TotalCount   int              `json:"total_count"`
	Daily        UsageWindowStats `json:"daily"` // Daily usage
}

// UsageWindowStats contains stats for a usage window.
type UsageWindowStats struct {
	AvgUsedPct     float64   `json:"avg_used_pct"`
	MinUsedPct     float64   `json:"min_used_pct"`
	MaxUsedPct     float64   `json:"max_used_pct"`
	AvailableCount int       `json:"available_count"`
	NextResetAt    time.Time `json:"next_reset_at,omitempty"`
	WindowName     string    `json:"window_name,omitempty"` // e.g., "5 hours", "7 days", "24 hours"
}

// AccountBrief is a summary of an account for the usage endpoint.
type AccountBrief struct {
	ID                 string  `json:"id"`
	Type               string  `json:"type"`
	Plan               string  `json:"plan"`
	Status             string  `json:"status"` // "healthy", "dead", "disabled"
	PrimaryPct         int     `json:"primary_pct"`
	SecondaryPct       int     `json:"secondary_pct"`
	PrimaryAvailable   bool    `json:"primary_available"`
	SecondaryAvailable bool    `json:"secondary_available"`
	Score              float64 `json:"score"`
	// Provider-specific labels for the percentages
	PrimaryLabel   string `json:"primary_label,omitempty"`   // e.g., "5hr tokens", "daily"
	SecondaryLabel string `json:"secondary_label,omitempty"` // e.g., "weekly", "requests"
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
	var primaryHealthyCount, secondaryHealthyCount int

	// Provider-specific tracking
	type providerStats struct {
		total, healthy                       int
		primaryCount, secondaryCount         int
		primarySum, secondarySum             float64
		primaryMin, primaryMax               float64
		secondaryMin, secondaryMax           float64
		nextPrimaryReset, nextSecondaryReset time.Time
	}
	codexStats := providerStats{primaryMin: 1.0, secondaryMin: 1.0}
	claudeStats := providerStats{primaryMin: 1.0, secondaryMin: 1.0}
	geminiStats := providerStats{primaryMin: 1.0, secondaryMin: 1.0}

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
		case AccountTypeZAI:
			stats.ZAICount++
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
		primaryAvailable := usagePrimaryWindowAvailable(a.Usage)
		secondaryAvailable := usageSecondaryWindowAvailable(a.Usage)

		isHealthy := !a.Dead && !a.Disabled

		// Track min/max for healthy accounts with an actual window. An absent
		// five-hour limit is not the same thing as a five-hour limit at 0%.
		if isHealthy {
			if primaryAvailable {
				totalP += primaryUsed
				primaryHealthyCount++
			}
			if secondaryAvailable {
				totalS += secondaryUsed
				secondaryHealthyCount++
				if secondaryUsed < stats.MinSecondaryUsed {
					stats.MinSecondaryUsed = secondaryUsed
				}
				if secondaryUsed > stats.MaxSecondaryUsed {
					stats.MaxSecondaryUsed = secondaryUsed
				}
			}
		}

		// Track provider-specific stats
		var ps *providerStats
		switch a.Type {
		case AccountTypeCodex:
			ps = &codexStats
		case AccountTypeClaude:
			ps = &claudeStats
		case AccountTypeGemini:
			ps = &geminiStats
		}
		if ps != nil {
			ps.total++
			if isHealthy {
				ps.healthy++
				if primaryAvailable {
					ps.primaryCount++
					ps.primarySum += primaryUsed
					if primaryUsed < ps.primaryMin {
						ps.primaryMin = primaryUsed
					}
					if primaryUsed > ps.primaryMax {
						ps.primaryMax = primaryUsed
					}
					if !a.Usage.PrimaryResetAt.IsZero() && (ps.nextPrimaryReset.IsZero() || a.Usage.PrimaryResetAt.Before(ps.nextPrimaryReset)) {
						ps.nextPrimaryReset = a.Usage.PrimaryResetAt
					}
				}
				if secondaryAvailable {
					ps.secondaryCount++
					ps.secondarySum += secondaryUsed
					if secondaryUsed < ps.secondaryMin {
						ps.secondaryMin = secondaryUsed
					}
					if secondaryUsed > ps.secondaryMax {
						ps.secondaryMax = secondaryUsed
					}
					if !a.Usage.SecondaryResetAt.IsZero() && (ps.nextSecondaryReset.IsZero() || a.Usage.SecondaryResetAt.Before(ps.nextSecondaryReset)) {
						ps.nextSecondaryReset = a.Usage.SecondaryResetAt
					}
				}
			}
		}

		score := 0.0
		if isHealthy {
			score = scoreAccountLocked(a, now)
		}

		// Provider-specific labels
		var primaryLabel, secondaryLabel string
		switch a.Type {
		case AccountTypeCodex:
			primaryLabel = "5hr"
			secondaryLabel = "weekly"
		case AccountTypeClaude:
			primaryLabel = "tokens"
			secondaryLabel = "requests"
		case AccountTypeGemini, AccountTypeAntigravity:
			primaryLabel = "daily"
			secondaryLabel = ""
		}

		stats.Accounts = append(stats.Accounts, AccountBrief{
			ID:                 a.ID,
			Type:               string(a.Type),
			Plan:               a.PlanType,
			Status:             status,
			PrimaryPct:         int(primaryUsed * 100),
			SecondaryPct:       int(secondaryUsed * 100),
			PrimaryAvailable:   primaryAvailable,
			SecondaryAvailable: secondaryAvailable,
			Score:              score,
			PrimaryLabel:       primaryLabel,
			SecondaryLabel:     secondaryLabel,
		})

		a.mu.Unlock()
	}

	if primaryHealthyCount > 0 {
		stats.AvgPrimaryUsed = totalP / float64(primaryHealthyCount)
	}
	if secondaryHealthyCount > 0 {
		stats.AvgSecondaryUsed = totalS / float64(secondaryHealthyCount)
	}
	if stats.MinSecondaryUsed > stats.MaxSecondaryUsed {
		stats.MinSecondaryUsed = 0
	}

	// Build provider-specific summaries
	stats.Providers = &ProviderUsageSummary{}

	if codexStats.total > 0 {
		stats.Providers.Codex = &CodexUsageSummary{
			TotalCount:   codexStats.total,
			HealthyCount: codexStats.healthy,
			FiveHour: UsageWindowStats{
				WindowName:     "5 hours",
				AvailableCount: codexStats.primaryCount,
			},
			Weekly: UsageWindowStats{
				WindowName:     "7 days",
				AvailableCount: codexStats.secondaryCount,
			},
		}
		if codexStats.primaryCount > 0 {
			stats.Providers.Codex.FiveHour.AvgUsedPct = (codexStats.primarySum / float64(codexStats.primaryCount)) * 100
			stats.Providers.Codex.FiveHour.MinUsedPct = codexStats.primaryMin * 100
			stats.Providers.Codex.FiveHour.MaxUsedPct = codexStats.primaryMax * 100
			stats.Providers.Codex.FiveHour.NextResetAt = codexStats.nextPrimaryReset
		}
		if codexStats.secondaryCount > 0 {
			stats.Providers.Codex.Weekly.AvgUsedPct = (codexStats.secondarySum / float64(codexStats.secondaryCount)) * 100
			stats.Providers.Codex.Weekly.MinUsedPct = codexStats.secondaryMin * 100
			stats.Providers.Codex.Weekly.MaxUsedPct = codexStats.secondaryMax * 100
			stats.Providers.Codex.Weekly.NextResetAt = codexStats.nextSecondaryReset
		}
	}

	if claudeStats.total > 0 {
		stats.Providers.Claude = &ClaudeUsageSummary{
			TotalCount:   claudeStats.total,
			HealthyCount: claudeStats.healthy,
			Tokens: UsageWindowStats{
				WindowName:     "tokens",
				AvailableCount: claudeStats.primaryCount,
			},
			Requests: UsageWindowStats{
				WindowName:     "requests",
				AvailableCount: claudeStats.secondaryCount,
			},
		}
		if claudeStats.primaryCount > 0 {
			stats.Providers.Claude.Tokens.AvgUsedPct = (claudeStats.primarySum / float64(claudeStats.primaryCount)) * 100
			stats.Providers.Claude.Tokens.MinUsedPct = claudeStats.primaryMin * 100
			stats.Providers.Claude.Tokens.MaxUsedPct = claudeStats.primaryMax * 100
			stats.Providers.Claude.Tokens.NextResetAt = claudeStats.nextPrimaryReset
		}
		if claudeStats.secondaryCount > 0 {
			stats.Providers.Claude.Requests.AvgUsedPct = (claudeStats.secondarySum / float64(claudeStats.secondaryCount)) * 100
			stats.Providers.Claude.Requests.MinUsedPct = claudeStats.secondaryMin * 100
			stats.Providers.Claude.Requests.MaxUsedPct = claudeStats.secondaryMax * 100
			stats.Providers.Claude.Requests.NextResetAt = claudeStats.nextSecondaryReset
		}
	}

	if geminiStats.total > 0 {
		stats.Providers.Gemini = &GeminiUsageSummary{
			TotalCount:   geminiStats.total,
			HealthyCount: geminiStats.healthy,
			Daily: UsageWindowStats{
				WindowName:     "24 hours",
				AvailableCount: geminiStats.primaryCount,
			},
		}
		if geminiStats.primaryCount > 0 {
			stats.Providers.Gemini.Daily.AvgUsedPct = (geminiStats.primarySum / float64(geminiStats.primaryCount)) * 100
			stats.Providers.Gemini.Daily.MinUsedPct = geminiStats.primaryMin * 100
			stats.Providers.Gemini.Daily.MaxUsedPct = geminiStats.primaryMax * 100
			stats.Providers.Gemini.Daily.NextResetAt = geminiStats.nextPrimaryReset
		}
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
