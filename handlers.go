package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

func (h *proxyHandler) serveHealth(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	respondJSON(w, map[string]any{
		"status": "ok",
		"uptime": formatDuration(time.Since(h.startTime)),
	})
}

func (h *proxyHandler) serveAccounts(w http.ResponseWriter) {
	type row struct {
		ID                      string      `json:"id"`
		PublicID                string      `json:"public_id"`
		Type                    AccountType `json:"type"`
		PlanType                string      `json:"plan_type,omitempty"`
		AccountID               string      `json:"account_id,omitempty"`
		IDTokenChatGPTAccountID string      `json:"id_token_chatgpt_account_id,omitempty"`
		Disabled                bool        `json:"disabled"`
		Dead                    bool        `json:"dead"`
		NeedsVerification       bool        `json:"needs_verification,omitempty"`
		VerificationURL         string      `json:"verification_url,omitempty"`
		HealthError             string      `json:"health_error,omitempty"`
		CyberAccess             bool        `json:"cyber_access,omitempty"`
		Inflight                int64       `json:"inflight"`
		ExpiresAt               time.Time   `json:"expires_at,omitempty"`
		LastRefresh             time.Time   `json:"last_refresh,omitempty"`
		Penalty                 float64     `json:"penalty"`
		Score                   float64     `json:"score"`
		ScoreTooltip            string      `json:"score_tooltip,omitempty"`
		IsPrimary               bool        `json:"is_primary"`
		Usage                   any         `json:"usage"`
		Totals                  any         `json:"totals"`
	}
	now := time.Now()
	h.pool.mu.RLock()
	out := make([]row, 0, len(h.pool.accounts))
	for _, a := range h.pool.accounts {
		a.mu.Lock()
		planType := a.PlanType
		accountID := a.AccountID
		idTokID := a.IDTokenChatGPTAccountID
		disabled := a.Disabled
		dead := a.Dead
		needsVerification := a.NeedsVerification
		verificationURL := a.VerificationURL
		healthError := a.HealthError
		cyberAccess := a.CyberAccess
		expiresAt := a.ExpiresAt
		lastRefresh := a.LastRefresh
		penalty := a.Penalty
		breakdown := scoreAccountBreakdownLocked(a, now)
		score := breakdown.Score
		scoreTooltip := scoreTooltipFromBreakdownLocked(a, now, breakdown)
		usage := a.Usage
		totals := a.Totals
		a.mu.Unlock()

		out = append(out, row{
			ID:                      a.ID,
			PublicID:                hashAccountID(a.ID),
			Type:                    a.Type,
			PlanType:                planType,
			AccountID:               accountID,
			IDTokenChatGPTAccountID: idTokID,
			Disabled:                disabled,
			Dead:                    dead,
			NeedsVerification:       needsVerification,
			VerificationURL:         verificationURL,
			HealthError:             healthError,
			CyberAccess:             cyberAccess,
			Inflight:                atomic.LoadInt64(&a.Inflight),
			ExpiresAt:               expiresAt,
			LastRefresh:             lastRefresh,
			Penalty:                 penalty,
			Score:                   score,
			ScoreTooltip:            scoreTooltip,
			Usage:                   usage,
			Totals:                  totals,
		})
	}
	h.pool.mu.RUnlock()

	// Mark highest-scoring non-dead account per type as primary
	highestScore := make(map[AccountType]float64)
	highestIdx := make(map[AccountType]int)
	for i, r := range out {
		if !r.Dead && !r.Disabled && r.Score > highestScore[r.Type] {
			highestScore[r.Type] = r.Score
			highestIdx[r.Type] = i
		}
	}
	for _, idx := range highestIdx {
		out[idx].IsPrimary = true
	}

	w.Header().Set("Content-Type", "application/json")
	respondJSON(w, out)
}

func (h *proxyHandler) reloadAccounts() {
	// A usage poll works on account pointers copied from the pool. Serialize reloads
	// with the poller so a completed fetch cannot update an account after it has
	// been replaced, then carry the latest snapshot onto the reloaded account.
	h.usagePollMu.Lock()
	defer h.usagePollMu.Unlock()

	log.Printf("reloading pool from %s", h.cfg.poolDir)
	accs, err := loadPool(h.cfg.poolDir, h.registry)
	if err != nil {
		log.Printf("load pool: %v", err)
		return
	}
	preserveUsageSnapshots(h.pool.allAccounts(), accs)
	h.pool.replace(accs)
	if h.pool.count() == 0 {
		log.Printf("warning: loaded 0 accounts from %s", h.cfg.poolDir)
	}

	// Restore persisted usage totals so hot-reloads don't lose data
	if h.store != nil {
		if persisted, err := h.store.loadAllAccountUsage(); err == nil && len(persisted) > 0 {
			h.pool.mu.RLock()
			for _, a := range h.pool.accounts {
				if usage, ok := persisted[a.ID]; ok {
					a.mu.Lock()
					a.Totals = usage
					a.mu.Unlock()
				}
			}
			h.pool.mu.RUnlock()
		}
	}
}

func preserveUsageSnapshots(current, loaded []*Account) {
	byID := make(map[string]*Account, len(current))
	for _, account := range current {
		if account != nil {
			byID[string(account.Type)+"\x00"+account.ID] = account
		}
	}
	for _, account := range loaded {
		if account == nil {
			continue
		}
		previous := byID[string(account.Type)+"\x00"+account.ID]
		if previous == nil {
			continue
		}
		previous.mu.Lock()
		usage := previous.Usage
		resetCredits := append([]RateLimitResetCredit(nil), previous.RateLimitResetCredits...)
		resetCreditsAvailable := previous.ResetCreditsAvailable
		resetCreditsRetrievedAt := previous.ResetCreditsRetrievedAt
		previous.mu.Unlock()
		account.mu.Lock()
		account.Usage = mergeUsage(account.Usage, usage)
		account.RateLimitResetCredits = resetCredits
		account.ResetCreditsAvailable = resetCreditsAvailable
		account.ResetCreditsRetrievedAt = resetCreditsRetrievedAt
		account.mu.Unlock()
	}
}

// setAccountDisabled changes whether an account may receive traffic and
// persists the state in its provider file.
func (h *proxyHandler) setAccountDisabled(w http.ResponseWriter, accountID string, disabled bool) {
	h.pool.mu.RLock()
	var target *Account
	for _, account := range h.pool.accounts {
		if account.ID == accountID {
			target = account
			break
		}
	}
	h.pool.mu.RUnlock()
	if target == nil {
		respondJSONError(w, http.StatusNotFound, "account not found")
		return
	}

	target.mu.Lock()
	previous := target.Disabled
	target.Disabled = disabled
	target.mu.Unlock()
	if err := saveAccount(target); err != nil {
		target.mu.Lock()
		target.Disabled = previous
		target.mu.Unlock()
		respondJSONError(w, http.StatusInternalServerError, "failed to persist account state")
		return
	}

	action := "enabled"
	if disabled {
		action = "disabled"
	}
	log.Printf("%s account %s", action, accountID)
	respondJSON(w, map[string]any{"status": "ok", "account": accountID, "disabled": disabled})
}

// resurrectAccount marks a dead account as alive and resets its penalty.
func (h *proxyHandler) resurrectAccount(w http.ResponseWriter, accountID string) {
	h.pool.mu.Lock()
	defer h.pool.mu.Unlock()

	for _, a := range h.pool.accounts {
		if a.ID == accountID {
			a.mu.Lock()
			wasDead := a.Dead
			wasRateLimited := !a.RateLimitUntil.IsZero() && a.RateLimitUntil.After(time.Now())
			a.Dead = false
			a.Penalty = 0
			a.RateLimitUntil = time.Time{}
			a.mu.Unlock()
			log.Printf("resurrected account %s (was_dead=%v, was_rate_limited=%v)", accountID, wasDead, wasRateLimited)
			w.WriteHeader(http.StatusOK)
			respondJSON(w, map[string]any{"status": "ok", "account": accountID, "was_dead": wasDead})
			return
		}
	}

	respondJSONError(w, http.StatusNotFound, "account not found")
}

// clearAllRateLimits clears rate limits on all accounts.
func (h *proxyHandler) clearAllRateLimits(w http.ResponseWriter) {
	h.pool.mu.Lock()
	defer h.pool.mu.Unlock()

	now := time.Now()
	cleared := 0
	for _, a := range h.pool.accounts {
		a.mu.Lock()
		if !a.RateLimitUntil.IsZero() && a.RateLimitUntil.After(now) {
			a.RateLimitUntil = time.Time{}
			cleared++
		}
		a.mu.Unlock()
	}

	log.Printf("cleared rate limits on %d accounts", cleared)
	respondJSON(w, map[string]any{"status": "ok", "cleared": cleared})
}

// purgeAnonymousUsers removes all usage data for users that are not registered pool users.
func (h *proxyHandler) purgeAnonymousUsers(w http.ResponseWriter) {
	allowed := make(map[string]bool)
	if h.poolUsers != nil {
		for _, u := range h.poolUsers.List() {
			allowed[u.ID] = true
		}
	}

	deleted, err := h.store.purgeNonPoolUsers(allowed)
	if err != nil {
		log.Printf("purge anonymous users failed: %v", err)
		respondJSONError(w, http.StatusInternalServerError, "purge failed: "+err.Error())
		return
	}

	log.Printf("purged %d anonymous usage entries (kept %d pool users)", deleted, len(allowed))
	respondJSON(w, map[string]any{"status": "ok", "deleted": deleted, "kept_users": len(allowed)})
}

// forceRefreshAccount forces a token refresh for a specific account, bypassing rate limits.
func (h *proxyHandler) forceRefreshAccount(w http.ResponseWriter, accountID string) {
	h.pool.mu.RLock()
	var target *Account
	for _, a := range h.pool.accounts {
		if a.ID == accountID {
			target = a
			break
		}
	}
	h.pool.mu.RUnlock()

	if target == nil {
		respondJSONError(w, http.StatusNotFound, "account not found")
		return
	}

	// Clear rate limit first
	target.mu.Lock()
	target.RateLimitUntil = time.Time{}
	target.LastRefresh = time.Time{} // Clear last refresh to bypass needsRefresh check
	hasRefreshToken := target.RefreshToken != ""
	target.mu.Unlock()

	if !hasRefreshToken {
		respondJSONError(w, http.StatusBadRequest, "account has no refresh token")
		return
	}

	// Force refresh
	err := h.refreshAccountOnce(context.Background(), target)
	if err != nil {
		log.Printf("force refresh %s failed: %v", accountID, err)
		respondJSONError(w, http.StatusInternalServerError, "refresh failed: "+err.Error())
		return
	}

	log.Printf("force refresh %s succeeded", accountID)
	respondJSON(w, map[string]any{"status": "ok", "account": accountID})
}

// serveTokenCapacity returns token tracking and capacity analysis data.
func (h *proxyHandler) serveTokenCapacity(w http.ResponseWriter) {
	// Collect in-memory account totals
	type accountTokens struct {
		ID               string    `json:"id"`
		PlanType         string    `json:"plan_type"`
		InputTokens      int64     `json:"input_tokens"`
		CachedTokens     int64     `json:"cached_tokens"`
		OutputTokens     int64     `json:"output_tokens"`
		ReasoningTokens  int64     `json:"reasoning_tokens"`
		BillableTokens   int64     `json:"billable_tokens"`
		RequestCount     int64     `json:"request_count"`
		LastPrimaryPct   float64   `json:"last_primary_pct"`
		LastSecondaryPct float64   `json:"last_secondary_pct"`
		LastUpdated      time.Time `json:"last_updated,omitempty"`
	}

	var accounts []accountTokens
	h.pool.mu.RLock()
	for _, a := range h.pool.accounts {
		a.mu.Lock()
		if a.Totals.RequestCount > 0 {
			accounts = append(accounts, accountTokens{
				ID:               a.ID,
				PlanType:         a.PlanType,
				InputTokens:      a.Totals.TotalInputTokens,
				CachedTokens:     a.Totals.TotalCachedTokens,
				OutputTokens:     a.Totals.TotalOutputTokens,
				ReasoningTokens:  a.Totals.TotalReasoningTokens,
				BillableTokens:   a.Totals.TotalBillableTokens,
				RequestCount:     a.Totals.RequestCount,
				LastPrimaryPct:   a.Totals.LastPrimaryPct,
				LastSecondaryPct: a.Totals.LastSecondaryPct,
				LastUpdated:      a.Totals.LastUpdated,
			})
		}
		a.mu.Unlock()
	}
	h.pool.mu.RUnlock()

	// Get persisted capacity data from store
	var planCapacity map[string]TokenCapacity
	var recentSamples []CapacitySample
	var persistedUsage map[string]AccountUsage
	var capacityEstimates map[string]CapacityEstimate

	if h.store != nil {
		var err error
		planCapacity, err = h.store.loadAllPlanCapacity()
		if err != nil {
			log.Printf("failed to load plan capacity: %v", err)
		}
		recentSamples, err = h.store.getRecentSamples(50)
		if err != nil {
			log.Printf("failed to load recent samples: %v", err)
		}
		persistedUsage, err = h.store.loadAllAccountUsage()
		if err != nil {
			log.Printf("failed to load account usage: %v", err)
		}
		capacityEstimates, err = h.store.EstimateCapacity()
		if err != nil {
			log.Printf("failed to estimate capacity: %v", err)
		}
	}

	resp := map[string]any{
		"accounts":           accounts,
		"plan_capacity":      planCapacity,
		"capacity_estimates": capacityEstimates,
		"recent_samples":     recentSamples,
		"persisted":          persistedUsage,
		"timestamp":          time.Now(),
		"model_info": map[string]any{
			"description": "Capacity estimation model",
			"formula":     "effective_tokens = input + (cached * 0.1) + (output * output_mult) + (reasoning * reasoning_mult)",
			"defaults": map[string]float64{
				"cached_multiplier":    0.1,
				"output_multiplier":    4.0,
				"reasoning_multiplier": 4.0,
			},
			"notes": "Multipliers are refined as more data is collected. Estimates improve with sample_count > 20.",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	respondJSON(w, resp)
}

func (h *proxyHandler) serveFakeOAuthToken(w http.ResponseWriter, r *http.Request) {
	// Check if this is a pool user refresh request
	if r.Method == http.MethodPost && h.poolUsers != nil {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if json.Unmarshal(body, &req) == nil && strings.HasPrefix(req.RefreshToken, "poolrt_") {
			h.handlePoolUserRefresh(w, req.RefreshToken)
			return
		}
	}

	// Return a syntactically-valid JWT-ish id_token (Codex parses it), but it is not
	// used for upstream calls because we always overwrite Authorization headers.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	exp := time.Now().Add(1 * time.Hour).Unix()
	payload := fmt.Sprintf(`{"exp":%d,"sub":"pooled","https://api.openai.com/auth":{"chatgpt_plan_type":"pro","chatgpt_account_id":"pooled"}}`, exp)
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	jwt := header + "." + body + "." + sig

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"access_token":"pooled","refresh_token":"pooled","id_token":"%s","token_type":"Bearer","expires_in":3600}`, jwt)
}

func (h *proxyHandler) handlePoolUserRefresh(w http.ResponseWriter, refreshToken string) {
	// Extract user ID from refresh token: poolrt_<user_id>_<random>
	parts := strings.Split(refreshToken, "_")
	if len(parts) < 3 {
		respondJSONError(w, http.StatusBadRequest, "invalid refresh token")
		return
	}
	userID := parts[1]

	user := h.poolUsers.Get(userID)
	if user == nil {
		respondJSONError(w, http.StatusNotFound, "user not found")
		return
	}
	if user.Disabled {
		respondJSONError(w, http.StatusForbidden, "user disabled")
		return
	}

	secret := getPoolJWTSecret()
	if secret == "" {
		respondJSONError(w, http.StatusServiceUnavailable, "JWT secret not configured")
		return
	}

	auth, err := generateCodexAuth(secret, user)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token":  auth.Tokens.AccessToken,
		"refresh_token": auth.Tokens.RefreshToken,
		"id_token":      auth.Tokens.IDToken,
		"token_type":    "Bearer",
		"expires_in":    31536000, // 1 year
	})
}

func isUsageRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	// Codex CLI uses /api/codex/usage; legacy clients use /backend-api/wham/usage.
	// Child resources under the legacy path must continue to the upstream API.
	path := strings.TrimSuffix(r.URL.Path, "/")
	return path == "/backend-api/wham/usage" || path == "/api/codex/usage"
}

// isClaudeProfileRequest checks if this is a Claude CLI profile request
func isClaudeProfileRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	return r.URL.Path == "/api/claude_cli_profile" ||
		r.URL.Path == "/api/oauth/profile" ||
		r.URL.Path == "/api/oauth/claude_cli/client_data"
}

// isClaudeUsageRequest checks if this is a Claude usage request
func isClaudeUsageRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	return r.URL.Path == "/api/oauth/usage"
}

// handleClaudeProfile returns pool info for Claude CLI profile requests
func (h *proxyHandler) handleClaudeProfile(w http.ResponseWriter, r *http.Request) {
	stats := h.pool.getPoolStats()

	// Return a profile that indicates this is a pooled account
	resp := map[string]any{
		"email":             "pool@codex-pool.local",
		"email_verified":    true,
		"name":              "Codex Pool",
		"subscription_type": "max",
		"plan_type":         "max",
		"is_pooled":         true,
		"pool_stats": map[string]any{
			"total_accounts":   stats.TotalCount,
			"healthy_accounts": stats.HealthyCount,
			"claude_accounts":  stats.ClaudeCount,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	respondJSON(w, resp)
}

// handleClaudeUsage returns blended usage from all Claude accounts
func (h *proxyHandler) handleClaudeUsage(w http.ResponseWriter, r *http.Request) {
	h.pollUpstreamUsage()

	// Use time-weighted usage for accurate pool utilization
	snap := h.pool.timeWeightedUsageByType(AccountTypeClaude)
	stats := h.pool.getPoolStats()

	// Format response like Claude's /api/oauth/usage endpoint
	now := time.Now()
	fiveHourReset := now.Add(5 * time.Hour)
	sevenDayReset := now.Add(7 * 24 * time.Hour)

	// Use earliest reset (soonest capacity refill)
	if !snap.PrimaryResetAt.IsZero() {
		fiveHourReset = snap.PrimaryResetAt
	}
	if !snap.SecondaryResetAt.IsZero() {
		sevenDayReset = snap.SecondaryResetAt
	}

	resp := map[string]any{
		"five_hour": map[string]any{
			"utilization": snap.PrimaryUsedPercent * 100,
			"resets_at":   fiveHourReset.Format(time.RFC3339),
		},
		"seven_day": map[string]any{
			"utilization": snap.SecondaryUsedPercent * 100,
			"resets_at":   sevenDayReset.Format(time.RFC3339),
		},
		"extra_usage": map[string]any{
			"is_enabled": false,
		},
		// Pool-specific info
		"is_pooled": true,
		"pool": map[string]any{
			"total_accounts":   stats.TotalCount,
			"healthy_accounts": stats.HealthyCount,
			"claude_accounts":  stats.ClaudeCount,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	respondJSON(w, resp)
}

func codexUsageWindowResponse(window *codexUsageWindow, now time.Time) any {
	if window == nil {
		return nil
	}
	resetAfter := int64(0)
	resetAt := int64(0)
	if !window.ResetAt.IsZero() {
		resetAt = window.ResetAt.Unix()
		resetAfter = int64(window.ResetAt.Sub(now).Seconds())
		if resetAfter < 0 {
			resetAfter = 0
		}
	}
	return map[string]any{
		"used_percent":         window.UsedPercent * 100,
		"limit_window_seconds": window.WindowMinutes * 60,
		"reset_after_seconds":  resetAfter,
		"reset_at":             resetAt,
	}
}

func (h *proxyHandler) handleAggregatedUsage(w http.ResponseWriter, reqID string) {
	now := time.Now()
	codexSnap := h.pool.timeWeightedUsageByType(AccountTypeCodex)
	codexSlots := codexUsageSlotsFromSnapshot(codexSnap)
	poolStats := h.pool.getPoolStats()
	codexHealthy := 0
	codexWeeklyUsed := 0.0
	if poolStats.Providers != nil && poolStats.Providers.Codex != nil {
		codexHealthy = poolStats.Providers.Codex.HealthyCount
		codexWeeklyUsed = poolStats.Providers.Codex.Weekly.AvgUsedPct / 100.0
	}

	resp := map[string]any{
		"plan_type": "pool", // Indicate this is a pool, not a single account
		"rate_limit_reset_credits": map[string]any{
			"available_count": 0,
		},
		"rate_limit": map[string]any{
			"allowed":          codexHealthy > 0,
			"limit_reached":    codexWeeklyUsed > 0.9,
			"primary_window":   codexUsageWindowResponse(codexSlots.Primary, now),
			"secondary_window": codexUsageWindowResponse(codexSlots.Secondary, now),
		},
		// Pool-specific stats
		"pool": map[string]any{
			"total_accounts":    poolStats.TotalCount,
			"healthy_accounts":  poolStats.HealthyCount,
			"dead_accounts":     poolStats.DeadCount,
			"codex_accounts":    poolStats.CodexCount,
			"gemini_accounts":   poolStats.GeminiCount,
			"claude_accounts":   poolStats.ClaudeCount,
			"zai_accounts":      poolStats.ZAICount,
			"avg_primary_pct":   int(poolStats.AvgPrimaryUsed * 100),
			"avg_secondary_pct": int(poolStats.AvgSecondaryUsed * 100),
			"min_secondary_pct": int(poolStats.MinSecondaryUsed * 100),
			"max_secondary_pct": int(poolStats.MaxSecondaryUsed * 100),
			"accounts":          poolStats.Accounts,
			"providers":         poolStats.Providers,
		},
	}
	if h.cfg.debug.Load() {
		log.Printf("[%s] aggregate usage served locally", reqID)
	}
	w.Header().Set("Content-Type", "application/json")
	respondJSON(w, resp)
}
