package main

import (
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
		Type                    AccountType `json:"type"`
		PlanType                string      `json:"plan_type,omitempty"`
		AccountID               string      `json:"account_id,omitempty"`
		IDTokenChatGPTAccountID string      `json:"id_token_chatgpt_account_id,omitempty"`
		Disabled                bool        `json:"disabled"`
		Dead                    bool        `json:"dead"`
		Inflight                int64       `json:"inflight"`
		ExpiresAt               time.Time   `json:"expires_at,omitempty"`
		LastRefresh             time.Time   `json:"last_refresh,omitempty"`
		Penalty                 float64     `json:"penalty"`
		Score                   float64     `json:"score"`
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
		expiresAt := a.ExpiresAt
		lastRefresh := a.LastRefresh
		penalty := a.Penalty
		score := scoreAccountLocked(a, now)
		usage := a.Usage
		totals := a.Totals
		a.mu.Unlock()

		out = append(out, row{
			ID:                      a.ID,
			Type:                    a.Type,
			PlanType:                planType,
			AccountID:               accountID,
			IDTokenChatGPTAccountID: idTokID,
			Disabled:                disabled,
			Dead:                    dead,
			Inflight:                atomic.LoadInt64(&a.Inflight),
			ExpiresAt:               expiresAt,
			LastRefresh:             lastRefresh,
			Penalty:                 penalty,
			Score:                   score,
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
	log.Printf("reloading pool from %s", h.cfg.poolDir)
	accs, err := loadPool(h.cfg.poolDir, h.registry)
	if err != nil {
		log.Printf("load pool: %v", err)
		return
	}
	h.pool.replace(accs)
	if h.pool.count() == 0 {
		log.Printf("warning: loaded 0 accounts from %s", h.cfg.poolDir)
	}
}

// resurrectAccount marks a dead account as alive and resets its penalty.
func (h *proxyHandler) resurrectAccount(w http.ResponseWriter, accountID string) {
	h.pool.mu.Lock()
	defer h.pool.mu.Unlock()

	for _, a := range h.pool.accounts {
		if a.ID == accountID {
			a.mu.Lock()
			wasDead := a.Dead
			a.Dead = false
			a.Penalty = 0
			a.mu.Unlock()
			log.Printf("resurrected account %s (was_dead=%v)", accountID, wasDead)
			w.WriteHeader(http.StatusOK)
			respondJSON(w, map[string]any{"status": "ok", "account": accountID, "was_dead": wasDead})
			return
		}
	}

	http.Error(w, "account not found", http.StatusNotFound)
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
		http.Error(w, "invalid refresh token", http.StatusBadRequest)
		return
	}
	userID := parts[1]

	user := h.poolUsers.Get(userID)
	if user == nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if user.Disabled {
		http.Error(w, "user disabled", http.StatusForbidden)
		return
	}

	secret := getPoolJWTSecret()
	if secret == "" {
		http.Error(w, "JWT secret not configured", http.StatusServiceUnavailable)
		return
	}

	auth, err := generateCodexAuth(secret, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	// Handle both paths - Codex CLI uses /api/codex/usage, legacy uses /backend-api/wham/usage
	return strings.HasPrefix(r.URL.Path, "/backend-api/wham/usage") ||
		strings.HasPrefix(r.URL.Path, "/api/codex/usage")
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
	h.refreshUsageIfStale()

	// Get average usage across all Claude accounts
	snap := h.pool.averageUsageByType(AccountTypeClaude)
	stats := h.pool.getPoolStats()

	// Format response like Claude's /api/oauth/usage endpoint
	now := time.Now()
	fiveHourReset := now.Add(5 * time.Hour)
	sevenDayReset := now.Add(7 * 24 * time.Hour)

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

func (h *proxyHandler) handleAggregatedUsage(w http.ResponseWriter, reqID string) {
	snap := h.pool.averageUsage()
	poolStats := h.pool.getPoolStats()

	resp := map[string]any{
		"plan_type": "pool", // Indicate this is a pool, not a single account
		"rate_limit": map[string]any{
			"allowed":       poolStats.HealthyCount > 0,
			"limit_reached": poolStats.AvgSecondaryUsed > 0.9,
			"primary_window": map[string]any{
				"used_percent":         int(snap.PrimaryUsed * 100),
				"limit_window_seconds": 18000,
				"reset_after_seconds":  3600,
				"reset_at":             time.Now().Add(3600 * time.Second).Unix(),
			},
			"secondary_window": map[string]any{
				"used_percent":         int(snap.SecondaryUsed * 100),
				"limit_window_seconds": 604800,
				"reset_after_seconds":  86400,
				"reset_at":             time.Now().Add(24 * time.Hour).Unix(),
			},
		},
		// Pool-specific stats
		"pool": map[string]any{
			"total_accounts":    poolStats.TotalCount,
			"healthy_accounts":  poolStats.HealthyCount,
			"dead_accounts":     poolStats.DeadCount,
			"codex_accounts":    poolStats.CodexCount,
			"gemini_accounts":   poolStats.GeminiCount,
			"claude_accounts":   poolStats.ClaudeCount,
			"avg_primary_pct":   int(poolStats.AvgPrimaryUsed * 100),
			"avg_secondary_pct": int(poolStats.AvgSecondaryUsed * 100),
			"min_secondary_pct": int(poolStats.MinSecondaryUsed * 100),
			"max_secondary_pct": int(poolStats.MaxSecondaryUsed * 100),
			"accounts":          poolStats.Accounts,
			"providers":         poolStats.Providers,
		},
	}
	if h.cfg.debug {
		log.Printf("[%s] aggregate usage served locally", reqID)
	}
	w.Header().Set("Content-Type", "application/json")
	respondJSON(w, resp)
}
