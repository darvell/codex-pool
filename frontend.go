package main

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed templates/friend_landing.html templates/cute_code_landing.html templates/og-image.png templates/og-image-transparent.webp templates/assets/favicon.ico
var friendContent embed.FS

//go:embed web/dist/index.html web/dist/assets/*
var signalRoomContent embed.FS

func (h *proxyHandler) serveFriendLanding(w http.ResponseWriter, r *http.Request) {
	data, err := friendContent.ReadFile("templates/friend_landing.html")
	if err != nil {
		http.Error(w, "internal error: template missing", http.StatusInternalServerError)
		return
	}
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl, err := template.New("friend").Parse(string(data))
	if err != nil {
		http.Error(w, "internal error: template parse failed", http.StatusInternalServerError)
		return
	}
	friendName := "PP"
	tagline := "For those who are friends, unlimited pooled AI resources await."
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
	_ = tmpl.Execute(w, map[string]string{
		"FriendName": friendName,
		"PublicURL":  h.getEffectivePublicURL(r),
		"Tagline":    tagline,
	})
}

func (h *proxyHandler) servePassportSPA(w http.ResponseWriter, r *http.Request) {
	data, err := signalRoomContent.ReadFile("web/dist/index.html")
	if err != nil {
		http.Error(w, "internal error: signal room missing", http.StatusInternalServerError)
		return
	}
	noStore(w)
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (h *proxyHandler) serveSignalRoomAsset(w http.ResponseWriter, r *http.Request) {
	assetPath := strings.TrimPrefix(r.URL.Path, "/")
	data, err := signalRoomContent.ReadFile("web/dist/" + assetPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if contentType := mime.TypeByExtension(filepath.Ext(assetPath)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(data)
}

func (h *proxyHandler) serveFavicon(w http.ResponseWriter, r *http.Request) {
	data, err := friendContent.ReadFile("templates/assets/favicon.ico")
	if err != nil {
		http.Error(w, "favicon not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(w, r, "favicon.ico", time.Time{}, bytes.NewReader(data))
}

func (h *proxyHandler) serveOGImage(w http.ResponseWriter, r *http.Request) {
	data, err := friendContent.ReadFile("templates/og-image.png")
	if err != nil {
		http.Error(w, "image not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

func (h *proxyHandler) serveHeroImage(w http.ResponseWriter, r *http.Request) {
	data, err := friendContent.ReadFile("templates/og-image-transparent.webp")
	if err != nil {
		http.Error(w, "image not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/webp")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

func (h *proxyHandler) getEffectivePublicURL(r *http.Request) string {
	if u := h.cfg.publicURL(); u != "" {
		return u
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost:8989"
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

func wantsPowerShell(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("shell"))) {
	case "powershell", "pwsh", "ps", "ps1":
		return true
	default:
		return false
	}
}

func (h *proxyHandler) serveCuteCodeLanding(w http.ResponseWriter, r *http.Request) {
	data, err := friendContent.ReadFile("templates/cute_code_landing.html")
	if err != nil {
		http.Error(w, "internal error: template missing", http.StatusInternalServerError)
		return
	}
	tmpl, err := template.New("cute-code").Parse(string(data))
	if err != nil {
		http.Error(w, "internal error: template parse failed", http.StatusInternalServerError)
		return
	}
	publicURL := h.getEffectivePublicURL(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	_ = tmpl.Execute(w, map[string]string{"PublicURL": publicURL})
}

func (h *proxyHandler) handleFriendClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.cfg == nil || h.cfg.legacyFriendCode == "" {
		http.Error(w, "feature disabled", http.StatusForbidden)
		return
	}

	ip := getClientIP(r)
	if h.bruteForce != nil && h.bruteForce.isBanned(ip) {
		http.Error(w, "too many failed attempts, try again later", http.StatusTooManyRequests)
		return
	}

	var req struct {
		FriendCode string `json:"friend_code"`
		Email      string `json:"user_email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if req.FriendCode != h.cfg.legacyFriendCode {
		if h.bruteForce != nil {
			h.bruteForce.recordFailure(ip)
		}
		respondJSONError(w, http.StatusForbidden, "Invalid Friend Code")
		return
	}

	if h.bruteForce != nil {
		h.bruteForce.recordSuccess(ip)
	}

	if h.poolUsers == nil {
		if h.cfg.poolJWTSecret() == "" {
			respondJSONError(w, http.StatusServiceUnavailable, "System error: Pool user system not configured (missing JWT secret).")
			return
		}
		respondJSONError(w, http.StatusServiceUnavailable, "System error: User storage not initialized.")
		return
	}

	email := req.Email
	if email == "" {
		guestDomain := "pool.local"
		if pubURL := h.cfg.publicURL(); pubURL != "" {
			if u, err := url.Parse(pubURL); err == nil && u.Host != "" {
				host := u.Hostname()
				if net.ParseIP(host) == nil {
					guestDomain = host
				}
			}
		}
		email = "guest@" + guestDomain
	}

	var newUser *PoolUser
	if existing := h.poolUsers.GetByEmail(email); existing != nil {
		newUser = existing
	} else {
		newUser = &PoolUser{
			ID:        randomHex(8),
			Token:     randomHex(16),
			Email:     email,
			PlanType:  "pro",
			CreatedAt: time.Now(),
		}
		if err := h.poolUsers.Create(newUser); err != nil {
			log.Printf("failed to create friend user: %v", err)
			respondJSONError(w, http.StatusInternalServerError, "Failed to create user account.")
			return
		}
	}

	secret := h.cfg.poolJWTSecret()
	authData, err := generateCodexAuth(secret, newUser)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to generate credentials.")
		return
	}
	authJSONBytes, _ := json.MarshalIndent(authData, "", "  ")

	geminiAuthData, err := generateGeminiAuth(secret, newUser)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to generate gemini credentials.")
		return
	}
	geminiJSONBytes, _ := json.MarshalIndent(geminiAuthData, "", "  ")

	claudeAuthData, err := generateClaudeAuth(secret, newUser)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to generate claude credentials.")
		return
	}

	codexAccessToken := ""
	if authData.Tokens != nil {
		codexAccessToken = authData.Tokens.AccessToken
	}
	piModelsJSON, err := generatePiModelsJSON(h.getEffectivePublicURL(r), codexAccessToken, claudeAuthData.AccessToken, h.pool)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to generate pi models config.")
		return
	}
	cuteCodeSettingsJSON, err := generateCuteCodeSettingsJSON(h.getEffectivePublicURL(r), claudeAuthData.AccessToken, h.pool)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to generate cute-code config.")
		return
	}

	geminiAPIKey := generateGeminiAPIKey(secret, newUser)
	publicURL := h.getEffectivePublicURL(r)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"public_url":              publicURL,
		"origin_id":               hashRequestOrigin(r, poolHashSalt(h.cfg.legacyFriendCode)),
		"download_token":          newUser.Token,
		"auth_json":               string(authJSONBytes),
		"gemini_auth_json":        string(geminiJSONBytes),
		"gemini_api_key":          geminiAPIKey,
		"claude_api_key":          claudeAuthData.AccessToken,
		"pi_models_json":          string(piModelsJSON),
		"cute_code_settings_json": string(cuteCodeSettingsJSON),
	})
}

func (h *proxyHandler) generateCuteCodeSettingsForToken(token string, r *http.Request) ([]byte, error) {
	if h.poolUsers == nil && h.passport == nil {
		return nil, fmt.Errorf("pool users not configured")
	}
	user := h.userForSetup(token)
	if user == nil {
		return nil, fmt.Errorf("invalid token")
	}
	if user.Disabled {
		return nil, fmt.Errorf("user disabled")
	}
	secret := h.cfg.poolJWTSecret()
	if secret == "" {
		return nil, fmt.Errorf("JWT secret not configured")
	}
	claudeAuth, err := generateClaudeAuth(secret, user)
	if err != nil {
		return nil, err
	}
	return generateCuteCodeSettingsJSON(h.getEffectivePublicURL(r), claudeAuth.AccessToken, h.pool)
}

func (h *proxyHandler) serveCuteCodeSettingsConfig(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/config/cute-code/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	settingsJSON, err := h.generateCuteCodeSettingsForToken(token, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(settingsJSON)
}

func (h *proxyHandler) serveCuteCodeSetupScript(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/setup/cute-code/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	if _, err := h.generateCuteCodeSettingsForToken(token, r); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	publicURL := h.getEffectivePublicURL(r)

	if wantsPowerShell(r) {
		script := renderSetupScript(cuteCodePowerShell, setupScriptData{publicURL: publicURL, token: token})
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(script))
		return
	}

	script := renderSetupScript(cuteCodeBash, setupScriptData{publicURL: publicURL, token: token})
	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Write([]byte(script))
}

func (h *proxyHandler) serveCodexSetupScript(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/setup/codex/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	publicURL := h.getEffectivePublicURL(r)

	if wantsPowerShell(r) {
		script := renderSetupScript(codexPowerShell, setupScriptData{token: token, publicURL: publicURL})

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(script))
		return
	}

	script := renderSetupScript(codexBash, setupScriptData{token: token, publicURL: publicURL})

	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Write([]byte(script))
}

func (h *proxyHandler) serveGeminiSetupScript(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/setup/gemini/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}

	if h.poolUsers == nil && h.passport == nil {
		http.Error(w, "pool users not configured", http.StatusServiceUnavailable)
		return
	}
	user := h.userForSetup(token)
	if user == nil {
		http.Error(w, "invalid token", http.StatusNotFound)
		return
	}
	if user.Disabled {
		http.Error(w, "user disabled", http.StatusForbidden)
		return
	}

	secret := h.cfg.poolJWTSecret()
	if secret == "" {
		http.Error(w, "JWT secret not configured", http.StatusServiceUnavailable)
		return
	}
	geminiAuth, err := generateGeminiAuth(secret, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	publicURL := h.getEffectivePublicURL(r)

	// Script sets env vars to bypass Google OAuth validation and route through proxy
	// Uses GOOGLE_GENAI_USE_GCA + GOOGLE_CLOUD_ACCESS_TOKEN to skip getTokenInfo() check
	if wantsPowerShell(r) {
		script := renderSetupScript(geminiPowerShell, setupScriptData{publicURL: publicURL, accessToken: geminiAuth.AccessToken})

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(script))
		return
	}

	script := renderSetupScript(geminiBash, setupScriptData{publicURL: publicURL, accessToken: geminiAuth.AccessToken})

	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Write([]byte(script))
}

func (h *proxyHandler) serveClaudeSetupScript(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/setup/claude/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}

	if h.poolUsers == nil && h.passport == nil {
		http.Error(w, "pool users not configured", http.StatusServiceUnavailable)
		return
	}
	user := h.userForSetup(token)
	if user == nil {
		http.Error(w, "invalid token", http.StatusNotFound)
		return
	}
	if user.Disabled {
		http.Error(w, "user disabled", http.StatusForbidden)
		return
	}

	secret := h.cfg.poolJWTSecret()
	if secret == "" {
		http.Error(w, "JWT secret not configured", http.StatusServiceUnavailable)
		return
	}
	claudeAuth, err := generateClaudeAuth(secret, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	publicURL := h.getEffectivePublicURL(r)

	if wantsPowerShell(r) {
		script := renderSetupScript(claudePowerShell, setupScriptData{publicURL: publicURL, accessToken: claudeAuth.AccessToken})

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(script))
		return
	}

	script := renderSetupScript(claudeBash, setupScriptData{publicURL: publicURL, accessToken: claudeAuth.AccessToken})

	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Write([]byte(script))
}

func hashAccountID(id string) string {
	h := sha256.Sum256([]byte(id + "pool-salt-2024"))
	return hex.EncodeToString(h[:])[:12]
}

func formatPlanWithTier(planType, tier string) string {
	switch tier {
	case "default_claude_max_20x":
		return planType + " 20x"
	case "default_claude_max_5x":
		return planType + " 5x"
	default:
		return planType
	}
}

type PoolStats struct {
	TotalAccounts    int               `json:"total_accounts"`
	ActiveAccounts   int               `json:"active_accounts"`
	TotalPoolUsers   int               `json:"total_pool_users"`
	Accounts         []AccountStats    `json:"accounts"`
	AggregateUsage   AggregateStats    `json:"aggregate"`
	CapacityAnalysis *CapacityAnalysis `json:"capacity_analysis,omitempty"`
	Last24hTokens    int64             `json:"last_24h_tokens"`
	DailyCosts       []DailyCostEntry  `json:"daily_costs,omitempty"`
	CyberPolicy      CyberPolicyStats  `json:"cyber_policy"`
	GeneratedAt      time.Time         `json:"generated_at"`
}

// CyberPolicyStats summarizes how often the cyber_policy safety net
// has fired since process start. Operators read this to alert when
// suppressions happen without successful swaps (i.e. the cyber pool
// is depleted) or when synthetic refusals are being emitted.
type CyberPolicyStats struct {
	// Healthy is true when there's been at least one cyber_policy
	// detection AND every detection was paired with either a
	// successful swap or a buffered/4xx retry. False when suppressions
	// fell back to synthetic refusal (no cyber candidate available).
	Healthy bool `json:"healthy"`
	// CyberCandidatesAvailable is the count of live, non-disabled
	// cyber_access accounts in the pool right now. Zero means the
	// next cyber_policy hit will fall back to a synthetic refusal.
	CyberCandidatesAvailable int `json:"cyber_candidates_available"`
	// Counters by action: "suppressed_ws", "suppressed_sse",
	// "suppressed_buffered", "swap_succeeded", "swap_no_candidate",
	// "retry_buffered", "retry_4xx".
	Counters map[string]int64 `json:"counters"`
	// PerAccount["shiv_1"]["suppressed_ws"] = 5 — useful when you
	// want to see which non-cyber account is hitting the policy
	// classifier most often.
	PerAccount map[string]map[string]int64 `json:"per_account,omitempty"`
}

type AccountStats struct {
	ID                        string               `json:"id"` // hashed
	Type                      string               `json:"type"`
	PlanType                  string               `json:"plan_type"`
	Status                    string               `json:"status"` // healthy, degraded, dead
	Penalty                   float64              `json:"penalty"`
	PrimaryWindowUsed         float64              `json:"primary_window_used_pct"`
	SecondaryWindowUsed       float64              `json:"secondary_window_used_pct"`
	PrimaryWindowAvailable    bool                 `json:"primary_window_available"`
	SecondaryWindowAvailable  bool                 `json:"secondary_window_available"`
	PrimaryResetMinutes       int                  `json:"primary_reset_minutes"`
	SecondaryResetMinutes     int                  `json:"secondary_reset_minutes"`
	PrimaryWindowMinutes      int                  `json:"primary_window_minutes"`
	SecondaryWindowMinutes    int                  `json:"secondary_window_minutes"`
	PrimaryPaceRatio          float64              `json:"primary_pace_ratio"`
	SecondaryPaceRatio        float64              `json:"secondary_pace_ratio"`
	AccountAddedAt            string               `json:"account_added_at,omitempty"`
	TotalInputTokens          int64                `json:"total_input_tokens"`
	TotalCachedTokens         int64                `json:"total_cached_tokens"`
	TotalOutputTokens         int64                `json:"total_output_tokens"`
	TotalReasoningTokens      int64                `json:"total_reasoning_tokens"`
	TotalBillableTokens       int64                `json:"total_billable_tokens"`
	CacheHitRate              float64              `json:"cache_hit_rate_pct"`
	CreditsBalance            float64              `json:"credits_balance,omitempty"`
	HasCredits                bool                 `json:"has_credits"`
	Score                     float64              `json:"score"`
	ScoreTooltip              string               `json:"score_tooltip,omitempty"`
	IsPrimary                 bool                 `json:"is_primary"` // highest score for this provider type
	SubscriptionCostMonthly   float64              `json:"subscription_cost_monthly"`
	SubscriptionSpend         float64              `json:"subscription_spend"`
	SubscriptionBillingCycles int                  `json:"subscription_billing_cycles"`
	CostTrackingStartedAt     string               `json:"cost_tracking_started_at,omitempty"`
	SubscriptionLabel         string               `json:"subscription_label"`
	APICostEstimate           float64              `json:"api_cost_estimate"` // all-time
	APICostLast30d            float64              `json:"api_cost_last_30d"` // last 30 days
	ROI                       float64              `json:"roi"`               // all-time API value / subscription spend
	ResetCreditsAvailable     int                  `json:"reset_credits_available"`
	ResetCreditExpirations    []string             `json:"reset_credit_expirations,omitempty"`
	ResetCreditsKnown         bool                 `json:"reset_credits_known"`
	QuotaWindows              []AccountQuotaWindow `json:"quota_windows,omitempty"`
}

type AggregateStats struct {
	TotalInputTokens         int64                          `json:"total_input_tokens"`
	TotalCachedTokens        int64                          `json:"total_cached_tokens"`
	TotalOutputTokens        int64                          `json:"total_output_tokens"`
	TotalReasoningTokens     int64                          `json:"total_reasoning_tokens"`
	TotalBillableTokens      int64                          `json:"total_billable_tokens"`
	AvgPrimaryUsed           float64                        `json:"avg_primary_window_used_pct"`
	AvgSecondaryUsed         float64                        `json:"avg_secondary_window_used_pct"`
	OverallCacheHitRate      float64                        `json:"overall_cache_hit_rate_pct"`
	TotalAPICost             float64                        `json:"total_api_cost"`
	TotalSubscriptionCost    float64                        `json:"total_subscription_cost"`
	TotalSubscriptionMonthly float64                        `json:"total_subscription_monthly"`
	OverallROI               float64                        `json:"overall_roi"`
	Economics                economicsSummary               `json:"economics"`
	CostByProvider           map[string]ProviderCostSummary `json:"cost_by_provider,omitempty"`
}

type CapacityAnalysis struct {
	TotalSamples int64                       `json:"total_samples"`
	Plans        map[string]PlanCapacityInfo `json:"plans"`
	ModelFormula string                      `json:"model_formula"`
}

type PlanCapacityInfo struct {
	SampleCount                int64   `json:"sample_count"`
	Confidence                 string  `json:"confidence"`
	TotalInputTokens           int64   `json:"total_input_tokens"`
	TotalOutputTokens          int64   `json:"total_output_tokens"`
	TotalCachedTokens          int64   `json:"total_cached_tokens"`
	TotalReasoningTokens       int64   `json:"total_reasoning_tokens"`
	OutputMultiplier           float64 `json:"output_multiplier"`
	EstimatedPrimaryCapacity   int64   `json:"estimated_5h_capacity"`
	EstimatedSecondaryCapacity int64   `json:"estimated_7d_capacity"`
}

// quotaPaceRatio compares current quota consumption with an even burn across
// the elapsed portion of a reset window. Values over one will exhaust the
// window early if the current pace holds.
func quotaPaceRatio(usedPercent float64, resetMinutes, windowMinutes int) float64 {
	if usedPercent <= 0 || resetMinutes <= 0 || windowMinutes <= 0 || resetMinutes >= windowMinutes {
		return 0
	}
	elapsed := windowMinutes - resetMinutes
	// Usage is reported in percentage-point increments. Before one point of
	// even-burn budget has elapsed, extrapolating the first non-zero reading is
	// dominated by measurement resolution (for example, 1% in 23 minutes of a
	// seven-day window appears to be 62.6%/day).
	if float64(elapsed) < float64(windowMinutes)/100 {
		return 0
	}
	return usedPercent / (100 * float64(elapsed) / float64(windowMinutes))
}

func (h *proxyHandler) handlePoolStats(w http.ResponseWriter, r *http.Request) {
	accounts := h.pool.allAccounts()

	stats := PoolStats{
		TotalAccounts: len(accounts),
		Accounts:      []AccountStats{},
		GeneratedAt:   time.Now(),
	}

	if h.poolUsers != nil {
		stats.TotalPoolUsers = len(h.poolUsers.List())
	}

	billingInputs := make([]accountBillingInput, 0, len(accounts))

	var totalInput, totalCached, totalOutput, totalReasoning, totalBillable int64
	var primarySum, secondarySum float64
	var primaryCount, secondaryCount int
	activeCount := 0

	for _, acc := range accounts {
		acc.mu.Lock()

		status := "healthy"
		if acc.Dead || acc.Disabled {
			status = "dead"
		} else if acc.NeedsVerification {
			status = "verify"
		} else if accountCoolingDownLocked(acc, stats.GeneratedAt) || accountUsageExhaustedLocked(acc) {
			status = "cooldown"
		} else if acc.Penalty > 2.0 {
			status = "degraded"
		}
		if status == "healthy" || status == "degraded" {
			activeCount++
		}

		accType := string(acc.Type)

		cacheHitRate := float64(0)
		if acc.Totals.TotalInputTokens > 0 {
			cacheHitRate = float64(acc.Totals.TotalCachedTokens) / float64(acc.Totals.TotalInputTokens) * 100
		}

		primaryReset := 0
		secondaryReset := 0
		if !acc.Usage.PrimaryResetAt.IsZero() {
			primaryReset = int(time.Until(acc.Usage.PrimaryResetAt).Minutes())
			if primaryReset < 0 {
				primaryReset = 0
			}
		}
		if !acc.Usage.SecondaryResetAt.IsZero() {
			secondaryReset = int(time.Until(acc.Usage.SecondaryResetAt).Minutes())
			if secondaryReset < 0 {
				secondaryReset = 0
			}
		}

		primaryUsed := accountPrimaryUsageLocked(acc) * 100
		secondaryUsed := accountSecondaryUsageLocked(acc) * 100

		breakdown := scoreBreakdown{}
		score := float64(0)
		if !acc.Dead && !acc.Disabled {
			breakdown = scoreAccountBreakdownLocked(acc, stats.GeneratedAt)
			score = breakdown.Score
		}
		scoreTooltip := scoreTooltipFromBreakdownLocked(acc, stats.GeneratedAt, breakdown)

		as := AccountStats{
			ID:                       hashAccountID(acc.ID),
			Type:                     accType,
			PlanType:                 formatPlanWithTier(acc.PlanType, acc.RateLimitTier),
			Status:                   status,
			Penalty:                  acc.Penalty,
			PrimaryWindowUsed:        primaryUsed,
			SecondaryWindowUsed:      secondaryUsed,
			PrimaryWindowAvailable:   usagePrimaryWindowAvailable(acc.Usage),
			SecondaryWindowAvailable: usageSecondaryWindowAvailable(acc.Usage),
			PrimaryResetMinutes:      primaryReset,
			SecondaryResetMinutes:    secondaryReset,
			PrimaryWindowMinutes:     acc.Usage.PrimaryWindowMinutes,
			SecondaryWindowMinutes:   acc.Usage.SecondaryWindowMinutes,
			PrimaryPaceRatio:         quotaPaceRatio(primaryUsed, primaryReset, acc.Usage.PrimaryWindowMinutes),
			SecondaryPaceRatio:       quotaPaceRatio(secondaryUsed, secondaryReset, acc.Usage.SecondaryWindowMinutes),
			AccountAddedAt:           acc.AddedAt.UTC().Format(time.RFC3339),
			TotalInputTokens:         acc.Totals.TotalInputTokens,
			TotalCachedTokens:        acc.Totals.TotalCachedTokens,
			TotalOutputTokens:        acc.Totals.TotalOutputTokens,
			TotalReasoningTokens:     acc.Totals.TotalReasoningTokens,
			TotalBillableTokens:      acc.Totals.TotalBillableTokens,
			CacheHitRate:             cacheHitRate,
			HasCredits:               acc.Usage.HasCredits,
			CreditsBalance:           acc.Usage.CreditsBalance,
			Score:                    score,
			ScoreTooltip:             scoreTooltip,
			ResetCreditsAvailable:    acc.ResetCreditsAvailable,
			ResetCreditsKnown:        !acc.ResetCreditsRetrievedAt.IsZero(),
		}
		for _, credit := range acc.RateLimitResetCredits {
			as.ResetCreditExpirations = append(as.ResetCreditExpirations, credit.ExpiresAt.UTC().Format(time.RFC3339Nano))
		}
		if acc.Type == AccountTypeAntigravity {
			as.QuotaWindows = antigravityQuotaWindows(&h.pool.antigravityModels, acc.ID, stats.GeneratedAt)
		}

		totalInput += acc.Totals.TotalInputTokens
		totalCached += acc.Totals.TotalCachedTokens
		totalOutput += acc.Totals.TotalOutputTokens
		totalReasoning += acc.Totals.TotalReasoningTokens
		totalBillable += acc.Totals.TotalBillableTokens
		if usagePrimaryWindowAvailable(acc.Usage) {
			primarySum += accountPrimaryUsageLocked(acc)
			primaryCount++
		}
		if usageSecondaryWindowAvailable(acc.Usage) {
			secondarySum += accountSecondaryUsageLocked(acc)
			secondaryCount++
		}

		billingInputs = append(billingInputs, accountBillingInput{
			accountID: acc.ID, accountType: acc.Type, plan: billingPlan(acc.PlanType, acc.RateLimitTier), addedAt: acc.AddedAt,
		})
		acc.mu.Unlock()
		stats.Accounts = append(stats.Accounts, as)
	}

	highestScore := make(map[string]float64)
	highestIdx := make(map[string]int)
	for i, as := range stats.Accounts {
		if (as.Status == "healthy" || as.Status == "degraded") && as.Score > highestScore[as.Type] {
			highestScore[as.Type] = as.Score
			highestIdx[as.Type] = i
		}
	}
	for _, idx := range highestIdx {
		stats.Accounts[idx].IsPrimary = true
	}

	stats.ActiveAccounts = activeCount

	overallCacheRate := float64(0)
	if totalInput > 0 {
		overallCacheRate = float64(totalCached) / float64(totalInput) * 100
	}

	avgPrimary := float64(0)
	avgSecondary := float64(0)
	if primaryCount > 0 {
		avgPrimary = (primarySum / float64(primaryCount)) * 100
	}
	if secondaryCount > 0 {
		avgSecondary = (secondarySum / float64(secondaryCount)) * 100
	}

	stats.AggregateUsage = AggregateStats{
		TotalInputTokens:     totalInput,
		TotalCachedTokens:    totalCached,
		TotalOutputTokens:    totalOutput,
		TotalReasoningTokens: totalReasoning,
		TotalBillableTokens:  totalBillable,
		AvgPrimaryUsed:       avgPrimary,
		AvgSecondaryUsed:     avgSecondary,
		OverallCacheHitRate:  overallCacheRate,
	}

	if h.store != nil {
		caps, err := h.store.loadAllPlanCapacity()
		if err == nil && len(caps) > 0 {
			analysis := &CapacityAnalysis{
				Plans:        make(map[string]PlanCapacityInfo),
				ModelFormula: "effective = input + (cached × 0.1) + (output × mult) + (reasoning × mult)",
			}
			for planType, cap := range caps {
				analysis.TotalSamples += cap.SampleCount
				confidence := "low"
				if cap.SampleCount >= 20 {
					confidence = "high"
				} else if cap.SampleCount >= 5 {
					confidence = "medium"
				}
				mult := cap.OutputMultiplier
				if mult == 0 {
					mult = 4.0
				}
				var estPrimary, estSecondary int64
				if cap.EffectivePerPrimaryPct > 0 {
					estPrimary = int64(cap.EffectivePerPrimaryPct)
				}
				if cap.EffectivePerSecondaryPct > 0 {
					estSecondary = int64(cap.EffectivePerSecondaryPct)
				}
				analysis.Plans[planType] = PlanCapacityInfo{
					SampleCount:                cap.SampleCount,
					Confidence:                 confidence,
					TotalInputTokens:           cap.TotalInputTokens,
					TotalOutputTokens:          cap.TotalOutputTokens,
					TotalCachedTokens:          cap.TotalCachedTokens,
					TotalReasoningTokens:       cap.TotalReasoningTokens,
					OutputMultiplier:           mult,
					EstimatedPrimaryCapacity:   estPrimary,
					EstimatedSecondaryCapacity: estSecondary,
				}
			}
			stats.CapacityAnalysis = analysis
		}
	}

	if h.store != nil {
		if hourly, err := h.store.getGlobalHourlyUsage(24); err == nil {
			for _, hu := range hourly {
				throughput := hu.InputTokens + hu.OutputTokens
				if hu.AccountType == string(AccountTypeClaude) {
					throughput += hu.CachedTokens
				}
				stats.Last24hTokens += throughput
			}
		}
	}

	if h.analyticsStore != nil {
		allTimeCostStats, _ := h.analyticsStore.getAllTimeAccountCostStats()
		last30dCosts, _ := h.analyticsStore.getCostByAccount(30)

		for i := range stats.Accounts {
			as := &stats.Accounts[i]
			billing := billingInputs[i]
			realID := billing.accountID

			subCost, subLabel := getSubscriptionCost(billing.accountType, billing.plan)
			costStats := allTimeCostStats[realID]
			as.SubscriptionCostMonthly = subCost
			as.SubscriptionLabel = subLabel
			as.APICostEstimate = costStats.CostUSD
			as.APICostLast30d = last30dCosts[realID]
			spendStart := billing.addedAt
			if spendStart.IsZero() {
				// Legacy in-memory fixtures can lack an admission timestamp. Keep
				// historical cost data as their compatibility fallback only.
				spendStart = costStats.FirstSeen
			}
			if spendStart.IsZero() {
				// A paid account with no recorded API use still consumed its current
				// subscription billing cycle.
				spendStart = stats.GeneratedAt
			}
			as.CostTrackingStartedAt = spendStart.UTC().Format(time.RFC3339)
			as.SubscriptionSpend, as.SubscriptionBillingCycles = estimateSubscriptionSpend(subCost, spendStart, stats.GeneratedAt)
			if as.SubscriptionSpend > 0 {
				as.ROI = as.APICostEstimate / as.SubscriptionSpend
			}
		}

		providerCosts := make(map[string]ProviderCostSummary)
		for i := range stats.Accounts {
			as := &stats.Accounts[i]
			pcs := providerCosts[as.Type]
			pcs.APICost += as.APICostEstimate
			pcs.SubscriptionCost += as.SubscriptionSpend
			pcs.MonthlySubscriptionCost += as.SubscriptionCostMonthly
			pcs.AccountCount++
			providerCosts[as.Type] = pcs
		}
		for k, pcs := range providerCosts {
			if pcs.SubscriptionCost > 0 {
				pcs.ROI = pcs.APICost / pcs.SubscriptionCost
			}
			providerCosts[k] = pcs
		}
		stats.AggregateUsage.CostByProvider = providerCosts

		// Pool-level ROI covers the same current-account set on both sides.
		// Historical API value from removed accounts cannot be compared with the
		// subscription spend of only the accounts still in the pool.
		var totalAPICost, totalSubCost, totalSubMonthly float64
		for _, pcs := range providerCosts {
			totalAPICost += pcs.APICost
			totalSubCost += pcs.SubscriptionCost
			totalSubMonthly += pcs.MonthlySubscriptionCost
		}
		stats.AggregateUsage.TotalAPICost = totalAPICost
		stats.AggregateUsage.TotalSubscriptionCost = totalSubCost
		stats.AggregateUsage.TotalSubscriptionMonthly = totalSubMonthly
		if totalSubCost > 0 {
			stats.AggregateUsage.OverallROI = totalAPICost / totalSubCost
		}

		// Headline economics and the signal chart use the same population and
		// billing history; per-account legacy estimates above are not totals.
		if err := h.analyticsStore.syncSubscriptionRates(accounts, stats.GeneratedAt); err != nil {
			log.Printf("economics: subscription sync: %v", err)
		} else if _, economics, err := h.analyticsStore.economics(stats.GeneratedAt); err != nil {
			log.Printf("economics: compute: %v", err)
		} else {
			stats.AggregateUsage.Economics = economics
			stats.AggregateUsage.TotalAPICost = economics.APIValue
			stats.AggregateUsage.TotalSubscriptionCost = economics.SubscriptionSpend
			stats.AggregateUsage.TotalSubscriptionMonthly = economics.CurrentMonthly
			stats.AggregateUsage.OverallROI = 0
			if economics.SubscriptionSpend > 0 && economics.UnknownAccounts == 0 && economics.UncoveredValue == 0 {
				stats.AggregateUsage.OverallROI = economics.APIValue / economics.SubscriptionSpend
			}
		}

		if dailyCosts, err := h.analyticsStore.getDailyCosts(30); err == nil {
			stats.DailyCosts = dailyCosts
		}
	}

	stats.CyberPolicy = h.computeCyberPolicyStats(accounts)
	if operatorAccessFromRequest(r) != nil {
		safe := make(map[string]map[string]int64, len(stats.CyberPolicy.PerAccount))
		for id, counters := range stats.CyberPolicy.PerAccount {
			safe[hashAccountID(id)] = counters
		}
		stats.CyberPolicy.PerAccount = safe
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// computeCyberPolicyStats summarises the metrics counters for the
// pool-stats UI/API. Healthy means: either no suppressions fired yet,
// or every suppression event was paired with a successful swap or a
// buffered/4xx retry — i.e. no synthetic-refusal fallbacks AND there's
// still a cyber candidate available for the next hit.
func (h *proxyHandler) computeCyberPolicyStats(accounts []*Account) CyberPolicyStats {
	out := CyberPolicyStats{
		Counters:   map[string]int64{},
		PerAccount: map[string]map[string]int64{},
	}

	now := time.Now()
	for _, a := range accounts {
		a.mu.Lock()
		if a.CyberAccess && !a.Dead && !a.Disabled &&
			(a.ExpiresAt.IsZero() || a.ExpiresAt.After(now) || h.cfg.disableRefresh) {
			out.CyberCandidatesAvailable++
		}
		a.mu.Unlock()
	}

	if h.metrics == nil {
		out.Healthy = out.CyberCandidatesAvailable > 0
		return out
	}

	snap := h.metrics.cyberPolicySnapshot()
	for k, v := range snap {
		out.Counters[k.action] += v
		if k.account != "" {
			perAcc, ok := out.PerAccount[k.account]
			if !ok {
				perAcc = map[string]int64{}
				out.PerAccount[k.account] = perAcc
			}
			perAcc[k.action] += v
		}
	}

	suppressions := out.Counters["suppressed_ws"] + out.Counters["suppressed_sse"] + out.Counters["suppressed_buffered"]
	resolutions := out.Counters["swap_succeeded"] + out.Counters["retry_buffered"] + out.Counters["retry_4xx"]
	noCandidate := out.Counters["swap_no_candidate"]

	switch {
	case suppressions == 0:
		out.Healthy = out.CyberCandidatesAvailable > 0
	case noCandidate > 0 || resolutions < suppressions:
		out.Healthy = false
	default:
		out.Healthy = out.CyberCandidatesAvailable > 0
	}
	return out
}

func accountPlanForSubscription(planType string) string {
	pt := strings.ToLower(strings.TrimSpace(planType))
	switch {
	case strings.Contains(pt, "20x"):
		return "max_20x"
	case strings.Contains(pt, "5x"):
		return "max_5x"
	case strings.Contains(pt, "team"):
		return "team"
	case strings.Contains(pt, "prolite"):
		return "prolite"
	case strings.Contains(pt, "pro"):
		return "pro"
	case strings.Contains(pt, "plus"):
		return "plus"
	default:
		return pt
	}
}

// handleWhoami returns the current user's ID based on their JWT, Claude pool token, or hashed IP.
func (h *proxyHandler) handleWhoami(w http.ResponseWriter, r *http.Request) {
	var userID string
	var userType string
	authHeader := r.Header.Get("Authorization")
	secret := h.cfg.poolJWTSecret()
	originID := hashRequestOrigin(r, h.originHashSalt())

	// Check for Claude pool tokens first (sk-ant-oat01-pool-* or legacy sk-ant-api-pool-*)
	if secret != "" {
		if isClaudePool, uid := isClaudePoolToken(secret, authHeader); isClaudePool {
			userID = uid
			userType = "pool_user"
		}
	}

	// Check for JWT-based pool tokens (Codex, Gemini)
	if userID == "" && secret != "" {
		if isPoolUser, uid, _ := isPoolUserToken(secret, authHeader); isPoolUser {
			userID = uid
			userType = "pool_user"
		}
	}

	// Check for Gemini OAuth pool tokens (ya29.pool-*)
	if userID == "" && secret != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if isPoolToken, uid := isGeminiOAuthPoolToken(secret, token); isPoolToken {
			userID = uid
			userType = "pool_user"
		}
	}

	if userID == "" {
		userID = strings.TrimPrefix(originID, "ip_")
		userType = "anonymous"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"user_id":   userID,
		"origin_id": originID,
		"type":      userType,
	})
}

// PoolUserStats represents a user's usage for the leaderboard.
type PoolUserStats struct {
	UserID              string    `json:"user_id"`
	TotalBillableTokens int64     `json:"total_billable_tokens"`
	TotalInputTokens    int64     `json:"total_input_tokens"`
	TotalOutputTokens   int64     `json:"total_output_tokens"`
	RequestCount        int64     `json:"request_count"`
	FirstSeen           time.Time `json:"first_seen"`
	LastSeen            time.Time `json:"last_seen"`
}

type PoolOriginStats struct {
	OriginID            string    `json:"origin_id"`
	TotalBillableTokens int64     `json:"total_billable_tokens"`
	TotalInputTokens    int64     `json:"total_input_tokens"`
	TotalOutputTokens   int64     `json:"total_output_tokens"`
	RequestCount        int64     `json:"request_count"`
	FirstSeen           time.Time `json:"first_seen"`
	LastSeen            time.Time `json:"last_seen"`
}

type AdminOriginStats struct {
	OriginID            string    `json:"origin_id"`
	RawIP               string    `json:"raw_ip,omitempty"`
	LastUserID          string    `json:"last_user_id,omitempty"`
	LastUserAgent       string    `json:"last_user_agent,omitempty"`
	LastPath            string    `json:"last_path,omitempty"`
	TotalBillableTokens int64     `json:"total_billable_tokens"`
	TotalInputTokens    int64     `json:"total_input_tokens"`
	TotalOutputTokens   int64     `json:"total_output_tokens"`
	RequestCount        int64     `json:"request_count"`
	FirstSeen           time.Time `json:"first_seen"`
	LastSeen            time.Time `json:"last_seen"`
}

// handlePoolUsers returns the public leaderboard of all users' usage.
func (h *proxyHandler) handlePoolUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.getAllUserUsage()
	if err != nil {
		http.Error(w, "failed to fetch user usage", http.StatusInternalServerError)
		return
	}

	// Convert to API format
	stats := make([]PoolUserStats, len(users))
	for i, u := range users {
		stats[i] = PoolUserStats{
			UserID:              u.UserID,
			TotalBillableTokens: u.TotalBillableTokens,
			TotalInputTokens:    u.TotalInputTokens,
			TotalOutputTokens:   u.TotalOutputTokens,
			RequestCount:        u.RequestCount,
			FirstSeen:           u.FirstSeen,
			LastSeen:            u.LastSeen,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"users":       stats,
		"total_users": len(stats),
	})
}

// handlePoolOrigins returns the public leaderboard of hashed incoming origin usage.
func (h *proxyHandler) handlePoolOrigins(w http.ResponseWriter, r *http.Request) {
	origins, err := h.store.getAllOriginUsage()
	if err != nil {
		http.Error(w, "failed to fetch origin usage", http.StatusInternalServerError)
		return
	}

	stats := make([]PoolOriginStats, len(origins))
	for i, origin := range origins {
		stats[i] = PoolOriginStats{
			OriginID:            origin.OriginID,
			TotalBillableTokens: origin.TotalBillableTokens,
			TotalInputTokens:    origin.TotalInputTokens,
			TotalOutputTokens:   origin.TotalOutputTokens,
			RequestCount:        origin.RequestCount,
			FirstSeen:           origin.FirstSeen,
			LastSeen:            origin.LastSeen,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"origins":       stats,
		"total_origins": len(stats),
	})
}

// handleAdminOrigins returns hashed origin usage joined with admin-only raw attribution metadata.
func (h *proxyHandler) handleAdminOrigins(w http.ResponseWriter, r *http.Request) {
	originFilter := strings.TrimSpace(r.URL.Query().Get("origin_id"))

	origins, err := h.store.getAllOriginUsage()
	if err != nil {
		http.Error(w, "failed to fetch origin usage", http.StatusInternalServerError)
		return
	}
	metas, err := h.store.getAllOriginMetadata()
	if err != nil {
		http.Error(w, "failed to fetch origin metadata", http.StatusInternalServerError)
		return
	}

	metaByID := make(map[string]OriginMetadata, len(metas))
	for _, meta := range metas {
		metaByID[meta.OriginID] = meta
	}

	stats := make([]AdminOriginStats, 0, len(origins))
	for _, origin := range origins {
		if originFilter != "" && origin.OriginID != originFilter {
			continue
		}
		meta := metaByID[origin.OriginID]
		firstSeen := origin.FirstSeen
		if firstSeen.IsZero() {
			firstSeen = meta.FirstSeen
		}
		lastSeen := origin.LastSeen
		if lastSeen.IsZero() {
			lastSeen = meta.LastSeen
		}
		stats = append(stats, AdminOriginStats{
			OriginID:            origin.OriginID,
			RawIP:               meta.RawIP,
			LastUserID:          meta.LastUserID,
			LastUserAgent:       meta.LastUserAgent,
			LastPath:            meta.LastPath,
			TotalBillableTokens: origin.TotalBillableTokens,
			TotalInputTokens:    origin.TotalInputTokens,
			TotalOutputTokens:   origin.TotalOutputTokens,
			RequestCount:        origin.RequestCount,
			FirstSeen:           firstSeen,
			LastSeen:            lastSeen,
		})
	}

	if originFilter != "" && len(stats) == 0 {
		if meta, ok := metaByID[originFilter]; ok {
			stats = append(stats, AdminOriginStats{
				OriginID:      meta.OriginID,
				RawIP:         meta.RawIP,
				LastUserID:    meta.LastUserID,
				LastUserAgent: meta.LastUserAgent,
				LastPath:      meta.LastPath,
				FirstSeen:     meta.FirstSeen,
				LastSeen:      meta.LastSeen,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"origins":       stats,
		"total_origins": len(stats),
	})
}

// handleDailyBreakdown returns combined daily token usage from all accounts.
func (h *proxyHandler) handleDailyBreakdown(w http.ResponseWriter, r *http.Request) {
	type DayUsage struct {
		Date     string             `json:"date"`
		Surfaces map[string]float64 `json:"surfaces"`
		Total    float64            `json:"total"`
	}

	// Aggregate daily data from all accounts
	combined := make(map[string]*DayUsage) // date -> usage

	accounts := h.pool.allAccounts()
	for _, acc := range accounts {
		if acc.Type != AccountTypeCodex || acc.Dead {
			continue
		}

		data, err := h.fetchDailyBreakdownData(acc)
		if err != nil {
			continue
		}

		for _, day := range data {
			if combined[day.Date] == nil {
				combined[day.Date] = &DayUsage{
					Date:     day.Date,
					Surfaces: make(map[string]float64),
				}
			}
			for surface, val := range day.Surfaces {
				combined[day.Date].Surfaces[surface] += val
				combined[day.Date].Total += val
			}
		}
	}

	// Convert to sorted slice
	var result []DayUsage
	for _, v := range combined {
		result = append(result, *v)
	}
	// Sort by date
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[i].Date > result[j].Date {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"days":          result,
		"account_count": len(accounts),
	})
}

// handleUserDaily returns a user's daily usage over the last N days.
func (h *proxyHandler) handleUserDaily(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from path: /api/pool/users/:id/daily
	path := r.URL.Path
	path = strings.TrimPrefix(path, "/api/pool/users/")
	path = strings.TrimSuffix(path, "/daily")
	userID := path

	if userID == "" {
		http.Error(w, "user ID required", http.StatusBadRequest)
		return
	}

	// Get days parameter (default 30)
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n > 0 && n <= 90 {
			days = n
		}
	}

	daily, err := h.store.getUserDailyUsage(userID, days)
	if err != nil {
		http.Error(w, "failed to fetch daily usage", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"user_id": userID,
		"days":    days,
		"daily":   daily,
	})
}

// handleUserHourly returns a user's hourly usage over the last N hours.
func (h *proxyHandler) handleUserHourly(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from path: /api/pool/users/:id/hourly
	path := r.URL.Path
	path = strings.TrimPrefix(path, "/api/pool/users/")
	path = strings.TrimSuffix(path, "/hourly")
	userID := path

	if userID == "" {
		http.Error(w, "user ID required", http.StatusBadRequest)
		return
	}

	hours := 24
	if h := r.URL.Query().Get("hours"); h != "" {
		if n, err := strconv.Atoi(h); err == nil && n > 0 && n <= 168 {
			hours = n
		}
	}

	hourly, err := h.store.getUserHourlyUsage(userID, hours)
	if err != nil {
		http.Error(w, "failed to fetch hourly usage", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"user_id": userID,
		"hours":   hours,
		"hourly":  hourly,
	})
}

// handleGlobalHourly returns global hourly usage (all users combined) over the last N hours.
func (h *proxyHandler) handleGlobalHourly(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if hParam := r.URL.Query().Get("hours"); hParam != "" {
		if n, err := strconv.Atoi(hParam); err == nil && n > 0 && n <= 168 {
			hours = n
		}
	}

	hourly, err := h.store.getGlobalHourlyUsage(hours)
	if err != nil {
		http.Error(w, "failed to fetch hourly usage", http.StatusInternalServerError)
		return
	}

	// Calculate aggregate totals for the period
	var totalBillable, totalInput, totalOutput, totalCached, totalReasoning, totalRequests int64
	for _, h := range hourly {
		totalBillable += h.BillableTokens
		totalInput += h.InputTokens
		totalOutput += h.OutputTokens
		totalCached += h.CachedTokens
		totalReasoning += h.ReasoningTokens
		totalRequests += h.RequestCount
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"hours":  hours,
		"hourly": hourly,
		"totals": map[string]int64{
			"billable_tokens":  totalBillable,
			"input_tokens":     totalInput,
			"output_tokens":    totalOutput,
			"cached_tokens":    totalCached,
			"reasoning_tokens": totalReasoning,
			"request_count":    totalRequests,
		},
	})
}
