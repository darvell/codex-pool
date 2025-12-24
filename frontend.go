package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//go:embed templates/friend_landing.html templates/local_landing.html templates/og-image.png templates/og-image-transparent.png
var friendContent embed.FS

func (h *proxyHandler) serveFriendLanding(w http.ResponseWriter, r *http.Request) {
	var templateFile string
	var templateData map[string]string

	if h.cfg.friendCode == "" {
		// Local/personal mode - no friend code required
		templateFile = "templates/local_landing.html"
		templateData = map[string]string{
			"BaseURL": getPublicURL(),
		}
		if templateData["BaseURL"] == "" {
			templateData["BaseURL"] = "http://localhost:8989"
		}
	} else {
		// Friend mode - requires friend code
		templateFile = "templates/friend_landing.html"
		templateData = map[string]string{
			"FriendName": getFriendName(),
			"Tagline":    getFriendTagline(),
		}
	}

	data, err := friendContent.ReadFile(templateFile)
	if err != nil {
		http.Error(w, "internal error: template missing", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.New("landing").Parse(string(data))
	if err != nil {
		http.Error(w, "internal error: template parse failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	tmpl.Execute(w, templateData)
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
	data, err := friendContent.ReadFile("templates/og-image-transparent.png")
	if err != nil {
		http.Error(w, "image not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

func (h *proxyHandler) handleFriendClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.cfg.friendCode == "" {
		http.Error(w, "feature disabled", http.StatusForbidden)
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

	if req.FriendCode != h.cfg.friendCode {
		respondJSONError(w, http.StatusForbidden, "Invalid Friend Code")
		return
	}

	// Ensure pool users system is ready
	if h.poolUsers == nil {
		// If using friend code, we expect pool users to be usable if JWT secret is set.
		if getPoolJWTSecret() == "" {
			respondJSONError(w, http.StatusServiceUnavailable, "System error: Pool user system not configured (missing JWT secret).")
			return
		}
		// Try to initialize on demand? (Not ideal, handled in main.go)
		respondJSONError(w, http.StatusServiceUnavailable, "System error: User storage not initialized.")
		return
	}

	// Determine email - use guest@<host> if none provided
	email := req.Email
	if email == "" {
		guestDomain := "pool.local"
		if pubURL := getPublicURL(); pubURL != "" {
			if u, err := url.Parse(pubURL); err == nil && u.Host != "" {
				host := u.Hostname()
				// Only use if not an IP address
				if net.ParseIP(host) == nil {
					guestDomain = host
				}
			}
		}
		email = "guest@" + guestDomain
	}

	// Check for existing user with this email
	var newUser *PoolUser
	if existing := h.poolUsers.GetByEmail(email); existing != nil {
		newUser = existing
	} else {
		// Create new user
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

	// Generate Auth JSON
	secret := getPoolJWTSecret()
	authData, err := generateCodexAuth(secret, newUser)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to generate credentials.")
		return
	}
	authJSONBytes, _ := json.MarshalIndent(authData, "", "  ")

	// Generate Gemini Auth JSON
	geminiAuthData, err := generateGeminiAuth(secret, newUser)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to generate gemini credentials.")
		return
	}
	geminiJSONBytes, _ := json.MarshalIndent(geminiAuthData, "", "  ")

	// Generate Claude Auth - returns JWT for use as API key
	claudeAuthData, err := generateClaudeAuth(secret, newUser)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to generate claude credentials.")
		return
	}

	publicURL := h.getEffectivePublicURL(r)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"public_url":        publicURL,
		"download_token":    newUser.Token,
		"auth_json":         string(authJSONBytes),
		"gemini_auth_json":  string(geminiJSONBytes),
		"claude_api_key":    claudeAuthData.AccessToken, // JWT token to use as API key
	})
}

func respondJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (h *proxyHandler) getEffectivePublicURL(r *http.Request) string {
	if u := getPublicURL(); u != "" {
		return u
	}
	// Infer from request
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}

func (h *proxyHandler) serveCodexSetupScript(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/setup/codex/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	publicURL := h.getEffectivePublicURL(r)
	
	script := fmt.Sprintf(`#!/bin/bash
set -e
TOKEN="%s"
BASE_URL="%s"
AUTH_DIR="$HOME/.codex"
CONFIG_FILE="$AUTH_DIR/config.toml"
AUTH_FILE="$AUTH_DIR/auth.json"

echo "Initializing Codex Pool setup..."
mkdir -p "$AUTH_DIR"

echo "1. Fetching credentials..."
curl -sL "$BASE_URL/config/codex/$TOKEN" -o "$AUTH_FILE"
chmod 600 "$AUTH_FILE"

echo "2. Updating configuration..."
if [ ! -f "$CONFIG_FILE" ]; then
    touch "$CONFIG_FILE"
fi

# Check if config already exists to avoid duplication
if ! grep -q "codex-pool" "$CONFIG_FILE"; then
    # Create temp file with pool config at TOP, then append existing config
    TEMP_FILE=$(mktemp)
    cat <<EOF > "$TEMP_FILE"
# Codex Pool Proxy Config
model_provider = "codex-pool"
chatgpt_base_url = "$BASE_URL"

EOF
    # Append existing config
    cat "$CONFIG_FILE" >> "$TEMP_FILE"

    # Add model_providers section at the end (sections go after top-level keys)
    cat <<EOF >> "$TEMP_FILE"

[model_providers.codex-pool]
name = "OpenAI via codex-pool proxy"
base_url = "$BASE_URL/v1"
wire_api = "responses"
requires_openai_auth = true
EOF

    mv "$TEMP_FILE" "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    echo "Configuration updated in $CONFIG_FILE"
else
    echo "Configuration already present in $CONFIG_FILE. Skipping."
fi

echo "Setup complete! You are ready to use the pool."
`, token, publicURL)

	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Write([]byte(script))
}

func (h *proxyHandler) serveGeminiSetupScript(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/setup/gemini/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	publicURL := h.getEffectivePublicURL(r)

	script := fmt.Sprintf(`#!/bin/bash
set -e
TOKEN="%s"
BASE_URL="%s"
AUTH_DIR="$HOME/.gemini"
SETTINGS_FILE="$AUTH_DIR/settings.json"
CREDS_FILE="$AUTH_DIR/oauth_creds.json"

echo "Initializing Gemini Pool setup..."
mkdir -p "$AUTH_DIR"

echo "1. Fetching credentials..."
curl -sL "$BASE_URL/config/gemini/$TOKEN" -o "$CREDS_FILE"
chmod 600 "$CREDS_FILE"

echo "2. Updating configuration..."
# Create settings.json if it doesn't exist or is empty
if [ ! -s "$SETTINGS_FILE" ]; then
    echo "{\"codeAssistEndpoint\": \"$BASE_URL\"}" > "$SETTINGS_FILE"
    echo "Created $SETTINGS_FILE"
else
    # Simple check if endpoint is already set
    if grep -q "codeAssistEndpoint" "$SETTINGS_FILE"; then
        echo "Settings file already has an endpoint configuration. Please verify $SETTINGS_FILE manually."
    else
        echo "Appending configuration (Note: JSON parsing in bash is fragile, manual verification recommended)..."
        # Naive JSON insertion (assuming ends with })
        # Actually, safely replacing the whole file is risky if user has other settings.
        # Let's just warn for now or do a simple overwrite if they agree, but for 'auto' we want low friction.
        # We'll stick to a safe overwrite if it's just a 1-key file, or warn.
        echo "Warning: $SETTINGS_FILE exists. Please manually ensure 'codeAssistEndpoint' is set to '$BASE_URL'."
    fi
fi

echo "Setup complete!"
`, token, publicURL)

	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Write([]byte(script))
}

func (h *proxyHandler) serveClaudeSetupScript(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/setup/claude/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}

	// Validate token and get user
	if h.poolUsers == nil {
		http.Error(w, "pool users not configured", http.StatusServiceUnavailable)
		return
	}
	user := h.poolUsers.GetByToken(token)
	if user == nil {
		http.Error(w, "invalid token", http.StatusNotFound)
		return
	}
	if user.Disabled {
		http.Error(w, "user disabled", http.StatusForbidden)
		return
	}

	// Generate Claude API key (JWT)
	secret := getPoolJWTSecret()
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

	script := fmt.Sprintf(`#!/bin/bash
set -e
BASE_URL="%s"
API_KEY="%s"

echo "Configuring Claude Code for pool access..."
echo ""

# Add environment variables to shell profiles
PROFILE_FILES=("$HOME/.bashrc" "$HOME/.zshrc")

for PROFILE in "${PROFILE_FILES[@]}"; do
    if [ -f "$PROFILE" ]; then
        # Remove old Claude pool config if present
        sed -i.bak '/# Claude Code Pool/,+2d' "$PROFILE" 2>/dev/null || true

        # Add new config
        echo "" >> "$PROFILE"
        echo "# Claude Code Pool" >> "$PROFILE"
        echo "export ANTHROPIC_BASE_URL=\"$BASE_URL\"" >> "$PROFILE"
        echo "export ANTHROPIC_API_KEY=\"$API_KEY\"" >> "$PROFILE"
        echo "✓ Configured $PROFILE"
    fi
done

echo ""
echo "Setup complete!"
echo ""
echo "To use immediately in this terminal, run:"
echo "  source ~/.bashrc  # or ~/.zshrc"
echo ""
echo "Then start Claude Code with: claude"
`, publicURL, claudeAuth.AccessToken)

	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Write([]byte(script))
}

// hashAccountID creates a short anonymized hash of an account identifier
func hashAccountID(id string) string {
	h := sha256.Sum256([]byte(id + "pool-salt-2024"))
	return hex.EncodeToString(h[:])[:12]
}

// PoolStats represents anonymized pool statistics
type PoolStats struct {
	TotalAccounts    int              `json:"total_accounts"`
	ActiveAccounts   int              `json:"active_accounts"`
	TotalPoolUsers   int              `json:"total_pool_users"`
	Accounts         []AccountStats   `json:"accounts"`
	AggregateUsage   AggregateStats   `json:"aggregate"`
	CapacityAnalysis *CapacityAnalysis `json:"capacity_analysis,omitempty"`
	GeneratedAt      time.Time        `json:"generated_at"`
}

type AccountStats struct {
	ID                    string  `json:"id"` // hashed
	Type                  string  `json:"type"`
	PlanType              string  `json:"plan_type"`
	Status                string  `json:"status"` // healthy, degraded, dead
	PrimaryWindowUsed     float64 `json:"primary_window_used_pct"`
	SecondaryWindowUsed   float64 `json:"secondary_window_used_pct"`
	PrimaryResetMinutes   int     `json:"primary_reset_minutes"`
	SecondaryResetMinutes int     `json:"secondary_reset_minutes"`
	TotalInputTokens      int64   `json:"total_input_tokens"`
	TotalCachedTokens     int64   `json:"total_cached_tokens"`
	TotalOutputTokens     int64   `json:"total_output_tokens"`
	TotalReasoningTokens  int64   `json:"total_reasoning_tokens"`
	TotalBillableTokens   int64   `json:"total_billable_tokens"`
	CacheHitRate          float64 `json:"cache_hit_rate_pct"`
	CreditsBalance        float64 `json:"credits_balance,omitempty"`
	HasCredits            bool    `json:"has_credits"`
}

type AggregateStats struct {
	TotalInputTokens    int64   `json:"total_input_tokens"`
	TotalCachedTokens   int64   `json:"total_cached_tokens"`
	TotalOutputTokens   int64   `json:"total_output_tokens"`
	TotalReasoningTokens int64  `json:"total_reasoning_tokens"`
	TotalBillableTokens int64   `json:"total_billable_tokens"`
	AvgPrimaryUsed      float64 `json:"avg_primary_window_used_pct"`
	AvgSecondaryUsed    float64 `json:"avg_secondary_window_used_pct"`
	OverallCacheHitRate float64 `json:"overall_cache_hit_rate_pct"`
}

// CapacityAnalysis contains token capacity estimation data for the stats API.
type CapacityAnalysis struct {
	TotalSamples    int64                       `json:"total_samples"`
	Plans           map[string]PlanCapacityInfo `json:"plans"`
	ModelFormula    string                      `json:"model_formula"`
}

type PlanCapacityInfo struct {
	SampleCount              int64   `json:"sample_count"`
	Confidence               string  `json:"confidence"`
	TotalInputTokens         int64   `json:"total_input_tokens"`
	TotalOutputTokens        int64   `json:"total_output_tokens"`
	TotalCachedTokens        int64   `json:"total_cached_tokens"`
	TotalReasoningTokens     int64   `json:"total_reasoning_tokens"`
	OutputMultiplier         float64 `json:"output_multiplier"`
	EstimatedPrimaryCapacity int64   `json:"estimated_5h_capacity"`
	EstimatedSecondaryCapacity int64 `json:"estimated_7d_capacity"`
}

func (h *proxyHandler) handlePoolStats(w http.ResponseWriter, r *http.Request) {
	// Require friend code authentication via query param or header
	friendCode := r.URL.Query().Get("code")
	if friendCode == "" {
		friendCode = r.Header.Get("X-Friend-Code")
	}

	if h.cfg.friendCode == "" || friendCode != h.cfg.friendCode {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	accounts := h.pool.allAccounts()

	stats := PoolStats{
		TotalAccounts: len(accounts),
		GeneratedAt:   time.Now(),
	}

	if h.poolUsers != nil {
		stats.TotalPoolUsers = len(h.poolUsers.List())
	}

	var totalInput, totalCached, totalOutput, totalReasoning, totalBillable int64
	var primarySum, secondarySum float64
	activeCount := 0

	for _, acc := range accounts {
		acc.mu.Lock()

		status := "healthy"
		if acc.Dead {
			status = "dead"
		} else if acc.Penalty > 0.5 {
			status = "degraded"
		} else {
			activeCount++
		}

		accType := "codex"
		if acc.Type == AccountTypeGemini {
			accType = "gemini"
		}

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

		as := AccountStats{
			ID:                    hashAccountID(acc.ID),
			Type:                  accType,
			PlanType:              acc.PlanType,
			Status:                status,
			PrimaryWindowUsed:     acc.Usage.PrimaryUsedPercent * 100,
			SecondaryWindowUsed:   acc.Usage.SecondaryUsedPercent * 100,
			PrimaryResetMinutes:   primaryReset,
			SecondaryResetMinutes: secondaryReset,
			TotalInputTokens:      acc.Totals.TotalInputTokens,
			TotalCachedTokens:     acc.Totals.TotalCachedTokens,
			TotalOutputTokens:     acc.Totals.TotalOutputTokens,
			TotalReasoningTokens:  acc.Totals.TotalReasoningTokens,
			TotalBillableTokens:   acc.Totals.TotalBillableTokens,
			CacheHitRate:          cacheHitRate,
			HasCredits:            acc.Usage.HasCredits,
			CreditsBalance:        acc.Usage.CreditsBalance,
		}

		totalInput += acc.Totals.TotalInputTokens
		totalCached += acc.Totals.TotalCachedTokens
		totalOutput += acc.Totals.TotalOutputTokens
		totalReasoning += acc.Totals.TotalReasoningTokens
		totalBillable += acc.Totals.TotalBillableTokens
		primarySum += acc.Usage.PrimaryUsedPercent
		secondarySum += acc.Usage.SecondaryUsedPercent

		acc.mu.Unlock()
		stats.Accounts = append(stats.Accounts, as)
	}

	stats.ActiveAccounts = activeCount

	overallCacheRate := float64(0)
	if totalInput > 0 {
		overallCacheRate = float64(totalCached) / float64(totalInput) * 100
	}

	avgPrimary := float64(0)
	avgSecondary := float64(0)
	if len(accounts) > 0 {
		avgPrimary = (primarySum / float64(len(accounts))) * 100
		avgSecondary = (secondarySum / float64(len(accounts))) * 100
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

	// Load capacity analysis from store
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
					estPrimary = int64(cap.EffectivePerPrimaryPct * 100)
				}
				if cap.EffectivePerSecondaryPct > 0 {
					estSecondary = int64(cap.EffectivePerSecondaryPct * 100)
				}
				analysis.Plans[planType] = PlanCapacityInfo{
					SampleCount:              cap.SampleCount,
					Confidence:               confidence,
					TotalInputTokens:         cap.TotalInputTokens,
					TotalOutputTokens:        cap.TotalOutputTokens,
					TotalCachedTokens:        cap.TotalCachedTokens,
					TotalReasoningTokens:     cap.TotalReasoningTokens,
					OutputMultiplier:         mult,
					EstimatedPrimaryCapacity: estPrimary,
					EstimatedSecondaryCapacity: estSecondary,
				}
			}
			stats.CapacityAnalysis = analysis
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleWhoami returns the current user's ID based on their JWT or hashed IP.
func (h *proxyHandler) handleWhoami(w http.ResponseWriter, r *http.Request) {
	var userID string
	var userType string

	if secret := getPoolJWTSecret(); secret != "" {
		if isPoolUser, uid, _ := isPoolUserToken(secret, r.Header.Get("Authorization")); isPoolUser {
			userID = uid
			userType = "pool_user"
		}
	}
	if userID == "" {
		ip := getClientIP(r)
		salt := h.cfg.friendCode
		if salt == "" {
			salt = "codex-pool"
		}
		userID = hashUserIP(ip, salt)
		userType = "anonymous"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"user_id": userID,
		"type":    userType,
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

// handleDailyBreakdown returns combined daily token usage from all accounts.
func (h *proxyHandler) handleDailyBreakdown(w http.ResponseWriter, r *http.Request) {
	type DayUsage struct {
		Date    string             `json:"date"`
		Surfaces map[string]float64 `json:"surfaces"`
		Total   float64            `json:"total"`
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
		"days":           result,
		"account_count":  len(accounts),
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
