package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Claude account admin handlers - JSON API only

// In-memory store for pending OAuth sessions
var claudeOAuthSessions = struct {
	sync.RWMutex
	sessions map[string]*ClaudeOAuthSession
}{sessions: make(map[string]*ClaudeOAuthSession)}

// serveClaudeAdmin routes Claude admin requests (auth already checked by router)
func (h *proxyHandler) serveClaudeAdmin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/claude")
	if path == "" {
		path = "/"
	}

	switch {
	case path == "/" && r.Method == http.MethodGet:
		h.handleClaudeList(w, r)

	case path == "/plans" && r.Method == http.MethodGet:
		h.handleClaudePlanProbe(w, r)

	case path == "/add" && r.Method == http.MethodPost:
		h.handleClaudeAdd(w, r)

	case path == "/callback" && r.Method == http.MethodGet:
		// Callback doesn't need admin auth - user redirected from Anthropic
		h.handleClaudeCallback(w, r)

	case path == "/exchange" && r.Method == http.MethodPost:
		h.handleClaudeExchange(w, r)

	case strings.HasSuffix(path, "/refresh") && r.Method == http.MethodPost:
		id := strings.TrimPrefix(path, "/")
		id = strings.TrimSuffix(id, "/refresh")
		h.handleClaudeRefresh(w, r, id)

	default:
		http.NotFound(w, r)
	}
}

// GET /admin/claude - list all Claude accounts
func (h *proxyHandler) handleClaudeList(w http.ResponseWriter, r *http.Request) {
	accounts := h.pool.allAccounts()

	type accountInfo struct {
		ID          string    `json:"id"`
		PlanType    string    `json:"plan_type"`
		TokenType   string    `json:"token_type"` // "oauth" or "api_key"
		Dead        bool      `json:"dead"`
		Disabled    bool      `json:"disabled"`
		ExpiresAt   time.Time `json:"expires_at,omitempty"`
		LastRefresh time.Time `json:"last_refresh,omitempty"`
	}

	var result []accountInfo
	for _, acc := range accounts {
		if acc.Type == AccountTypeClaude {
			tokenType := "api_key"
			if strings.HasPrefix(acc.AccessToken, "sk-ant-oat") {
				tokenType = "oauth"
			}
			result = append(result, accountInfo{
				ID:          acc.ID,
				PlanType:    acc.PlanType,
				TokenType:   tokenType,
				Dead:        acc.Dead,
				Disabled:    acc.Disabled,
				ExpiresAt:   acc.ExpiresAt,
				LastRefresh: acc.LastRefresh,
			})
		}
	}

	respondJSON(w, map[string]any{
		"accounts": result,
		"count":    len(result),
	})
}

type claudeOAuthPlanHint struct {
	AccountID      string         `json:"account_id"`
	AccessPlanType string         `json:"access_plan_type"`
	FilePlanType   string         `json:"file_plan_type"`
	PlanType       string         `json:"plan_type"`
	PlanSource     string         `json:"plan_source"`
	Status         string         `json:"status"`
	Subscription   string         `json:"subscription_type"`
	RateLimitTier  string         `json:"rate_limit_tier"`
	TokenFormat    string         `json:"token_format"`
	TokenClaims    map[string]any `json:"token_claims,omitempty"`
	TokenClaimsErr string         `json:"token_claims_error,omitempty"`
	LivePlanType   string         `json:"live_plan_type"`
	LivePlanSource string         `json:"live_plan_source"`
	LiveProfile    map[string]any `json:"live_profile,omitempty"`
	LiveError      string         `json:"live_profile_error,omitempty"`
}

type claudeOAuthFileMetadata struct {
	PlanType      string `json:"plan_type"`
	ClaudeAiOauth struct {
		SubscriptionType string `json:"subscriptionType"`
		RateLimitTier    string `json:"rateLimitTier"`
	} `json:"claudeAiOauth"`
}

func (h *proxyHandler) handleClaudePlanProbe(w http.ResponseWriter, r *http.Request) {
	live := r.URL.Query().Get("live") == "1" || strings.EqualFold(r.URL.Query().Get("live"), "true")
	accounts := h.pool.allAccounts()

	var result []claudeOAuthPlanHint
	for _, acc := range accounts {
		if acc.Type != AccountTypeClaude {
			continue
		}

		acc.mu.Lock()
		accountID := acc.ID
		accessPlanType := acc.PlanType
		accessToken := acc.AccessToken
		dead := acc.Dead
		disabled := acc.Disabled
		expiresAt := acc.ExpiresAt
		filePath := acc.File
		acc.mu.Unlock()

		entry := claudeOAuthPlanHint{
			AccountID:      accountID,
			AccessPlanType: accessPlanType,
			PlanType:       "unknown",
			PlanSource:     "fallback",
			Status:         "active",
		}
		if accessPlanType != "" {
			entry.PlanType = accessPlanType
			entry.PlanSource = "memory"
		}
		if dead {
			entry.Status = "dead"
		}
		if disabled {
			entry.Status = "disabled"
		}
		if !expiresAt.IsZero() && time.Now().After(expiresAt) {
			entry.Status = "expired"
		}

		format, claims, claimErr := decodeJWTClaims(accessToken)
		entry.TokenFormat = format
		if claims != nil {
			entry.TokenClaims = claims
		}
		if claimErr != "" {
			entry.TokenClaimsErr = claimErr
		}

		raw, err := os.ReadFile(filePath)
		if err != nil {
			entry.LiveError = "failed reading account file: " + err.Error()
			result = append(result, entry)
			continue
		}

		var metadata claudeOAuthFileMetadata
		if err := json.Unmarshal(raw, &metadata); err != nil {
			entry.LiveError = "failed parsing account file: " + err.Error()
			result = append(result, entry)
			continue
		}

		entry.FilePlanType = metadata.PlanType
		entry.Subscription = metadata.ClaudeAiOauth.SubscriptionType
		entry.RateLimitTier = metadata.ClaudeAiOauth.RateLimitTier

		switch {
		case entry.Subscription != "":
			entry.PlanType = entry.Subscription
			entry.PlanSource = "file.subscriptionType"
		case entry.FilePlanType != "" && entry.FilePlanType != "claude":
			entry.PlanType = entry.FilePlanType
			entry.PlanSource = "file.plan_type"
		}

		if live && strings.HasPrefix(accessToken, "sk-ant-oat") {
			profile, err := h.fetchClaudeOAuthProfile(accessToken)
			if err != nil {
				entry.LiveError = err.Error()
			} else {
				entry.LiveProfile = profile
				// Extract plan from organization.organization_type (the canonical source)
				info := extractProfileInfo(profile)
				entry.LivePlanType = info.SubscriptionType
				entry.RateLimitTier = info.RateLimitTier
				entry.LivePlanSource = "api.oauth.profile"
				if entry.LivePlanType == "" {
					entry.LivePlanType = "unknown"
				}
				entry.PlanType = entry.LivePlanType
				entry.PlanSource = entry.LivePlanSource
			}
		} else if live {
			entry.LiveError = "live profile probing is for OAuth tokens only"
		}

		result = append(result, entry)
	}

	respondJSON(w, map[string]any{
		"accounts": result,
		"count":    len(result),
		"live":     live,
	})
}

func (h *proxyHandler) fetchClaudeOAuthProfile(accessToken string) (map[string]any, error) {
	u := *h.cfg.claudeBase
	u.Path = singleJoin(u.Path, "/api/oauth/profile")

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("anthropic-version", ccAnthropicVersion)
	req.Header.Set("anthropic-dangerous-direct-browser-access", "true")
	req.Header.Set("X-App", "cli")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "codex-pool-admin-diagnostics")

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("profile status=%s body=%s", resp.Status, string(body))
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func decodeJWTClaims(token string) (string, map[string]any, string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		if strings.HasPrefix(token, "sk-ant-oat") {
			return "sk-ant-oat", nil, ""
		}
		if strings.HasPrefix(token, "sk-ant-api") {
			return "sk-ant-api", nil, ""
		}
		return "opaque", nil, ""
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return "jwt", nil, err.Error()
		}
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "jwt", nil, err.Error()
	}
	return "jwt", claims, ""
}

func normalizeString(v any) string {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// POST /admin/claude/add - start OAuth flow
func (h *proxyHandler) handleClaudeAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccountID string `json:"account_id"`
	}

	if r.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondJSONError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
	} else {
		req.AccountID = r.FormValue("account_id")
	}

	accountID := strings.TrimSpace(req.AccountID)
	if accountID == "" {
		accountID = "claude_" + randomHex(8)
	}

	// Generate OAuth URL
	authURL, session, err := ClaudeAuthorize(accountID)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Store session
	claudeOAuthSessions.Lock()
	claudeOAuthSessions.sessions[session.PKCE.Verifier] = session
	claudeOAuthSessions.Unlock()

	// Clean up old sessions
	go cleanupOldSessions()

	respondJSON(w, map[string]any{
		"oauth_url":  authURL,
		"verifier":   session.PKCE.Verifier,
		"account_id": accountID,
	})
}

// GET /admin/claude/callback - OAuth redirect endpoint (returns JSON with code)
func (h *proxyHandler) handleClaudeCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	respondJSON(w, map[string]any{
		"code":  code,
		"state": state,
	})
}

// POST /admin/claude/exchange - exchange OAuth code for tokens
func (h *proxyHandler) handleClaudeExchange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code     string `json:"code"`
		Verifier string `json:"verifier"`
	}

	if r.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondJSONError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
	} else {
		req.Code = r.FormValue("code")
		req.Verifier = r.FormValue("verifier")
	}

	code := strings.TrimSpace(req.Code)
	verifier := strings.TrimSpace(req.Verifier)

	if code == "" || verifier == "" {
		respondJSONError(w, http.StatusBadRequest, "code and verifier are required")
		return
	}

	// Look up session
	claudeOAuthSessions.RLock()
	session, ok := claudeOAuthSessions.sessions[verifier]
	claudeOAuthSessions.RUnlock()

	if !ok {
		respondJSONError(w, http.StatusBadRequest, "invalid or expired session")
		return
	}

	// Exchange code for tokens
	tokens, err := ClaudeExchange(code, verifier)
	if err != nil {
		log.Printf("Claude token exchange failed: %v", err)
		respondJSONError(w, http.StatusInternalServerError, "token exchange failed: "+err.Error())
		return
	}

	// Save the account
	if err := SaveClaudeAccount(h.cfg.poolDir, session.AccountID, tokens); err != nil {
		respondJSONError(w, http.StatusInternalServerError, "failed to save account: "+err.Error())
		return
	}

	// Remove session
	claudeOAuthSessions.Lock()
	delete(claudeOAuthSessions.sessions, verifier)
	claudeOAuthSessions.Unlock()

	// Reload accounts
	h.reloadAccounts()

	respondJSON(w, map[string]any{
		"success":    true,
		"account_id": session.AccountID,
	})
}

// POST /admin/claude/:id/refresh - refresh single account tokens
func (h *proxyHandler) handleClaudeRefresh(w http.ResponseWriter, r *http.Request, accountID string) {
	accounts := h.pool.allAccounts()
	var target *Account
	for _, acc := range accounts {
		if acc.Type == AccountTypeClaude && acc.ID == accountID {
			target = acc
			break
		}
	}

	if target == nil {
		respondJSONError(w, http.StatusNotFound, "account not found")
		return
	}

	if err := RefreshClaudeAccountTokens(target); err != nil {
		respondJSONError(w, http.StatusInternalServerError, "refresh failed: "+err.Error())
		return
	}

	respondJSON(w, map[string]any{
		"success":    true,
		"account_id": accountID,
	})
}

func cleanupOldSessions() {
	claudeOAuthSessions.Lock()
	defer claudeOAuthSessions.Unlock()

	now := time.Now()
	for verifier, session := range claudeOAuthSessions.sessions {
		if now.Sub(session.CreatedAt) > 10*time.Minute {
			delete(claudeOAuthSessions.sessions, verifier)
		}
	}
}
