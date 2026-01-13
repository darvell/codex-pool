package main

import (
	"encoding/json"
	"log"
	"net/http"
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

// POST /admin/claude/add - start OAuth flow
func (h *proxyHandler) handleClaudeAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccountID string `json:"account_id"`
	}

	if r.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
			http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		req.Code = r.FormValue("code")
		req.Verifier = r.FormValue("verifier")
	}

	code := strings.TrimSpace(req.Code)
	verifier := strings.TrimSpace(req.Verifier)

	if code == "" || verifier == "" {
		http.Error(w, "code and verifier are required", http.StatusBadRequest)
		return
	}

	// Look up session
	claudeOAuthSessions.RLock()
	session, ok := claudeOAuthSessions.sessions[verifier]
	claudeOAuthSessions.RUnlock()

	if !ok {
		http.Error(w, "invalid or expired session", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens
	tokens, err := ClaudeExchange(code, verifier)
	if err != nil {
		log.Printf("Claude token exchange failed: %v", err)
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Save the account
	if err := SaveClaudeAccount(h.cfg.poolDir, session.AccountID, tokens); err != nil {
		http.Error(w, "failed to save account: "+err.Error(), http.StatusInternalServerError)
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
		http.Error(w, "account not found", http.StatusNotFound)
		return
	}

	if err := RefreshClaudeAccountTokens(target); err != nil {
		http.Error(w, "refresh failed: "+err.Error(), http.StatusInternalServerError)
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
