package main

import (
	"log"
	"net/http"
	"strings"
)

// checkAdminAuth verifies the admin token from header or query param.
// Returns true if authorized, false if not (and sends 401 response).
func (h *proxyHandler) checkAdminAuth(w http.ResponseWriter, r *http.Request) bool {
	if h.cfg.adminToken == "" {
		// No admin token configured - deny all admin access
		http.Error(w, "admin access disabled", http.StatusForbidden)
		return false
	}

	// Check header first, then query param
	token := r.Header.Get("X-Admin-Token")
	if token == "" {
		token = r.URL.Query().Get("admin_token")
	}

	if token != h.cfg.adminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// checkAdminOrFriendAuth verifies either the admin token or the friend code.
// This is used for "pool stats" endpoints that are intended to be accessible in friend mode
// (with the friend code) while still allowing admin access when configured.
func (h *proxyHandler) checkAdminOrFriendAuth(w http.ResponseWriter, r *http.Request) bool {
	// If nothing is configured, treat as an open/local deployment.
	if h.cfg.adminToken == "" && h.cfg.friendCode == "" {
		return true
	}

	// Admin token (header first, then query param)
	if h.cfg.adminToken != "" {
		headerToken := r.Header.Get("X-Admin-Token")
		queryToken := r.URL.Query().Get("admin_token")
		if headerToken == h.cfg.adminToken || queryToken == h.cfg.adminToken {
			return true
		}
	}

	// Friend code (query param or header)
	if h.cfg.friendCode != "" {
		queryCode := r.URL.Query().Get("code")
		headerCode := r.Header.Get("X-Friend-Code")
		if queryCode == h.cfg.friendCode || headerCode == h.cfg.friendCode {
			return true
		}
	}

	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

// ServeHTTP routes incoming requests to the appropriate handler.
func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := randomID()
	if h.cfg.debug {
		log.Printf("[%s] incoming %s %s", reqID, r.Method, r.URL.Path)
	}

	// Static routes
	switch r.URL.Path {
	case "/":
		h.serveFriendLanding(w, r)
		return
	case "/og-image.png":
		h.serveOGImage(w, r)
		return
	case "/hero.png":
		h.serveHeroImage(w, r)
		return
	case "/api/friend/claim":
		h.handleFriendClaim(w, r)
		return
	case "/api/pool/stats":
		h.handlePoolStats(w, r)
		return
	case "/api/pool/whoami":
		h.handleWhoami(w, r)
		return
	case "/api/pool/users":
		if !h.checkAdminOrFriendAuth(w, r) {
			return
		}
		h.handlePoolUsers(w, r)
		return
	case "/api/pool/daily-breakdown":
		if !h.checkAdminOrFriendAuth(w, r) {
			return
		}
		h.handleDailyBreakdown(w, r)
		return
	case "/favicon.ico":
		http.NotFound(w, r)
		return
	case "/healthz":
		h.serveHealth(w)
		return
	case "/metrics":
		if !h.checkAdminAuth(w, r) {
			return
		}
		h.metrics.serve(w, r)
		return
	case "/admin/reload":
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.reloadAccounts()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		return
	case "/admin/accounts":
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.serveAccounts(w)
		return
	case "/admin/tokens":
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.serveTokenCapacity(w)
		return
	}

	// Account resurrect: /admin/accounts/:id/resurrect
	if strings.HasPrefix(r.URL.Path, "/admin/accounts/") && strings.HasSuffix(r.URL.Path, "/resurrect") {
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Extract account ID from path
		path := strings.TrimPrefix(r.URL.Path, "/admin/accounts/")
		accountID := strings.TrimSuffix(path, "/resurrect")
		h.resurrectAccount(w, accountID)
		return
	}

	// Friend landing page with code
	if strings.HasPrefix(r.URL.Path, "/friend/") {
		h.serveFriendLanding(w, r)
		return
	}

	// User daily usage: /api/pool/users/:id/daily
	if strings.HasPrefix(r.URL.Path, "/api/pool/users/") && strings.HasSuffix(r.URL.Path, "/daily") {
		h.handleUserDaily(w, r)
		return
	}

	// Setup scripts
	if strings.HasPrefix(r.URL.Path, "/setup/codex/") {
		h.serveCodexSetupScript(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/setup/gemini/") {
		h.serveGeminiSetupScript(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/setup/claude/") {
		h.serveClaudeSetupScript(w, r)
		return
	}

	// Pool user admin routes
	if strings.HasPrefix(r.URL.Path, "/admin/pool-users") {
		if !h.checkAdminAuth(w, r) {
			return
		}
		h.servePoolUsersAdmin(w, r)
		return
	}

	// Claude account admin routes
	// Note: /admin/claude/callback skips auth (OAuth redirect from Anthropic)
	if strings.HasPrefix(r.URL.Path, "/admin/claude") {
		if r.URL.Path != "/admin/claude/callback" {
			if !h.checkAdminAuth(w, r) {
				return
			}
		}
		h.serveClaudeAdmin(w, r)
		return
	}

	// Codex account admin routes (friend auth - accessible from friend landing page)
	if strings.HasPrefix(r.URL.Path, "/admin/codex") {
		if !h.checkAdminOrFriendAuth(w, r) {
			return
		}
		h.serveCodexAdmin(w, r)
		return
	}

	// Config download routes (no auth - token is the auth)
	if strings.HasPrefix(r.URL.Path, "/config/codex/") || strings.HasPrefix(r.URL.Path, "/config/gemini/") || strings.HasPrefix(r.URL.Path, "/config/claude/") {
		h.serveConfigDownload(w, r)
		return
	}

	// Fake refresh handler so Codex CLI never needs to hit the real auth server.
	if strings.HasPrefix(r.URL.Path, "/oauth/token") {
		h.serveFakeOAuthToken(w, r)
		return
	}

	// Special case: aggregate usage for client; do not hit upstream.
	if isUsageRequest(r) {
		h.refreshUsageIfStale()
		h.handleAggregatedUsage(w, reqID)
		return
	}

	// Claude-specific endpoints - return pool info instead of individual account info
	if isClaudeProfileRequest(r) {
		h.handleClaudeProfile(w, r)
		return
	}
	if isClaudeUsageRequest(r) {
		h.handleClaudeUsage(w, r)
		return
	}

	// Default: proxy to upstream
	h.proxyRequest(w, r, reqID)
}
