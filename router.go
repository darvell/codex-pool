package main

import (
	"log"
	"net/http"
	"strings"
)

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
		h.handlePoolUsers(w, r)
		return
	case "/api/pool/daily-breakdown":
		h.handleDailyBreakdown(w, r)
		return
	case "/favicon.ico":
		http.NotFound(w, r)
		return
	case "/healthz":
		h.serveHealth(w)
		return
	case "/metrics":
		h.metrics.serve(w, r)
		return
	case "/admin/reload":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.reloadAccounts()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		return
	case "/admin/accounts":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.serveAccounts(w)
		return
	case "/admin/tokens":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.serveTokenCapacity(w)
		return
	}

	// Account resurrect: /admin/accounts/:id/resurrect
	if strings.HasPrefix(r.URL.Path, "/admin/accounts/") && strings.HasSuffix(r.URL.Path, "/resurrect") {
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
		h.servePoolUsersAdmin(w, r)
		return
	}

	// Claude account admin routes
	if strings.HasPrefix(r.URL.Path, "/admin/claude") {
		h.serveClaudeAdmin(w, r)
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
