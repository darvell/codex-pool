package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

func normalizeNoopPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	// Reverse proxies and clients sometimes leave a trailing slash.
	if path != "/" {
		path = strings.TrimRight(path, "/")
	}
	return path
}

// isCodexAppsMCPPath matches the streamable-HTTP endpoint Codex uses for the
// built-in codex_apps MCP server. Path can arrive with or without the
// /backend-api prefix depending on how the public reverse proxy rewrites.
func isCodexAppsMCPPath(path string) bool {
	path = normalizeNoopPath(path)
	switch path {
	case "/api/codex/apps",
		"/backend-api/wham/apps",
		"/wham/apps",
		"/apps",
		"/backend-api/ps/mcp",
		"/api/codex/ps/mcp",
		"/ps/mcp":
		return true
	}
	return strings.HasSuffix(path, "/wham/apps") ||
		strings.HasSuffix(path, "/codex/apps") ||
		strings.HasSuffix(path, "/ps/mcp")
}

func isCodexResetCreditsPath(path string) bool {
	path = normalizeNoopPath(path)
	return strings.HasSuffix(path, "/rate-limit-reset-credits") ||
		strings.HasSuffix(path, "/rate-limit-reset-credits/consume")
}

func servePoolCodexResetCredits(w http.ResponseWriter, r *http.Request) {
	path := normalizeNoopPath(r.URL.Path)
	if strings.HasSuffix(path, "/consume") {
		respondJSON(w, map[string]any{
			"code":          "no_credit",
			"windows_reset": 0,
		})
		return
	}
	respondJSON(w, map[string]any{
		"available_count": 0,
		"credits":         []any{},
	})
}

func shouldNoopCodexPath(path string) bool {
	path = normalizeNoopPath(path)
	if isCodexAppsMCPPath(path) {
		return true
	}
	// OAuth discovery for streamable HTTP is rooted at the MCP URL path.
	if strings.HasPrefix(path, "/.well-known/oauth-authorization-server") {
		return true
	}
	switch path {
	case "/connectors/directory/list",
		"/connectors/directory/list_workspace",
		"/codex/analytics-events/events",
		"/v1/traces/ingest",
		"/plugins/featured",
		"/plugins/list",
		"/backend-api/plugins/featured",
		"/backend-api/codex/analytics-events/events":
		return true
	default:
		return false
	}
}

func serveNoopCodexPath(w http.ResponseWriter, r *http.Request) {
	path := normalizeNoopPath(r.URL.Path)
	if isCodexAppsMCPPath(path) {
		serveNoopCodexAppsMCP(w, r)
		return
	}
	if strings.HasPrefix(path, "/.well-known/oauth-authorization-server") {
		// Empty discovery doc: codex_apps does not need OAuth through the pool.
		respondJSON(w, map[string]any{
			"authorization_endpoint": "",
			"token_endpoint":         "",
			"scopes_supported":       []string{},
		})
		return
	}
	switch path {
	case "/connectors/directory/list", "/connectors/directory/list_workspace":
		respondJSON(w, map[string]any{
			"apps":      []any{},
			"nextToken": nil,
		})
	case "/v1/traces/ingest":
		respondJSON(w, map[string]any{"ok": true})
	default:
		// Empty success for noisy telemetry / plugin list probes.
		w.WriteHeader(http.StatusOK)
	}
}

func serveNoopCodexAppsMCP(w http.ResponseWriter, r *http.Request) {
	// Streamable HTTP may open with GET (SSE) or OPTIONS; neither needs tools.
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, HEAD, POST, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = json.Unmarshal(body, &req)

	// Notifications (no id) — accept and stop. Includes notifications/initialized.
	if len(req.ID) == 0 || string(req.ID) == "null" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		return
	}

	result := map[string]any{}
	switch req.Method {
	case "initialize":
		// Echo the client's protocolVersion when present; clients reject
		// unsupported versions. Empty tools is intentional — pool has no apps.
		protocolVersion := "2025-06-18"
		if len(req.Params) > 0 {
			var params struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			if err := json.Unmarshal(req.Params, &params); err == nil && strings.TrimSpace(params.ProtocolVersion) != "" {
				protocolVersion = strings.TrimSpace(params.ProtocolVersion)
			}
		}
		result = map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities": map[string]any{
				"tools": map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{"name": "codex_apps", "version": "0.0.0"},
		}
	case "tools/list":
		// Empty tool list: quiet success instead of 401/handshake failure.
		result = map[string]any{"tools": []any{}}
	case "resources/list":
		result = map[string]any{"resources": []any{}}
	case "resources/templates/list":
		result = map[string]any{"resourceTemplates": []any{}}
	case "prompts/list":
		result = map[string]any{"prompts": []any{}}
	case "ping":
		result = map[string]any{}
	default:
		// Unknown methods: empty result rather than hard error so startup
		// probes do not surface as MCP client failures.
		result = map[string]any{}
	}

	respondJSON(w, map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(req.ID),
		"result":  result,
	})
}

// checkAdminAuth verifies the admin token from its request header.
// Returns true if authorized, false if not (and sends 401 response).
func (h *proxyHandler) checkAdminAuth(w http.ResponseWriter, r *http.Request) bool {
	ip := getClientIP(r)
	if h.bruteForce != nil && h.bruteForce.isBanned(ip) {
		http.Error(w, "too many failed attempts, try again later", http.StatusTooManyRequests)
		return false
	}

	if h.cfg.adminToken == "" {
		// No admin token configured - deny all admin access
		log.Printf("admin auth: no token configured")
		http.Error(w, "admin access disabled", http.StatusForbidden)
		return false
	}

	// Secrets belong in headers, never URLs or logs.
	token := r.Header.Get("X-Admin-Token")

	if h.cfg.debug.Load() {
		log.Printf("admin auth: credential_present=%v", token != "")
	}

	if token != h.cfg.adminToken {
		if h.bruteForce != nil {
			h.bruteForce.recordFailure(ip)
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	if h.bruteForce != nil {
		h.bruteForce.recordSuccess(ip)
	}
	return true
}

// checkAdminOrFriendAuth verifies either the admin token or the friend code.
// This is used for "pool stats" endpoints that are intended to be accessible in friend mode
// (with the friend code) while still allowing admin access when configured.
func (h *proxyHandler) checkAdminOrFriendAuth(w http.ResponseWriter, r *http.Request) bool {
	ip := getClientIP(r)
	if h.bruteForce != nil && h.bruteForce.isBanned(ip) {
		http.Error(w, "too many failed attempts, try again later", http.StatusTooManyRequests)
		return false
	}

	// If nothing is configured, treat as an open/local deployment.
	if h.cfg.adminToken == "" && h.cfg.friendCode == "" {
		return true
	}

	// Admin credentials are header-only for the same reason as friend codes.
	if h.cfg.adminToken != "" {
		headerToken := r.Header.Get("X-Admin-Token")
		if headerToken == h.cfg.adminToken {
			if h.bruteForce != nil {
				h.bruteForce.recordSuccess(ip)
			}
			return true
		}
	}

	// Friend credentials are accepted only in a header. Query-string secrets
	// leak into browser history, reverse-proxy logs, analytics, and referrers.
	if h.cfg.friendCode != "" {
		headerCode := r.Header.Get("X-Friend-Code")
		if headerCode == h.cfg.friendCode {
			if h.bruteForce != nil {
				h.bruteForce.recordSuccess(ip)
			}
			return true
		}
	}

	if h.bruteForce != nil {
		h.bruteForce.recordFailure(ip)
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

// ServeHTTP routes incoming requests to the appropriate handler.
func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := randomID()
	if h.cfg.debug.Load() {
		log.Printf("[%s] incoming %s %s", reqID, r.Method, r.URL.Path)
	}

	// Fingerprinted signal-room assets are embedded by the Go binary.
	if strings.HasPrefix(r.URL.Path, "/assets/") {
		h.serveSignalRoomAsset(w, r)
		return
	}

	// Static routes
	switch r.URL.Path {
	case "/":
		h.serveFriendLanding(w, r)
		return
	case "/cute-code":
		h.serveCuteCodeLanding(w, r)
		return
	case "/status":
		h.serveStatusPage(w, r)
		return
	case "/og-image.png":
		h.serveOGImage(w, r)
		return
	case "/hero.png", "/hero.webp":
		h.serveHeroImage(w, r)
		return
	case "/api/friend/claim":
		h.handleFriendClaim(w, r)
		return
	case "/api/pool/stats":
		if !h.checkAdminOrFriendAuth(w, r) {
			return
		}
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
	case "/api/pool/origins":
		if !h.checkAdminOrFriendAuth(w, r) {
			return
		}
		h.handlePoolOrigins(w, r)
		return
	case "/api/pool/daily-breakdown":
		if !h.checkAdminOrFriendAuth(w, r) {
			return
		}
		h.handleDailyBreakdown(w, r)
		return
	case "/api/pool/hourly":
		if !h.checkAdminOrFriendAuth(w, r) {
			return
		}
		h.handleGlobalHourly(w, r)
		return
	case "/api/pool/signal":
		if !h.checkAdminOrFriendAuth(w, r) {
			return
		}
		h.handleSignalAnalytics(w, r)
		return
	case "/api/pool/catalog":
		if !h.checkAdminOrFriendAuth(w, r) {
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		servePoolModels(w, h.pool)
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
	case "/admin/origins":
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleAdminOrigins(w, r)
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
	case "/admin/clear-rate-limits":
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.clearAllRateLimits(w)
		return
	case "/admin/purge-anonymous":
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.purgeAnonymousUsers(w)
		return
	}

	// Account enable/disable: /admin/accounts/:id/{enable,disable}
	if strings.HasPrefix(r.URL.Path, "/admin/accounts/") &&
		(strings.HasSuffix(r.URL.Path, "/enable") || strings.HasSuffix(r.URL.Path, "/disable")) {
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/admin/accounts/")
		disabled := strings.HasSuffix(path, "/disable")
		accountID := strings.TrimSuffix(strings.TrimSuffix(path, "/disable"), "/enable")
		h.setAccountDisabled(w, accountID, disabled)
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

	// Account force refresh: /admin/accounts/:id/refresh
	if strings.HasPrefix(r.URL.Path, "/admin/accounts/") && strings.HasSuffix(r.URL.Path, "/refresh") {
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/admin/accounts/")
		accountID := strings.TrimSuffix(path, "/refresh")
		h.forceRefreshAccount(w, accountID)
		return
	}

	// Friend landing page with code
	if strings.HasPrefix(r.URL.Path, "/friend/") {
		h.serveFriendLanding(w, r)
		return
	}

	// User daily usage: /api/pool/users/:id/daily
	if strings.HasPrefix(r.URL.Path, "/api/pool/users/") && strings.HasSuffix(r.URL.Path, "/daily") {
		if !h.checkAdminOrFriendAuth(w, r) {
			return
		}
		h.handleUserDaily(w, r)
		return
	}

	// User hourly usage: /api/pool/users/:id/hourly
	if strings.HasPrefix(r.URL.Path, "/api/pool/users/") && strings.HasSuffix(r.URL.Path, "/hourly") {
		if !h.checkAdminOrFriendAuth(w, r) {
			return
		}
		h.handleUserHourly(w, r)
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
	if strings.HasPrefix(r.URL.Path, "/setup/cute-code/") {
		h.serveCuteCodeSetupScript(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/setup/grok/") {
		h.serveGrokSetupScript(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/setup/pi/") {
		h.servePiSetupScript(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/config/cute-code/") {
		h.serveCuteCodeSettingsConfig(w, r)
		return
	}

	// Friends may contribute new provider credentials, but cannot inspect raw
	// account identities, remove accounts, or mutate existing provider state.
	if strings.HasPrefix(r.URL.Path, "/api/pool/accounts/") {
		if !h.checkAdminOrFriendAuth(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		switch r.URL.Path {
		case "/api/pool/accounts/codex/add":
			h.handleCodexAdd(w, r)
		case "/api/pool/accounts/codex/exchange":
			h.handleCodexExchange(w, r)
		case "/api/pool/accounts/claude/add":
			h.handleClaudeAdd(w, r)
		case "/api/pool/accounts/claude/exchange":
			h.handleClaudeExchange(w, r)
		case "/api/pool/accounts/antigravity/add":
			h.handleAntigravityAdd(w, r)
		case "/api/pool/accounts/antigravity/status":
			h.handleAntigravityStatus(w, r)
		case "/api/pool/accounts/antigravity/exchange":
			h.handleAntigravityExchange(w, r)
		case "/api/pool/accounts/kimi/add":
			h.handleKimiAdd(w, r)
		case "/api/pool/accounts/minimax/add":
			h.handleMinimaxAdd(w, r)
		case "/api/pool/accounts/zai/add":
			h.handleZAIAdd(w, r)
		case "/api/pool/accounts/xiaomi/add":
			h.handleXiaomiAdd(w, r)
		case "/api/pool/accounts/grok/add":
			h.handleGrokImport(w, r)
		default:
			http.NotFound(w, r)
		}
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

	// Provider mutations require an explicit operator unlock. The Claude OAuth
	// callback remains public because it is invoked by the upstream redirect;
	// exchanging that callback for credentials still requires admin auth.
	if strings.HasPrefix(r.URL.Path, "/admin/claude") {
		if r.URL.Path != "/admin/claude/callback" && !h.checkAdminAuth(w, r) {
			return
		}
		h.serveClaudeAdmin(w, r)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/admin/codex") {
		if !h.checkAdminAuth(w, r) {
			return
		}
		h.serveCodexAdmin(w, r)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/admin/antigravity") {
		if r.URL.Path == "/admin/antigravity/callback" {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			h.handleAntigravityCallback(w, r)
			return
		}
		if !h.checkAdminAuth(w, r) {
			return
		}
		if r.URL.Path == "/admin/antigravity/models/sync" && r.Method == http.MethodPost {
			h.handleAntigravityModelSync(w, r)
			return
		}
		if r.URL.Path == "/admin/antigravity/models/verify" && r.Method == http.MethodPost {
			h.handleAntigravityModelVerify(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/admin/kimi") {
		if !h.checkAdminAuth(w, r) {
			return
		}
		h.serveKimiAdmin(w, r)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/admin/minimax") {
		if !h.checkAdminAuth(w, r) {
			return
		}
		h.serveMinimaxAdmin(w, r)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/admin/zai") {
		if !h.checkAdminAuth(w, r) {
			return
		}
		h.serveZAIAdmin(w, r)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/admin/xiaomi") {
		if !h.checkAdminAuth(w, r) {
			return
		}
		h.serveXiaomiAdmin(w, r)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/admin/grok") {
		if !h.checkAdminAuth(w, r) {
			return
		}
		h.serveGrokAdmin(w, r)
		return
	}

	// Config download routes (no auth - token is the auth)
	if strings.HasPrefix(r.URL.Path, "/config/codex/") || strings.HasPrefix(r.URL.Path, "/config/gemini/") || strings.HasPrefix(r.URL.Path, "/config/claude/") || strings.HasPrefix(r.URL.Path, "/config/pi/") || strings.HasPrefix(r.URL.Path, "/config/grok/") {
		h.serveConfigDownload(w, r)
		return
	}

	// Fake refresh handler so Codex CLI never needs to hit the real auth server.
	if strings.HasPrefix(r.URL.Path, "/oauth/token") {
		h.serveFakeOAuthToken(w, r)
		return
	}

	// Pool users never own reset credits. Redemption is reserved for the
	// server-side account poller, which calls ChatGPT directly.
	if isCodexResetCreditsPath(r.URL.Path) {
		servePoolCodexResetCredits(w, r)
		return
	}

	// Special case: aggregate usage for client; do not hit upstream.
	if isUsageRequest(r) {
		h.pollUpstreamUsage()
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

	if shouldNoopCodexPath(r.URL.Path) {
		serveNoopCodexPath(w, r)
		return
	}

	// Default: proxy to upstream
	h.proxyRequest(w, r, reqID)
}
