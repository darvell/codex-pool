package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

type config struct {
	listenAddr    string
	responsesBase *url.URL
	whamBase      *url.URL
	refreshBase   *url.URL
	geminiBase    *url.URL // Gemini CloudCode endpoint
	poolDir       string

	disableRefresh bool

	debug         bool
	logBodies     bool
	bodyLogLimit  int64
	flushInterval time.Duration
	usageRefresh  time.Duration
	maxAttempts   int
	storePath     string
	retentionDays int
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustParse(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		log.Fatalf("invalid URL %q: %v", raw, err)
	}
	return u
}

func parseInt64(s string) (int64, error) {
	var n int64
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// Global config file reference for pool users config
var globalConfigFile *ConfigFile

func buildConfig() config {
	// Load config.toml if it exists
	configFile, err := loadConfigFile("config.toml")
	if err != nil {
		log.Printf("warning: failed to load config.toml: %v", err)
	}
	globalConfigFile = configFile

	var fileCfg ConfigFile
	if configFile != nil {
		fileCfg = *configFile
	}

	cfg := config{}
	cfg.listenAddr = getConfigString("PROXY_LISTEN_ADDR", fileCfg.ListenAddr, "127.0.0.1:8989")
	cfg.responsesBase = mustParse(getenv("UPSTREAM_RESPONSES_BASE", "https://chatgpt.com/backend-api/codex"))
	cfg.whamBase = mustParse(getenv("UPSTREAM_WHAM_BASE", "https://chatgpt.com/backend-api"))
	cfg.refreshBase = mustParse(getenv("UPSTREAM_REFRESH_BASE", "https://auth.openai.com"))
	cfg.geminiBase = mustParse(getenv("UPSTREAM_GEMINI_BASE", "https://cloudcode-pa.googleapis.com"))
	cfg.poolDir = getConfigString("POOL_DIR", fileCfg.PoolDir, "pool")

	// Refresh often fails for some auth.json fixtures; allow opting out.
	cfg.disableRefresh = getConfigBool("PROXY_DISABLE_REFRESH", fileCfg.DisableRefresh, false)

	cfg.debug = getConfigBool("PROXY_DEBUG", fileCfg.Debug, false)
	cfg.logBodies = getenv("PROXY_LOG_BODIES", "0") == "1"
	cfg.bodyLogLimit = 16 * 1024 // 16 KiB
	if v := getenv("PROXY_BODY_LOG_LIMIT", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n > 0 {
			cfg.bodyLogLimit = n
		}
	}
	cfg.flushInterval = 200 * time.Millisecond
	if v := getenv("PROXY_FLUSH_INTERVAL_MS", ""); v != "" {
		if ms, err := parseInt64(v); err == nil && ms > 0 {
			cfg.flushInterval = time.Duration(ms) * time.Millisecond
		}
	}
	cfg.usageRefresh = 5 * time.Minute
	if v := getenv("PROXY_USAGE_REFRESH_SECONDS", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n > 0 {
			cfg.usageRefresh = time.Duration(n) * time.Second
		}
	}
	cfg.maxAttempts = getConfigInt("PROXY_MAX_ATTEMPTS", fileCfg.MaxAttempts, 3)
	cfg.storePath = getConfigString("PROXY_DB_PATH", fileCfg.DBPath, "./data/proxy.db")
	cfg.retentionDays = 30
	if v := getenv("PROXY_USAGE_RETENTION_DAYS", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n > 0 {
			cfg.retentionDays = int(n)
		}
	}

	flag.StringVar(&cfg.listenAddr, "listen", cfg.listenAddr, "listen address")
	flag.Parse()
	return cfg
}

func main() {
	cfg := buildConfig()

	log.Printf("loading pool from %s", cfg.poolDir)
	accounts, err := loadPool(cfg.poolDir)
	if err != nil {
		log.Fatalf("load pool: %v", err)
	}
	pool := newPoolState(accounts, cfg.debug)
	codexCount := pool.countByType(AccountTypeCodex)
	geminiCount := pool.countByType(AccountTypeGemini)
	if pool.count() == 0 {
		log.Printf("warning: loaded 0 accounts from %s", cfg.poolDir)
	}

	store, err := newUsageStore(cfg.storePath, cfg.retentionDays)
	if err != nil {
		log.Fatalf("open usage store: %v", err)
	}
	defer store.Close()

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSHandshakeTimeout:   10 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 25 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
	}
	_ = http2.ConfigureTransport(transport)

	// Initialize pool users store if configured
	var poolUsers *PoolUserStore
	if getPoolAdminPassword() != "" && getPoolJWTSecret() != "" {
		poolUsersPath := getPoolUsersPath()
		var err error
		poolUsers, err = newPoolUserStore(poolUsersPath)
		if err != nil {
			log.Printf("warning: failed to load pool users: %v", err)
		} else {
			log.Printf("pool users enabled (%d users)", len(poolUsers.List()))
		}
	}

	h := &proxyHandler{
		cfg:       cfg,
		transport: transport,
		pool:      pool,
		poolUsers: poolUsers,
		store:     store,
		metrics:   newMetrics(),
		recent:    newRecentErrors(50),
		startTime: time.Now(),
	}
	h.startUsagePoller()

	srv := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           h,
		ReadHeaderTimeout: 15 * time.Second,
	}
	log.Printf("codex-pool proxy listening on %s (codex=%d, gemini=%d)", cfg.listenAddr, codexCount, geminiCount)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

type proxyHandler struct {
	cfg       config
	transport *http.Transport
	pool      *poolState
	poolUsers *PoolUserStore
	store     *usageStore
	metrics   *metrics
	recent    *recentErrors
	inflight  int64
	startTime time.Time
}

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := randomID()
	if h.cfg.debug {
		log.Printf("[%s] incoming %s %s", reqID, r.Method, r.URL.Path)
	}

	switch r.URL.Path {
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
	case "/status", "/status/":
		h.serveStatusPage(w, r)
		return
	}

	// Pool user admin routes
	if strings.HasPrefix(r.URL.Path, "/admin/pool-users") {
		h.servePoolUsersAdmin(w, r)
		return
	}

	// Config download routes (no auth - token is the auth)
	if strings.HasPrefix(r.URL.Path, "/config/codex/") || strings.HasPrefix(r.URL.Path, "/config/gemini/") {
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

	h.proxyRequest(w, r, reqID)
}

func (h *proxyHandler) serveHealth(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	respondJSON(w, map[string]any{
		"ok":             true,
		"uptime_seconds": int(time.Since(h.startTime).Seconds()),
		"accounts":       h.pool.count(),
		"inflight":       atomic.LoadInt64(&h.inflight),
		"recent_errors":  h.recent.snapshot(),
	})
}

func (h *proxyHandler) serveAccounts(w http.ResponseWriter) {
	type row struct {
		ID                      string      `json:"id"`
		Type                    AccountType `json:"type"`
		AccountID               string      `json:"account_id,omitempty"`
		IDTokenChatGPTAccountID string      `json:"id_token_chatgpt_account_id,omitempty"`
		Disabled                bool        `json:"disabled"`
		Dead                    bool        `json:"dead"`
		Inflight                int64       `json:"inflight"`
		ExpiresAt               time.Time   `json:"expires_at,omitempty"`
		LastRefresh             time.Time   `json:"last_refresh,omitempty"`
		Penalty                 float64     `json:"penalty"`
		Usage                   any         `json:"usage"`
		Totals                  any         `json:"totals"`
	}
	h.pool.mu.RLock()
	out := make([]row, 0, len(h.pool.accounts))
	for _, a := range h.pool.accounts {
		a.mu.Lock()
		accountID := a.AccountID
		idTokID := a.IDTokenChatGPTAccountID
		disabled := a.Disabled
		dead := a.Dead
		expiresAt := a.ExpiresAt
		lastRefresh := a.LastRefresh
		penalty := a.Penalty
		usage := a.Usage
		totals := a.Totals
		a.mu.Unlock()

		out = append(out, row{
			ID:                      a.ID,
			Type:                    a.Type,
			AccountID:               accountID,
			IDTokenChatGPTAccountID: idTokID,
			Disabled:                disabled,
			Dead:                    dead,
			Inflight:                atomic.LoadInt64(&a.Inflight),
			ExpiresAt:               expiresAt,
			LastRefresh:             lastRefresh,
			Penalty:                 penalty,
			Usage:                   usage,
			Totals:                  totals,
		})
	}
	h.pool.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	respondJSON(w, out)
}

func (h *proxyHandler) reloadAccounts() {
	log.Printf("reloading pool from %s", h.cfg.poolDir)
	accs, err := loadPool(h.cfg.poolDir)
	if err != nil {
		log.Printf("load pool: %v", err)
		return
	}
	h.pool.replace(accs)
	if h.pool.count() == 0 {
		log.Printf("warning: loaded 0 accounts from %s", h.cfg.poolDir)
	}
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
	return r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/backend-api/wham/usage")
}

func (h *proxyHandler) handleAggregatedUsage(w http.ResponseWriter, reqID string) {
	snap := h.pool.averageUsage()
	resp := map[string]any{
		"plan_type": "pro",
		"rate_limit": map[string]any{
			"allowed":       true,
			"limit_reached": false,
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
	}
	if h.cfg.debug {
		log.Printf("[%s] aggregate usage served locally", reqID)
	}
	w.Header().Set("Content-Type", "application/json")
	respondJSON(w, resp)
}

func (h *proxyHandler) pickUpstream(path string) (*url.URL, string, AccountType) {
	switch {
	// Gemini paths: /v1internal:generateContent, /v1internal:streamGenerateContent, etc.
	case strings.HasPrefix(path, "/v1internal:"):
		return h.cfg.geminiBase, "gemini", AccountTypeGemini
	case strings.HasPrefix(path, "/v1/"), strings.HasPrefix(path, "/responses"):
		return h.cfg.responsesBase, "responses", AccountTypeCodex
	case strings.HasPrefix(path, "/backend-api/"), strings.HasPrefix(path, "/api/codex/"):
		return h.cfg.whamBase, "wham", AccountTypeCodex
	default:
		return h.cfg.responsesBase, "fallback", AccountTypeCodex
	}
}

func mapResponsesPath(in string) string {
	switch {
	case strings.HasPrefix(in, "/v1/responses/compact"), strings.HasPrefix(in, "/responses/compact"):
		return "/responses/compact"
	case strings.HasPrefix(in, "/v1/responses"), strings.HasPrefix(in, "/responses"):
		return "/responses"
	default:
		return "/responses"
	}
}

func normalizePath(basePath, incoming string) string {
	if basePath == "" || basePath == "/" {
		return incoming
	}
	if strings.HasPrefix(incoming, basePath) {
		trimmed := strings.TrimPrefix(incoming, basePath)
		if !strings.HasPrefix(trimmed, "/") {
			trimmed = "/" + trimmed
		}
		return trimmed
	}
	return incoming
}

func singleJoin(basePath, reqPath string) string {
	if basePath == "" || basePath == "/" {
		return reqPath
	}
	if strings.HasSuffix(basePath, "/") && strings.HasPrefix(reqPath, "/") {
		return basePath + strings.TrimPrefix(reqPath, "/")
	}
	if !strings.HasSuffix(basePath, "/") && !strings.HasPrefix(reqPath, "/") {
		return basePath + "/" + reqPath
	}
	return basePath + reqPath
}

func extractConversationIDFromJSON(blob []byte) string {
	if len(blob) == 0 {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal(blob, &obj); err != nil {
		return ""
	}
	for _, key := range []string{"conversation_id", "conversation", "prompt_cache_key"} {
		if v, ok := obj[key].(string); ok && v != "" {
			return v
		}
	}
	// Some variants may tuck metadata under a sub-object.
	for _, containerKey := range []string{"metadata", "meta"} {
		if sub, ok := obj[containerKey].(map[string]any); ok {
			for _, key := range []string{"conversation_id", "conversation", "prompt_cache_key"} {
				if v, ok := sub[key].(string); ok && v != "" {
					return v
				}
			}
		}
	}
	return ""
}

func extractConversationIDFromSSE(sample []byte) string {
	// Best-effort: scan lines for JSON fragments and grab conversation_id/conversation.
	for _, line := range bytes.Split(sample, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			line = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		}
		if len(line) == 0 || bytes.Equal(line, []byte("[DONE]")) {
			continue
		}
		if id := extractConversationIDFromJSON(line); id != "" {
			return id
		}
	}
	return ""
}

func bodyForInspection(r *http.Request, body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	enc := ""
	if r != nil {
		enc = strings.ToLower(r.Header.Get("Content-Encoding"))
	}
	looksGzip := len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b
	if strings.Contains(enc, "gzip") || looksGzip {
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body
		}
		defer gr.Close()
		decoded, err := io.ReadAll(io.LimitReader(gr, 512*1024))
		if err != nil || len(decoded) == 0 {
			return body
		}
		return decoded
	}
	return body
}

func (h *proxyHandler) proxyRequest(w http.ResponseWriter, r *http.Request, reqID string) {
	start := time.Now()

	// Check if this is a pool user request
	if secret := getPoolJWTSecret(); secret != "" {
		if isPoolUser, userID, _ := isPoolUserToken(secret, r.Header.Get("Authorization")); isPoolUser {
			// Check if user is disabled
			if h.poolUsers != nil {
				if user := h.poolUsers.Get(userID); user != nil && user.Disabled {
					http.Error(w, "pool user disabled", http.StatusForbidden)
					return
				}
			}
			if h.cfg.debug {
				log.Printf("[%s] pool user request: user_id=%s", reqID, userID)
			}
			// Continue with normal routing - the proxy will use real pooled accounts
		}
	}

	targetBase, category, accountType := h.pickUpstream(r.URL.Path)
	if targetBase == nil {
		http.Error(w, "no upstream for path", http.StatusNotFound)
		return
	}

	bodyBytes, bodySample, err := readBodyForReplay(r.Body, h.cfg.logBodies, h.cfg.bodyLogLimit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// conversation_id usually comes from request JSON (Codex often includes it).
	inspect := bodyBytes
	if len(inspect) == 0 {
		inspect = bodySample
	}
	inspect = bodyForInspection(r, inspect)
	conversationID := extractConversationIDFromJSON(inspect)
	if h.cfg.debug && conversationID == "" && len(inspect) > 0 {
		// Help debug why conversation id isn't being extracted without dumping the full body.
		var obj map[string]any
		if err := json.Unmarshal(inspect, &obj); err == nil {
			keys := make([]string, 0, len(obj))
			for k := range obj {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if len(keys) > 30 {
				keys = keys[:30]
			}
			log.Printf("[%s] conv_id empty; top-level keys (first %d): %s", reqID, len(keys), strings.Join(keys, ","))
		}
	}

	if h.cfg.debug {
		log.Printf("[%s] incoming %s %s category=%s conv_id=%s authZ_len=%d chatgpt-id=%q content-type=%q content-encoding=%q body_bytes=%d",
			reqID,
			r.Method,
			r.URL.Path,
			category,
			conversationID,
			len(r.Header.Get("Authorization")),
			r.Header.Get("ChatGPT-Account-ID"),
			r.Header.Get("Content-Type"),
			r.Header.Get("Content-Encoding"),
			len(bodyBytes),
		)
	}
	if h.cfg.logBodies && len(bodySample) > 0 {
		log.Printf("[%s] request body sample (%d bytes): %s", reqID, len(bodySample), safeText(bodySample))
	}

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	attempts := h.cfg.maxAttempts
	if attempts <= 0 {
		attempts = 1
	}
	if n := h.pool.count(); n > 0 && attempts > n {
		attempts = n
	}

	exclude := map[string]bool{}
	var lastErr error
	var lastStatus int

	for attempt := 1; attempt <= attempts; attempt++ {
		acc := h.pool.candidate(conversationID, exclude, accountType)
		if acc == nil {
			if lastErr != nil {
				http.Error(w, lastErr.Error(), http.StatusServiceUnavailable)
			} else {
				http.Error(w, fmt.Sprintf("no live %s accounts", accountType), http.StatusServiceUnavailable)
			}
			return
		}
		exclude[acc.ID] = true

		atomic.AddInt64(&acc.Inflight, 1)
		atomic.AddInt64(&h.inflight, 1)

		resp, sampleBuf, err := h.tryOnce(ctx, r, bodyBytes, targetBase, category, acc, reqID)

		atomic.AddInt64(&acc.Inflight, -1)
		atomic.AddInt64(&h.inflight, -1)

		if err != nil {
			lastErr = err
			h.recent.add(err.Error())
			if h.cfg.debug {
				log.Printf("[%s] attempt %d/%d account=%s failed: %v", reqID, attempt, attempts, acc.ID, err)
			}
			continue
		}
		lastStatus = resp.StatusCode

		if isRetryableStatus(resp.StatusCode) {
			// Mark account health and try another one.
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				acc.mu.Lock()
				acc.Dead = true
				acc.Penalty += 1.0
				acc.mu.Unlock()
			} else {
				acc.mu.Lock()
				acc.Penalty += 0.3
				acc.mu.Unlock()
			}
			lastErr = fmt.Errorf("upstream %s", resp.Status)
			h.recent.add(lastErr.Error())
			resp.Body.Close()
			if h.cfg.debug {
				log.Printf("[%s] attempt %d/%d account=%s retryable status=%d", reqID, attempt, attempts, acc.ID, resp.StatusCode)
			}
			continue
		}

		h.updateUsageFromHeaders(acc, resp.Header)

		// Write response to client.
		copyHeader(w.Header(), resp.Header)
		removeHopByHopHeaders(w.Header())
		w.WriteHeader(resp.StatusCode)

		flusher, _ := w.(http.Flusher)
		isSSE := strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")

		// Stream body while optionally flushing.
		var writer io.Writer = w
		if isSSE && flusher != nil {
			writer = &flushWriter{w: w, f: flusher, flushInterval: h.cfg.flushInterval}
		}
		_, copyErr := io.Copy(writer, resp.Body)
		resp.Body.Close()
		if fw, ok := writer.(*flushWriter); ok {
			fw.stop()
		}

		if copyErr != nil {
			h.recent.add(copyErr.Error())
			h.metrics.inc("error", acc.ID)
			return
		}

		respSample := []byte(nil)
		if sampleBuf != nil {
			respSample = sampleBuf.Bytes()
		}
		if h.cfg.logBodies && len(respSample) > 0 {
			log.Printf("[%s] response body sample (%d bytes): %s", reqID, len(respSample), safeText(respSample))
		}
		if len(respSample) > 0 {
			h.updateUsageFromBody(acc, respSample)
		}

		// Success: pin conversation if possible (if request didn't include it, try to learn from response).
		if conversationID == "" && len(respSample) > 0 {
			conversationID = extractConversationIDFromSSE(respSample)
		}
		if conversationID != "" {
			h.pool.pin(conversationID, acc.ID)
		}
		acc.mu.Lock()
		acc.LastUsed = time.Now()
		acc.mu.Unlock()

		h.metrics.inc(strconv.Itoa(resp.StatusCode), acc.ID)

		if h.cfg.debug {
			log.Printf("[%s] done status=%d account=%s duration_ms=%d", reqID, resp.StatusCode, acc.ID, time.Since(start).Milliseconds())
		}
		return
	}

	// All attempts failed.
	status := http.StatusBadGateway
	if lastStatus == http.StatusTooManyRequests {
		status = http.StatusTooManyRequests
	}
	if lastErr == nil {
		lastErr = errors.New("all attempts failed")
	}
	http.Error(w, lastErr.Error(), status)
}

func isRetryableStatus(code int) bool {
	if code == http.StatusUnauthorized || code == http.StatusForbidden || code == http.StatusTooManyRequests {
		return true
	}
	return code >= 500 && code <= 599
}

func (h *proxyHandler) tryOnce(
	ctx context.Context,
	in *http.Request,
	bodyBytes []byte,
	targetBase *url.URL,
	category string,
	acc *Account,
	reqID string,
) (*http.Response, *bytes.Buffer, error) {
	if acc == nil {
		return nil, nil, errors.New("nil account")
	}

	if !h.cfg.disableRefresh && h.needsRefresh(acc) {
		if err := h.refreshAccount(ctx, acc); err != nil && h.cfg.debug {
			log.Printf("[%s] refresh %s failed: %v (continuing with existing token)", reqID, acc.ID, err)
		}
	}

	outURL := new(url.URL)
	*outURL = *in.URL
	outURL.Scheme = targetBase.Scheme
	outURL.Host = targetBase.Host
	switch category {
	case "gemini":
		// Gemini paths are already in the correct format: /v1internal:generateContent
		outURL.Path = in.URL.Path
	case "responses":
		outURL.Path = singleJoin(targetBase.Path, mapResponsesPath(in.URL.Path))
	default:
		outURL.Path = singleJoin(targetBase.Path, normalizePath(targetBase.Path, in.URL.Path))
	}

	buildReq := func() (*http.Request, error) {
		var body io.Reader
		if len(bodyBytes) > 0 {
			body = bytes.NewReader(bodyBytes)
		}
		outReq, err := http.NewRequestWithContext(ctx, in.Method, outURL.String(), body)
		if err != nil {
			return nil, err
		}

		outReq.Host = targetBase.Host
		outReq.Header = cloneHeader(in.Header)
		removeHopByHopHeaders(outReq.Header)

		// Always overwrite client-provided auth; the proxy is the single source of truth.
		outReq.Header.Del("Authorization")
		outReq.Header.Del("ChatGPT-Account-ID")
		outReq.Header.Del("Cookie")

		acc.mu.Lock()
		access := acc.AccessToken
		accountID := acc.AccountID
		idTokID := acc.IDTokenChatGPTAccountID
		accType := acc.Type
		acc.mu.Unlock()

		if access == "" {
			return nil, fmt.Errorf("account %s has empty access token", acc.ID)
		}
		outReq.Header.Set("Authorization", "Bearer "+access)

		// ChatGPT-Account-ID only applies to Codex accounts
		if accType == AccountTypeCodex {
			chatgptHeaderID := accountID
			if chatgptHeaderID == "" {
				chatgptHeaderID = idTokID
			}
			if chatgptHeaderID != "" {
				outReq.Header.Set("ChatGPT-Account-ID", chatgptHeaderID)
			}
		}
		return outReq, nil
	}

	outReq, err := buildReq()
	if err != nil {
		return nil, nil, err
	}

	if h.cfg.debug {
		acc.mu.Lock()
		log.Printf("[%s] -> %s %s (account=%s account_id=%s)", reqID, outReq.Method, outReq.URL.String(), acc.ID, acc.AccountID)
		acc.mu.Unlock()
	}

	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		acc.mu.Lock()
		acc.Penalty += 0.2
		acc.mu.Unlock()
		return nil, nil, err
	}

	// If we got a 401/403, try to refresh and retry on the *same* account once.
	if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && !h.cfg.disableRefresh {
		acc.mu.Lock()
		hasRefresh := acc.RefreshToken != ""
		acc.mu.Unlock()
		if hasRefresh {
			_ = resp.Body.Close()
			if err := h.refreshAccount(ctx, acc); err == nil {
				outReq, err = buildReq()
				if err != nil {
					return nil, nil, err
				}
				if h.cfg.debug {
					acc.mu.Lock()
					log.Printf("[%s] retry after refresh -> %s %s (account=%s account_id=%s)", reqID, outReq.Method, outReq.URL.String(), acc.ID, acc.AccountID)
					acc.mu.Unlock()
				}
				resp, err = h.transport.RoundTrip(outReq)
				if err != nil {
					acc.mu.Lock()
					acc.Penalty += 0.2
					acc.mu.Unlock()
					return nil, nil, err
				}
			}
		}
	}

	// Always tee a bounded sample of response body for usage extraction and conversation pinning.
	sampleLimit := int64(16 * 1024)
	if h.cfg.logBodies && h.cfg.bodyLogLimit > 0 {
		sampleLimit = h.cfg.bodyLogLimit
	}
	buf := &bytes.Buffer{}
	resp.Body = struct {
		io.Reader
		io.Closer
	}{
		Reader: io.TeeReader(resp.Body, &limitedWriter{w: buf, n: sampleLimit}),
		Closer: resp.Body,
	}
	return resp, buf, nil
}

func (h *proxyHandler) needsRefresh(a *Account) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.RefreshToken == "" {
		return false
	}
	now := time.Now()
	if !a.ExpiresAt.IsZero() && a.ExpiresAt.Before(now.Add(5*time.Minute)) {
		return true
	}
	if a.ExpiresAt.IsZero() && !a.LastRefresh.IsZero() && now.Sub(a.LastRefresh) > 6*time.Hour {
		return true
	}
	return false
}

func (h *proxyHandler) refreshAccount(ctx context.Context, a *Account) error {
	if a == nil {
		return errors.New("nil account")
	}
	a.mu.Lock()
	refreshTok := a.RefreshToken
	accType := a.Type
	a.mu.Unlock()
	if refreshTok == "" {
		return errors.New("no refresh token")
	}

	if accType == AccountTypeGemini {
		return h.refreshGeminiAccount(ctx, a, refreshTok)
	}
	return h.refreshCodexAccount(ctx, a, refreshTok)
}

func (h *proxyHandler) refreshCodexAccount(ctx context.Context, a *Account, refreshTok string) error {
	// Match Codex behavior: JSON body, Content-Type: application/json.
	body := map[string]string{
		"client_id":     "app_EMoamEEZ73f0CkXaXp7hrann",
		"grant_type":    "refresh_token",
		"refresh_token": refreshTok,
		"scope":         "openid profile email",
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return err
	}
	refreshURL := h.cfg.refreshBase.ResolveReference(&url.URL{Path: "/oauth/token"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, refreshURL.String(), bytes.NewReader(bodyJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "codex-pool-proxy")

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Best-effort include upstream error message without leaking tokens.
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		if len(bytes.TrimSpace(msg)) > 0 {
			return fmt.Errorf("refresh unauthorized: %s: %s", resp.Status, safeText(msg))
		}
		return fmt.Errorf("refresh unauthorized: %s", resp.Status)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		if len(bytes.TrimSpace(msg)) > 0 {
			return fmt.Errorf("refresh failed: %s: %s", resp.Status, safeText(msg))
		}
		return fmt.Errorf("refresh failed: %s", resp.Status)
	}

	var payload struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if payload.AccessToken == "" {
		return errors.New("empty access token after refresh")
	}

	a.mu.Lock()
	a.AccessToken = payload.AccessToken
	if payload.RefreshToken != "" {
		a.RefreshToken = payload.RefreshToken
	}
	if payload.IDToken != "" {
		a.IDToken = payload.IDToken
		claims := parseClaims(payload.IDToken)
		if !claims.ExpiresAt.IsZero() {
			a.ExpiresAt = claims.ExpiresAt
		}
		if claims.ChatGPTAccountID != "" {
			a.IDTokenChatGPTAccountID = claims.ChatGPTAccountID
			if a.AccountID == "" {
				a.AccountID = claims.ChatGPTAccountID
			}
		}
		if claims.PlanType != "" {
			a.PlanType = claims.PlanType
		}
	}
	a.LastRefresh = time.Now().UTC()
	a.Dead = false
	// Persist updated tokens back to disk so the pool stays consistent.
	defer a.mu.Unlock()
	return saveAccount(a)
}

// Gemini OAuth token endpoint
const geminiOAuthTokenURL = "https://oauth2.googleapis.com/token"

// geminiOAuthClientID returns the OAuth client ID for Gemini.
// Uses GEMINI_OAUTH_CLIENT_ID env var if set, otherwise the public Gemini CLI client ID.
func geminiOAuthClientID() string {
	if v := os.Getenv("GEMINI_OAUTH_CLIENT_ID"); v != "" {
		return v
	}
	// Public client ID from Gemini CLI (safe per OAuth 2.0 spec for installed apps)
	return "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j" + ".apps.googleusercontent.com"
}

// geminiOAuthClientSecret returns the OAuth client secret for Gemini.
// Uses GEMINI_OAUTH_CLIENT_SECRET env var if set, otherwise the public Gemini CLI client secret.
func geminiOAuthClientSecret() string {
	if v := os.Getenv("GEMINI_OAUTH_CLIENT_SECRET"); v != "" {
		return v
	}
	// Public client secret from Gemini CLI (safe per OAuth 2.0 spec for installed apps)
	return "GOCSPX-" + "4uHgMPm-1o7Sk-geV6Cu5clXFsxl"
}

func (h *proxyHandler) refreshGeminiAccount(ctx context.Context, a *Account, refreshTok string) error {
	// Google OAuth uses form-encoded body
	form := url.Values{}
	form.Set("client_id", geminiOAuthClientID())
	form.Set("client_secret", geminiOAuthClientSecret())
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshTok)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, geminiOAuthTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "codex-pool-proxy")

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		if len(bytes.TrimSpace(msg)) > 0 {
			return fmt.Errorf("gemini refresh unauthorized: %s: %s", resp.Status, safeText(msg))
		}
		return fmt.Errorf("gemini refresh unauthorized: %s", resp.Status)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		if len(bytes.TrimSpace(msg)) > 0 {
			return fmt.Errorf("gemini refresh failed: %s: %s", resp.Status, safeText(msg))
		}
		return fmt.Errorf("gemini refresh failed: %s", resp.Status)
	}

	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"` // seconds until expiry
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if payload.AccessToken == "" {
		return errors.New("empty access token after gemini refresh")
	}

	a.mu.Lock()
	a.AccessToken = payload.AccessToken
	if payload.RefreshToken != "" {
		a.RefreshToken = payload.RefreshToken
	}
	if payload.ExpiresIn > 0 {
		a.ExpiresAt = time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second)
	}
	a.LastRefresh = time.Now().UTC()
	a.Dead = false
	defer a.mu.Unlock()
	return saveAccount(a)
}

func (h *proxyHandler) startUsagePoller() {
	if h == nil || h.cfg.usageRefresh <= 0 {
		return
	}
	ticker := time.NewTicker(h.cfg.usageRefresh)
	go func() {
		for range ticker.C {
			h.refreshUsageIfStale()
		}
	}()
}

func (h *proxyHandler) refreshUsageIfStale() {
	now := time.Now()
	h.pool.mu.RLock()
	accs := append([]*Account{}, h.pool.accounts...)
	h.pool.mu.RUnlock()

	for _, a := range accs {
		if a == nil {
			continue
		}
		a.mu.Lock()
		dead := a.Dead
		hasToken := a.AccessToken != ""
		retrievedAt := a.Usage.RetrievedAt
		accType := a.Type
		a.mu.Unlock()
		// Skip Gemini accounts - they don't have WHAM usage endpoint
		if accType == AccountTypeGemini {
			continue
		}
		if dead || !hasToken {
			continue
		}
		if !retrievedAt.IsZero() && now.Sub(retrievedAt) < h.cfg.usageRefresh {
			continue
		}
		if err := h.fetchUsage(now, a); err != nil && h.cfg.debug {
			log.Printf("usage fetch %s failed: %v", a.ID, err)
		}
	}
}

func (h *proxyHandler) fetchUsage(now time.Time, a *Account) error {
	usageURL := buildWhamUsageURL(h.cfg.whamBase)
	doReq := func() (*http.Response, error) {
		req, _ := http.NewRequest(http.MethodGet, usageURL, nil)
		a.mu.Lock()
		access := a.AccessToken
		accountID := a.AccountID
		idTokID := a.IDTokenChatGPTAccountID
		a.mu.Unlock()
		req.Header.Set("Authorization", "Bearer "+access)
		chatgptHeaderID := accountID
		if chatgptHeaderID == "" {
			chatgptHeaderID = idTokID
		}
		if chatgptHeaderID != "" {
			req.Header.Set("ChatGPT-Account-ID", chatgptHeaderID)
		}
		return h.transport.RoundTrip(req)
	}

	resp, err := doReq()
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Try refresh once (unless disabled).
		if !h.cfg.disableRefresh && h.needsRefresh(a) {
			if err := h.refreshAccount(context.Background(), a); err == nil {
				resp.Body.Close()
				resp, err = doReq()
				if err != nil {
					return err
				}
				defer resp.Body.Close()
			}
		}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		a.mu.Lock()
		a.Penalty += 0.3
		a.mu.Unlock()
		return fmt.Errorf("usage unauthorized: %s", resp.Status)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("usage bad status: %s", resp.Status)
	}

	var payload struct {
		RateLimit struct {
			PrimaryWindow struct {
				UsedPercent float64 `json:"used_percent"`
			} `json:"primary_window"`
			SecondaryWindow struct {
				UsedPercent float64 `json:"used_percent"`
			} `json:"secondary_window"`
		} `json:"rate_limit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	whamSnap := UsageSnapshot{
		PrimaryUsed:          payload.RateLimit.PrimaryWindow.UsedPercent / 100.0,
		SecondaryUsed:        payload.RateLimit.SecondaryWindow.UsedPercent / 100.0,
		PrimaryUsedPercent:   payload.RateLimit.PrimaryWindow.UsedPercent / 100.0,
		SecondaryUsedPercent: payload.RateLimit.SecondaryWindow.UsedPercent / 100.0,
		RetrievedAt:          now,
		Source:               "wham",
	}
	a.mu.Lock()
	a.Usage = mergeUsage(a.Usage, whamSnap)
	a.mu.Unlock()
	return nil
}

func buildWhamUsageURL(base *url.URL) string {
	joined := singleJoin(base.Path, "/wham/usage")
	copy := *base
	copy.Path = joined
	copy.RawQuery = ""
	return copy.String()
}

func (h *proxyHandler) updateUsageFromHeaders(a *Account, hdr http.Header) {
	if a == nil {
		return
	}
	primaryStr := hdr.Get("X-Codex-Primary-Used-Percent")
	secondaryStr := hdr.Get("X-Codex-Secondary-Used-Percent")
	if primaryStr == "" && secondaryStr == "" {
		return
	}

	a.mu.Lock()
	snap := a.Usage
	snap.RetrievedAt = time.Now()
	snap.Source = "headers"

	if v := primaryStr; v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			snap.PrimaryUsedPercent = f / 100.0
			snap.PrimaryUsed = snap.PrimaryUsedPercent
		}
	}
	if v := secondaryStr; v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			snap.SecondaryUsedPercent = f / 100.0
			snap.SecondaryUsed = snap.SecondaryUsedPercent
		}
	}

	if v := hdr.Get("X-Codex-Primary-Window-Minutes"); v != "" {
		snap.PrimaryWindowMinutes, _ = strconv.Atoi(v)
	}
	if v := hdr.Get("X-Codex-Secondary-Window-Minutes"); v != "" {
		snap.SecondaryWindowMinutes, _ = strconv.Atoi(v)
	}

	if v := hdr.Get("X-Codex-Primary-Reset-At"); v != "" {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			snap.PrimaryResetAt = time.Unix(ts, 0)
		}
	}
	if v := hdr.Get("X-Codex-Secondary-Reset-At"); v != "" {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			snap.SecondaryResetAt = time.Unix(ts, 0)
		}
	}

	if v := hdr.Get("X-Codex-Credits-Balance"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			snap.CreditsBalance = f
		}
	}
	snap.HasCredits = strings.EqualFold(hdr.Get("X-Codex-Credits-Has-Credits"), "true")
	snap.CreditsUnlimited = strings.EqualFold(hdr.Get("X-Codex-Credits-Unlimited"), "true")

	a.Usage = mergeUsage(a.Usage, snap)
	a.mu.Unlock()
}

func (h *proxyHandler) updateUsageFromBody(a *Account, sample []byte) {
	if a == nil || len(sample) == 0 {
		return
	}
	lines := bytes.Split(sample, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			line = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		}
		var obj map[string]any
		if err := json.Unmarshal(line, &obj); err != nil {
			continue
		}
		if rl, ok := obj["rate_limit"].(map[string]any); ok {
			// convert to map[string]interface{} for applyRateLimitObject
			rl2 := map[string]any{}
			for k, v := range rl {
				rl2[k] = v
			}
			// account method expects map[string]interface{}
			converted := map[string]interface{}{}
			for k, v := range rl2 {
				converted[k] = v
			}
			a.applyRateLimitObject(converted)
			return
		}
		if resp, ok := obj["response"].(map[string]any); ok {
			if rl, ok := resp["rate_limit"].(map[string]any); ok {
				converted := map[string]interface{}{}
				for k, v := range rl {
					converted[k] = v
				}
				a.applyRateLimitObject(converted)
			}
			if ru := parseRequestUsage(resp); ru != nil {
				ru.AccountID = a.ID
				h.recordUsage(a, *ru)
			}
		}
		if ru := parseRequestUsage(obj); ru != nil {
			ru.AccountID = a.ID
			h.recordUsage(a, *ru)
		}
	}
}

func (h *proxyHandler) recordUsage(a *Account, ru RequestUsage) {
	if a == nil {
		return
	}
	a.applyRequestUsage(ru)
	if h.store != nil {
		_ = h.store.record(ru)
	}
}

func parseRequestUsage(obj map[string]any) *RequestUsage {
	usageMap, ok := obj["usage"].(map[string]any)
	if !ok {
		return nil
	}
	ru := &RequestUsage{Timestamp: time.Now()}
	ru.InputTokens = readInt64(usageMap, "input_tokens")
	ru.CachedInputTokens = readInt64(usageMap, "cached_input_tokens")
	if ru.CachedInputTokens == 0 {
		ru.CachedInputTokens = readInt64(usageMap, "cache_read_input_tokens")
	}
	ru.OutputTokens = readInt64(usageMap, "output_tokens")
	ru.BillableTokens = readInt64(usageMap, "billable_tokens")
	if ru.BillableTokens == 0 {
		ru.BillableTokens = ru.InputTokens - ru.CachedInputTokens + ru.OutputTokens
	}
	if ru.InputTokens == 0 && ru.OutputTokens == 0 && ru.BillableTokens == 0 {
		return nil
	}
	if v, ok := obj["prompt_cache_key"].(string); ok {
		ru.PromptCacheKey = v
	}
	return ru
}

func readInt64(m map[string]any, key string) int64 {
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case float64:
			return int64(t)
		case int64:
			return t
		case int:
			return int64(t)
		case json.Number:
			if n, err := t.Int64(); err == nil {
				return n
			}
		}
	}
	return 0
}

type limitedWriter struct {
	w io.Writer
	n int64
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.n <= 0 {
		return len(p), nil
	}
	if int64(len(p)) > lw.n {
		p = p[:lw.n]
	}
	n, err := lw.w.Write(p)
	lw.n -= int64(n)
	return len(p), err
}

type loggingReadCloser struct {
	io.ReadCloser
	onClose func()
}

func (rc *loggingReadCloser) Close() error {
	if rc.onClose != nil {
		rc.onClose()
	}
	return rc.ReadCloser.Close()
}

type flushWriter struct {
	w             http.ResponseWriter
	f             http.Flusher
	flushInterval time.Duration
	lastFlush     time.Time
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	now := time.Now()
	if fw.flushInterval <= 0 || fw.lastFlush.IsZero() || now.Sub(fw.lastFlush) >= fw.flushInterval {
		fw.f.Flush()
		fw.lastFlush = now
	}
	return n, err
}

func (fw *flushWriter) stop() {}

func randomID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

func safeText(b []byte) string {
	s := string(b)
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}

func respondJSON(w http.ResponseWriter, v any) {
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

// readBodyForReplay reads the full body into memory so we can retry requests across accounts.
// It also returns a bounded sample for logging.
func readBodyForReplay(body io.ReadCloser, wantSample bool, sampleLimit int64) (full []byte, sample []byte, err error) {
	if body == nil {
		return nil, nil, nil
	}
	defer body.Close()
	full, err = io.ReadAll(body)
	if err != nil {
		return nil, nil, err
	}
	if wantSample && sampleLimit > 0 {
		if int64(len(full)) > sampleLimit {
			sample = full[:sampleLimit]
		} else {
			sample = full
		}
	}
	return full, sample, nil
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vv := range h {
		cpy := make([]string, len(vv))
		copy(cpy, vv)
		out[k] = cpy
	}
	return out
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		dst.Del(k)
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// removeHopByHopHeaders strips headers that must not be forwarded by proxies.
func removeHopByHopHeaders(h http.Header) {
	// Strip any headers listed in the Connection header first.
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(textproto.CanonicalMIMEHeaderKey(f))
			}
		}
	}

	// Standard hop-by-hop headers.
	for _, k := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		h.Del(k)
	}
}
