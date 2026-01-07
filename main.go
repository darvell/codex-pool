package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

type config struct {
	listenAddr    string
	responsesBase *url.URL
	whamBase      *url.URL
	refreshBase   *url.URL
	geminiBase    *url.URL // Gemini CloudCode endpoint (for OAuth/Code Assist mode)
	geminiAPIBase *url.URL // Gemini API endpoint (for API key mode)
	claudeBase    *url.URL // Claude API endpoint
	poolDir       string

	disableRefresh bool

	debug          bool
	logBodies      bool
	bodyLogLimit   int64
	flushInterval  time.Duration
	usageRefresh   time.Duration
	maxAttempts    int
	storePath      string
	retentionDays  int
	friendCode     string
	requestTimeout time.Duration // Timeout for non-streaming requests (0 = no timeout)
	streamTimeout  time.Duration // Timeout for streaming/SSE requests (0 = no timeout)
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
	cfg.geminiAPIBase = mustParse(getenv("UPSTREAM_GEMINI_API_BASE", "https://generativelanguage.googleapis.com"))
	cfg.claudeBase = mustParse(getenv("UPSTREAM_CLAUDE_BASE", "https://api.anthropic.com"))
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
	cfg.friendCode = getConfigString("FRIEND_CODE", fileCfg.FriendCode, "")
	cfg.retentionDays = 30
	if v := getenv("PROXY_USAGE_RETENTION_DAYS", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n > 0 {
			cfg.retentionDays = int(n)
		}
	}

	// Request timeouts: default 2 min for regular requests, 30 min for streaming.
	// Set to 0 to disable timeout entirely (not recommended for non-streaming).
	cfg.requestTimeout = 2 * time.Minute
	if v := getenv("PROXY_REQUEST_TIMEOUT_SECONDS", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n >= 0 {
			cfg.requestTimeout = time.Duration(n) * time.Second
		}
	}
	cfg.streamTimeout = 30 * time.Minute // Long timeout for streaming - Claude Code sessions can be long
	if v := getenv("PROXY_STREAM_TIMEOUT_SECONDS", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n >= 0 {
			cfg.streamTimeout = time.Duration(n) * time.Second
		}
	}

	flag.StringVar(&cfg.listenAddr, "listen", cfg.listenAddr, "listen address")
	flag.Parse()
	return cfg
}

func main() {
	cfg := buildConfig()

	// Create provider registry
	codexProvider := NewCodexProvider(cfg.responsesBase, cfg.whamBase, cfg.refreshBase)
	claudeProvider := NewClaudeProvider(cfg.claudeBase)
	geminiProvider := NewGeminiProvider(cfg.geminiBase, cfg.geminiAPIBase)
	registry := NewProviderRegistry(codexProvider, claudeProvider, geminiProvider)

	log.Printf("loading pool from %s", cfg.poolDir)
	accounts, err := loadPool(cfg.poolDir, registry)
	if err != nil {
		log.Fatalf("load pool: %v", err)
	}
	pool := newPoolState(accounts, cfg.debug)
	codexCount := pool.countByType(AccountTypeCodex)
	claudeCount := pool.countByType(AccountTypeClaude)
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
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second, // TCP keepalives to prevent NAT/router timeouts
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0, // Disable - we handle timeouts per-request based on streaming
		ExpectContinueTimeout: 5 * time.Second,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
	}
	_ = http2.ConfigureTransport(transport)

	// Initialize pool users store if configured
	var poolUsers *PoolUserStore
	// Pool users require a JWT secret. Admin password is optional if friend code is used.
	if (getPoolAdminPassword() != "" || cfg.friendCode != "") && getPoolJWTSecret() != "" {
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
		registry:  registry,
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
		IdleTimeout:       5 * time.Minute, // Keep connections alive for reuse
	}

	// Configure HTTP/2 with settings optimized for long-running streams.
	http2Srv := &http2.Server{
		MaxConcurrentStreams:         250,
		IdleTimeout:                  5 * time.Minute,
		MaxUploadBufferPerConnection: 1 << 20,       // 1MB
		MaxUploadBufferPerStream:     1 << 20,       // 1MB
		MaxReadFrameSize:             1 << 20,       // 1MB
	}
	if err := http2.ConfigureServer(srv, http2Srv); err != nil {
		log.Printf("warning: failed to configure HTTP/2 server: %v", err)
	}

	log.Printf("codex-pool proxy listening on %s (codex=%d, claude=%d, gemini=%d, request_timeout=%v, stream_timeout=%v)",
		cfg.listenAddr, codexCount, claudeCount, geminiCount, cfg.requestTimeout, cfg.streamTimeout)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

type proxyHandler struct {
	cfg       config
	transport *http.Transport
	pool      *poolState
	poolUsers *PoolUserStore
	registry  *ProviderRegistry
	store     *usageStore
	metrics   *metrics
	recent    *recentErrors
	inflight  int64
	startTime time.Time

	// Rate limiting for token refresh operations
	refreshMu       sync.Mutex
	lastRefreshTime time.Time
}

// Note: ServeHTTP is now in router.go
// Note: Handler functions (serveHealth, serveAccounts, etc.) are now in handlers.go

func (h *proxyHandler) pickUpstream(path string, headers http.Header) (Provider, *url.URL) {
	// Check headers first - Anthropic requests have X-Api-Key or anthropic-* headers
	if headers.Get("X-Api-Key") != "" {
		// X-Api-Key is used by Anthropic Claude API
		provider := h.registry.ForType(AccountTypeClaude)
		return provider, provider.UpstreamURL(path)
	}
	// Check for any anthropic-* headers (version, beta, etc.)
	for key := range headers {
		if strings.HasPrefix(strings.ToLower(key), "anthropic-") {
			provider := h.registry.ForType(AccountTypeClaude)
			return provider, provider.UpstreamURL(path)
		}
	}

	// Fall back to path-based routing
	provider := h.registry.ForPath(path)
	if provider == nil {
		// Fallback to Codex provider
		provider = h.registry.ForType(AccountTypeCodex)
	}
	return provider, provider.UpstreamURL(path)
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
	// Check top-level keys (includes session_id for Gemini)
	for _, key := range []string{"conversation_id", "conversation", "prompt_cache_key", "session_id"} {
		if v, ok := obj[key].(string); ok && v != "" {
			return v
		}
	}
	// Some variants may tuck metadata under a sub-object.
	for _, containerKey := range []string{"metadata", "meta"} {
		if sub, ok := obj[containerKey].(map[string]any); ok {
			for _, key := range []string{"conversation_id", "conversation", "prompt_cache_key", "session_id"} {
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
	authHeader := r.Header.Get("Authorization")

	// Determine user ID - either from pool JWT, Claude pool token, or hashed IP
	var userID string
	var userType string // "pool_user", "passthrough", or "anonymous"
	secret := getPoolJWTSecret()

	// Check for Claude pool tokens first (sk-ant-api-pool-*)
	if secret != "" {
		if isClaudePool, uid := isClaudePoolToken(secret, authHeader); isClaudePool {
			userID = uid
			userType = "pool_user"
			// Check if user is disabled
			if h.poolUsers != nil {
				if user := h.poolUsers.Get(userID); user != nil && user.Disabled {
					http.Error(w, "pool user disabled", http.StatusForbidden)
					return
				}
			}
			if h.cfg.debug {
				log.Printf("[%s] claude pool user request: user_id=%s", reqID, userID)
			}
		}
	}

	// Check for Gemini API key pool tokens (AIzaSy-pool-*)
	if userID == "" && secret != "" {
		// Check x-goog-api-key header (Gemini API key mode)
		geminiAPIKey := r.Header.Get("x-goog-api-key")
		if geminiAPIKey == "" {
			// Also check query parameter
			geminiAPIKey = r.URL.Query().Get("key")
		}
		if geminiAPIKey != "" {
			if isPoolKey, uid, _ := isPoolGeminiAPIKey(secret, geminiAPIKey); isPoolKey {
				userID = uid
				userType = "pool_user"
				// Check if user is disabled
				if h.poolUsers != nil {
					if user := h.poolUsers.Get(userID); user != nil && user.Disabled {
						http.Error(w, "pool user disabled", http.StatusForbidden)
						return
					}
				}
				if h.cfg.debug {
					log.Printf("[%s] gemini api key pool user request: user_id=%s", reqID, userID)
				}
			}
		}
	}

	// Check for JWT-based pool tokens (Codex, Gemini OAuth)
	if userID == "" && secret != "" {
		if isPoolUser, uid, _ := isPoolUserToken(secret, authHeader); isPoolUser {
			userID = uid
			userType = "pool_user"
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
		}
	}

	// Check for Gemini OAuth pool tokens (ya29.pool-*)
	if userID == "" && secret != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if isPoolToken, uid := isGeminiOAuthPoolToken(secret, token); isPoolToken {
			userID = uid
			userType = "pool_user"
			// Check if user is disabled
			if h.poolUsers != nil {
				if user := h.poolUsers.Get(userID); user != nil && user.Disabled {
					http.Error(w, "pool user disabled", http.StatusForbidden)
					return
				}
			}
			if h.cfg.debug {
				log.Printf("[%s] gemini oauth pool user request: user_id=%s", reqID, userID)
			}
		}
	}

	// Check if this looks like a real provider credential that should be passed through
	// This allows users to use their own API keys while benefiting from the proxy infrastructure
	if userID == "" {
		if isProviderCred, providerType := looksLikeProviderCredential(authHeader); isProviderCred {
			if h.cfg.debug {
				log.Printf("[%s] pass-through request with %s credential", reqID, providerType)
			}
			h.proxyPassthrough(w, r, reqID, providerType, start)
			return
		}
	}

	// If not a pool user, hash their IP for anonymous tracking
	if userID == "" {
		ip := getClientIP(r)
		salt := h.cfg.friendCode
		if salt == "" {
			salt = "codex-pool"
		}
		userID = hashUserIP(ip, salt)
		userType = "anonymous"
	}
	// Store userType in request context for whoami endpoint
	_ = userType

	provider, targetBase := h.pickUpstream(r.URL.Path, r.Header)
	if provider == nil || targetBase == nil {
		http.Error(w, "no upstream for path", http.StatusNotFound)
		return
	}
	accountType := provider.Type()

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
		log.Printf("[%s] incoming %s %s provider=%s conv_id=%s authZ_len=%d chatgpt-id=%q content-type=%q content-encoding=%q body_bytes=%d",
			reqID,
			r.Method,
			r.URL.Path,
			accountType,
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

	// Use much longer timeout for streaming requests to support long-running operations.
	// Streaming requests are identified by Accept: text/event-stream header.
	isStreamingRequest := strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream")
	timeout := h.cfg.requestTimeout
	if isStreamingRequest && h.cfg.streamTimeout > 0 {
		timeout = h.cfg.streamTimeout
	}

	ctx := r.Context()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	attempts := h.cfg.maxAttempts
	if attempts <= 0 {
		attempts = 1
	}
	// Try at least all accounts of this type, up to configured max
	if n := h.pool.countByType(accountType); n > attempts {
		attempts = n
	}
	// But don't exceed total pool size
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

		resp, sampleBuf, refreshFailed, err := h.tryOnce(ctx, r, bodyBytes, targetBase, provider, acc, reqID)

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
				// Only mark as dead if we couldn't refresh (no refresh token or refresh failed)
				// If refresh succeeded but we still got 401/403, just add penalty - might be transient
				if refreshFailed {
					acc.Dead = true
					acc.Penalty += 1.0
					if h.cfg.debug {
						log.Printf("[%s] marking account %s as dead (401/403, refresh failed or unavailable)", reqID, acc.ID)
					}
					acc.mu.Unlock()
					if err := saveAccount(acc); err != nil {
						log.Printf("[%s] warning: failed to save dead account %s: %v", reqID, acc.ID, err)
					}
				} else {
					// Refresh was rate-limited or not needed but we still got 401/403
					// Add heavy penalty so this account drops below working ones
					acc.Penalty += 10.0
					if h.cfg.debug {
						log.Printf("[%s] account %s got 401/403, adding heavy penalty (not marking dead)", reqID, acc.ID)
					}
					acc.mu.Unlock()
				}
			} else {
				acc.mu.Lock()
				acc.Penalty += 0.3
				acc.mu.Unlock()
			}
			lastErr = fmt.Errorf("upstream %s", resp.Status)
			h.recent.add(lastErr.Error())
			resp.Body.Close()
			if h.cfg.debug {
				log.Printf("[%s] attempt %d/%d account=%s retryable status=%d refreshFailed=%v", reqID, attempt, attempts, acc.ID, resp.StatusCode, refreshFailed)
			}
			continue
		}

		provider.ParseUsageHeaders(acc, resp.Header)

		// Write response to client.
		copyHeader(w.Header(), resp.Header)
		removeHopByHopHeaders(w.Header())
		// Replace individual account usage headers with pool aggregate usage
		h.replaceUsageHeaders(w.Header())
		w.WriteHeader(resp.StatusCode)

		flusher, _ := w.(http.Flusher)
		respContentType := resp.Header.Get("Content-Type")
		// Use provider's SSE detection logic
		isSSE := provider.DetectsSSE(r.URL.Path, respContentType)
		if h.cfg.debug {
			log.Printf("[%s] response: isSSE=%v content-type=%s", reqID, isSSE, respContentType)
		}

		// Stream body while optionally flushing.
		var writer io.Writer = w
		var fw *flushWriter
		if isSSE && flusher != nil {
			fw = &flushWriter{w: w, f: flusher, flushInterval: h.cfg.flushInterval}
			writer = fw
		}

		// For SSE streams, intercept usage events inline as they flow through
		if isSSE {
			writer = &sseInterceptWriter{
				w: writer,
				callback: func(data []byte) {
					// Parse the JSON event data - try object first, then array
					var obj map[string]any
					if err := json.Unmarshal(data, &obj); err != nil {
						// Try parsing as array (Gemini sends [{"candidates":..., "usageMetadata":...}])
						var arr []map[string]any
						if err2 := json.Unmarshal(data, &arr); err2 != nil || len(arr) == 0 {
							if h.cfg.debug {
								log.Printf("[%s] SSE callback: failed to parse JSON: %v", reqID, err)
							}
							return
						}
						obj = arr[0] // Use first element
					}
					// Use provider's ParseUsage method
					ru := provider.ParseUsage(obj)
					if ru == nil {
						return
					}
					ru.AccountID = acc.ID
					ru.UserID = userID
					acc.mu.Lock()
					ru.PlanType = acc.PlanType
					acc.mu.Unlock()
					h.recordUsage(acc, *ru)
				},
			}
		}

		_, copyErr := io.Copy(writer, resp.Body)
		resp.Body.Close()
		if fw != nil {
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
		// Still try to parse sample for non-SSE responses or fallback
		if !isSSE && len(respSample) > 0 {
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
		// Successful request - decay penalty faster (proves account works)
		if acc.Penalty > 0 {
			acc.Penalty *= 0.5
			if acc.Penalty < 0.01 {
				acc.Penalty = 0
			}
		}
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

// looksLikeProviderCredential checks if a token looks like a real provider credential
// that should be passed through directly rather than replaced with pool credentials.
func looksLikeProviderCredential(authHeader string) (bool, AccountType) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false, ""
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return false, ""
	}

	// Pool-generated Claude tokens: sk-ant-api-pool-* should NOT be passed through
	// These are fake API keys that identify pool users
	if strings.HasPrefix(token, ClaudePoolTokenPrefix) {
		return false, ""
	}

	// Claude/Anthropic API keys: sk-ant-api* or sk-ant-oat* (OAuth tokens)
	if strings.HasPrefix(token, "sk-ant-") {
		return true, AccountTypeClaude
	}

	// OpenAI-style API keys: sk-proj-*, sk-* (but not sk-ant-)
	if strings.HasPrefix(token, "sk-proj-") || (strings.HasPrefix(token, "sk-") && !strings.HasPrefix(token, "sk-ant-")) {
		return true, AccountTypeCodex
	}

	// Google OAuth tokens typically start with ya29. (access tokens)
	// But NOT pool tokens which are ya29.pool-*
	if strings.HasPrefix(token, "ya29.") && !strings.HasPrefix(token, "ya29.pool-") {
		return true, AccountTypeGemini
	}

	return false, ""
}

// isClaudePoolToken checks if the auth header contains a pool-generated Claude token.
// Returns (isPoolToken, userID) if valid.
func isClaudePoolToken(secret, authHeader string) (bool, string) {
	if secret == "" {
		return false, ""
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false, ""
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	userID, valid := parseClaudePoolToken(secret, token)
	return valid, userID
}

// proxyPassthrough handles requests where the user provides their own credentials.
// The request is proxied directly to the upstream without using pool accounts.
func (h *proxyHandler) proxyPassthrough(w http.ResponseWriter, r *http.Request, reqID string, providerType AccountType, start time.Time) {
	provider := h.registry.ForType(providerType)
	if provider == nil {
		// Fallback: try to detect from path and headers
		provider, _ = h.pickUpstream(r.URL.Path, r.Header)
	}
	if provider == nil {
		http.Error(w, "unknown provider", http.StatusBadRequest)
		return
	}

	targetBase := provider.UpstreamURL(r.URL.Path)
	bodyBytes, bodySample, err := readBodyForReplay(r.Body, h.cfg.logBodies, h.cfg.bodyLogLimit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if h.cfg.debug {
		log.Printf("[%s] passthrough %s %s provider=%s content-type=%q body_bytes=%d",
			reqID, r.Method, r.URL.Path, providerType,
			r.Header.Get("Content-Type"), len(bodyBytes))
		// Debug: log all headers for Claude passthrough
		if providerType == AccountTypeClaude {
			var hdrs []string
			for k, v := range r.Header {
				if strings.HasPrefix(strings.ToLower(k), "anthropic") {
					hdrs = append(hdrs, fmt.Sprintf("%s=%s", k, v[0]))
				}
			}
			log.Printf("[%s] passthrough claude anthropic headers: %v", reqID, hdrs)
		}
	}
	if h.cfg.logBodies && len(bodySample) > 0 {
		log.Printf("[%s] passthrough request body sample (%d bytes): %s", reqID, len(bodySample), safeText(bodySample))
	}

	// Determine timeout
	isStreamingRequest := strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream")
	timeout := h.cfg.requestTimeout
	if isStreamingRequest && h.cfg.streamTimeout > 0 {
		timeout = h.cfg.streamTimeout
	}

	ctx := r.Context()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Build the outgoing request - preserving the original Authorization header
	outURL := new(url.URL)
	*outURL = *r.URL
	outURL.Scheme = targetBase.Scheme
	outURL.Host = targetBase.Host
	outURL.Path = singleJoin(targetBase.Path, provider.NormalizePath(r.URL.Path))

	var body io.Reader
	if len(bodyBytes) > 0 {
		body = bytes.NewReader(bodyBytes)
	}
	outReq, err := http.NewRequestWithContext(ctx, r.Method, outURL.String(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	outReq.Host = targetBase.Host
	outReq.Header = cloneHeader(r.Header)
	removeHopByHopHeaders(outReq.Header)

	// Keep the original Authorization header (don't delete it like we do for pool requests)
	// Remove Cloudflare/proxy headers that would cause issues
	outReq.Header.Del("Cdn-Loop")
	outReq.Header.Del("Cf-Connecting-Ip")
	outReq.Header.Del("Cf-Ray")
	outReq.Header.Del("Cf-Visitor")
	outReq.Header.Del("Cf-Warp-Tag-Id")
	outReq.Header.Del("Cf-Ipcountry")
	outReq.Header.Del("X-Forwarded-For")
	outReq.Header.Del("X-Forwarded-Proto")
	outReq.Header.Del("X-Real-Ip")

	// For Claude, ensure required headers are set
	if providerType == AccountTypeClaude {
		if outReq.Header.Get("anthropic-version") == "" {
			outReq.Header.Set("anthropic-version", "2023-06-01")
		}
	}

	if h.cfg.debug {
		log.Printf("[%s] passthrough -> %s %s", reqID, outReq.Method, outReq.URL.String())
	}

	// Full dump for Claude passthrough requests
	if providerType == AccountTypeClaude {
		log.Printf("[%s] === CLAUDE PASSTHROUGH FULL DUMP ===", reqID)
		log.Printf("[%s] URL: %s", reqID, outReq.URL.String())
		for k, v := range outReq.Header {
			for _, val := range v {
				if len(val) > 100 {
					log.Printf("[%s] Header %s: %s...(truncated)", reqID, k, val[:100])
				} else {
					log.Printf("[%s] Header %s: %s", reqID, k, val)
				}
			}
		}
		log.Printf("[%s] === END DUMP ===", reqID)
	}

	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		h.recent.add(err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Write response to client
	copyHeader(w.Header(), resp.Header)
	removeHopByHopHeaders(w.Header())
	w.WriteHeader(resp.StatusCode)

	flusher, _ := w.(http.Flusher)
	respContentType := resp.Header.Get("Content-Type")
	isSSE := provider.DetectsSSE(r.URL.Path, respContentType)

	var writer io.Writer = w
	if isSSE && flusher != nil {
		fw := &flushWriter{w: w, f: flusher, flushInterval: h.cfg.flushInterval}
		writer = fw
		defer fw.stop()
	}

	if _, copyErr := io.Copy(writer, resp.Body); copyErr != nil {
		h.recent.add(copyErr.Error())
		h.metrics.inc("error", "passthrough")
		return
	}

	h.metrics.inc(strconv.Itoa(resp.StatusCode), "passthrough")

	if h.cfg.debug {
		log.Printf("[%s] passthrough done status=%d duration_ms=%d", reqID, resp.StatusCode, time.Since(start).Milliseconds())
	}
}

func (h *proxyHandler) tryOnce(
	ctx context.Context,
	in *http.Request,
	bodyBytes []byte,
	targetBase *url.URL,
	provider Provider,
	acc *Account,
	reqID string,
) (*http.Response, *bytes.Buffer, bool, error) { // Added refreshFailed return value
	if acc == nil {
		return nil, nil, false, errors.New("nil account")
	}
	refreshFailed := false // Track if refresh was attempted but failed

	if !h.cfg.disableRefresh && h.needsRefresh(acc) {
		if err := h.refreshAccount(ctx, acc); err != nil && h.cfg.debug {
			log.Printf("[%s] refresh %s failed: %v (continuing with existing token)", reqID, acc.ID, err)
		}
	}

	outURL := new(url.URL)
	*outURL = *in.URL
	outURL.Scheme = targetBase.Scheme
	outURL.Host = targetBase.Host
	// Use provider's NormalizePath method for path handling
	outURL.Path = singleJoin(targetBase.Path, provider.NormalizePath(in.URL.Path))

	// For Claude OAuth tokens, add beta=true query param (required for OAuth to work)
	if provider.Type() == AccountTypeClaude && strings.HasPrefix(acc.AccessToken, "sk-ant-oat") {
		q := outURL.Query()
		q.Set("beta", "true")
		outURL.RawQuery = q.Encode()
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
		outReq.Header.Del("X-Api-Key") // Remove Claude API key from client (might be pool token)

		// Remove Cloudflare/proxy headers that would cause issues with OpenAI's Cloudflare
		outReq.Header.Del("Cdn-Loop")
		outReq.Header.Del("Cf-Connecting-Ip")
		outReq.Header.Del("Cf-Ray")
		outReq.Header.Del("Cf-Visitor")
		outReq.Header.Del("Cf-Warp-Tag-Id")
		outReq.Header.Del("Cf-Ipcountry")
		outReq.Header.Del("X-Forwarded-For")
		outReq.Header.Del("X-Forwarded-Proto")
		outReq.Header.Del("X-Real-Ip")
		// Remove Gemini API key header (we use Bearer auth for pool accounts)
		outReq.Header.Del("x-goog-api-key")

		acc.mu.Lock()
		access := acc.AccessToken
		acc.mu.Unlock()

		if access == "" {
			return nil, fmt.Errorf("account %s has empty access token", acc.ID)
		}

		// Use provider's SetAuthHeaders method for provider-specific auth
		provider.SetAuthHeaders(outReq, acc)

		// Debug: log outgoing headers for Claude OAuth
		if h.cfg.debug && provider.Type() == AccountTypeClaude && strings.HasPrefix(acc.AccessToken, "sk-ant-oat") {
			var hdrs []string
			for k, v := range outReq.Header {
				if strings.HasPrefix(strings.ToLower(k), "anthropic") || strings.HasPrefix(strings.ToLower(k), "x-stainless") || strings.ToLower(k) == "authorization" {
					val := v[0]
					if len(val) > 30 {
						val = val[:30]
					}
					hdrs = append(hdrs, fmt.Sprintf("%s=%s", k, val))
				}
			}
			log.Printf("[%s] claude oauth outgoing headers: %v", reqID, hdrs)
		}

		// Keep the original User-Agent from the client - don't override it
		return outReq, nil
	}

	outReq, err := buildReq()
	if err != nil {
		return nil, nil, false, err
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
		return nil, nil, false, err
	}

	// If we got a 401/403, try to refresh and retry on the *same* account once.
	if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && !h.cfg.disableRefresh {
		// Log the error response body for debugging
		if h.cfg.debug {
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			// Try to decompress if gzip
			decompressed := bodyForInspection(nil, errBody)
			log.Printf("[%s] got %d from upstream, body: %s", reqID, resp.StatusCode, safeText(decompressed))
		}
		acc.mu.Lock()
		hasRefresh := acc.RefreshToken != ""
		acc.mu.Unlock()
		if hasRefresh {
			_ = resp.Body.Close()
			if err := h.refreshAccount(ctx, acc); err == nil {
				outReq, err = buildReq()
				if err != nil {
					return nil, nil, false, err
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
					return nil, nil, false, err
				}
				// Log response after retry
				if h.cfg.debug && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
					errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
					decompressed := bodyForInspection(nil, errBody)
					log.Printf("[%s] after refresh retry got %d, body: %s", reqID, resp.StatusCode, safeText(decompressed))
					// Recreate body for downstream processing
					resp.Body = io.NopCloser(bytes.NewReader(errBody))
				}
				// Refresh succeeded - if we still get 401/403 after refresh,
				// the account is truly dead (fresh token still rejected)
			} else {
				errStr := err.Error()
				// If refresh token is permanently invalid, mark account as dead immediately
				if strings.Contains(errStr, "invalid_grant") || strings.Contains(errStr, "refresh_token_reused") {
					acc.mu.Lock()
					acc.Dead = true
					acc.Penalty += 100.0
					acc.mu.Unlock()
					log.Printf("[%s] marking account %s as dead: refresh token revoked/invalid", reqID, acc.ID)
					if err := saveAccount(acc); err != nil {
						log.Printf("[%s] warning: failed to save dead account %s: %v", reqID, acc.ID, err)
					}
					refreshFailed = true
				} else if !strings.Contains(errStr, "rate limited") {
					// Other non-rate-limited failures also count as refresh failed
					refreshFailed = true
				}
				if h.cfg.debug {
					log.Printf("[%s] refresh failed for %s: %v (refreshFailed=%v)", reqID, acc.ID, err, refreshFailed)
				}
			}
		} else {
			// No refresh token available - can't recover from 401/403
			refreshFailed = true
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
	return resp, buf, refreshFailed, nil
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

	// Per-account rate limiting: don't refresh too frequently
	// This prevents hammering the OAuth endpoint when refresh tokens are invalid
	if !a.LastRefresh.IsZero() && now.Sub(a.LastRefresh) < refreshPerAccountInterval {
		return false
	}

	// Only refresh if token is ACTUALLY expired (not "about to expire")
	// This is more conservative - we only refresh when we know the token won't work
	if !a.ExpiresAt.IsZero() && a.ExpiresAt.Before(now) {
		return true
	}
	// If no expiry time known, refresh after 12 hours since last refresh
	if a.ExpiresAt.IsZero() && !a.LastRefresh.IsZero() && now.Sub(a.LastRefresh) > 12*time.Hour {
		return true
	}
	return false
}

// refreshMinInterval is the minimum time between ANY refresh attempts globally
const refreshMinInterval = 5 * time.Second

// refreshPerAccountInterval is the minimum time between refresh attempts for a single account
// This is persisted to disk and survives restarts, preventing hammering OAuth endpoints
// 15 minutes balances between preventing hammering and allowing recovery from expired tokens
const refreshPerAccountInterval = 15 * time.Minute

func (h *proxyHandler) refreshAccount(ctx context.Context, a *Account) error {
	if a == nil {
		return errors.New("nil account")
	}

	// Per-account rate limiting (persisted to disk via LastRefresh)
	a.mu.Lock()
	sinceLastRefresh := time.Since(a.LastRefresh)
	if !a.LastRefresh.IsZero() && sinceLastRefresh < refreshPerAccountInterval {
		a.mu.Unlock()
		return fmt.Errorf("account refresh rate limited (%s), wait %v", a.ID, refreshPerAccountInterval-sinceLastRefresh)
	}
	accType := a.Type
	a.mu.Unlock()

	// Global rate limit - max 1 refresh globally every 5 seconds
	h.refreshMu.Lock()
	elapsed := time.Since(h.lastRefreshTime)
	if elapsed < refreshMinInterval {
		h.refreshMu.Unlock()
		return fmt.Errorf("refresh rate limited, wait %v", refreshMinInterval-elapsed)
	}
	h.lastRefreshTime = time.Now()
	h.refreshMu.Unlock()

	// Use the provider's RefreshToken method
	provider := h.registry.ForType(accType)
	if provider == nil {
		return fmt.Errorf("no provider for account type %s", accType)
	}
	err := provider.RefreshToken(ctx, a, h.transport)

	// On FAILED refresh, still update LastRefresh and save to prevent retrying for 1 hour
	// Successful refreshes already update LastRefresh in the provider
	if err != nil {
		a.mu.Lock()
		a.LastRefresh = time.Now().UTC()
		a.mu.Unlock()
		// Save to disk so rate limiting persists across restarts
		if saveErr := saveAccount(a); saveErr != nil {
			log.Printf("warning: failed to save account %s after refresh failure: %v", a.ID, saveErr)
		}
	}

	return err
}

// Note: Account refresh logic is now in the provider files:
// - provider_codex.go: CodexProvider.RefreshToken
// - provider_claude.go: ClaudeProvider.RefreshToken
// - provider_gemini.go: GeminiProvider.RefreshToken

// Note: Usage tracking functions are now in usage_tracking.go:
// - startUsagePoller, refreshUsageIfStale, fetchUsage, buildWhamUsageURL
// - DailyBreakdownDay, fetchDailyBreakdownData, replaceUsageHeaders

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
		if bytes.Equal(line, []byte("[DONE]")) {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal(line, &obj); err != nil {
			continue
		}

		// Handle Codex token_count events: {type: "token_count", info: {...}, rate_limits: {...}}
		if objType, _ := obj["type"].(string); objType == "token_count" {
			ru := parseTokenCountEvent(obj)
			if ru != nil {
				ru.AccountID = a.ID
				a.mu.Lock()
				ru.PlanType = a.PlanType
				a.mu.Unlock()
				h.recordUsage(a, *ru)
			}
			// Also apply rate limits from token_count
			if rl, ok := obj["rate_limits"].(map[string]any); ok {
				a.applyRateLimitsFromTokenCount(rl)
			}
			continue
		}

		// Legacy: rate_limit at top level
		if rl, ok := obj["rate_limit"].(map[string]any); ok {
			converted := map[string]interface{}{}
			for k, v := range rl {
				converted[k] = v
			}
			a.applyRateLimitObject(converted)
		}

		// Legacy: response object with usage
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
				a.mu.Lock()
				ru.PlanType = a.PlanType
				a.mu.Unlock()
				h.recordUsage(a, *ru)
			}
		}

		// Legacy: direct usage object
		if ru := parseRequestUsage(obj); ru != nil {
			ru.AccountID = a.ID
			a.mu.Lock()
			ru.PlanType = a.PlanType
			a.mu.Unlock()
			h.recordUsage(a, *ru)
		}
	}
}
