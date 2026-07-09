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

	"github.com/coder/websocket"
	"github.com/google/uuid"
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
	kimiBase      *url.URL // Kimi API endpoint
	minimaxBase   *url.URL // MiniMax API endpoint
	zaiBase       *url.URL // Z.ai Anthropic-compatible endpoint
	xiaomiBase    *url.URL // Xiaomi MiMo Token Plan Anthropic-compatible endpoint
	grokBase      *url.URL // Grok Code OpenAI-compatible endpoint
	poolDir       string

	disableRefresh  bool
	refreshProxyURL string // HTTP proxy URL for refresh operations

	debug                      atomic.Bool
	logBodies                  bool
	bodyLogLimit               int64
	claudeTraceDir             string
	claudeTraceBodyLimit       int64
	claudeTraceSecrets         bool
	maxInMemoryBodyBytes       int64
	flushInterval              time.Duration
	usageRefresh               time.Duration
	maxAttempts                int
	storePath                  string
	retentionDays              int
	friendCode                 string
	adminToken                 string
	requestTimeout             time.Duration // Timeout for non-streaming requests (0 = no timeout)
	streamTimeout              time.Duration // Timeout for streaming/SSE requests (0 = no timeout)
	streamIdleTimeout          time.Duration // Kill SSE streams idle for this long (0 = no idle timeout)
	websocketIdleTimeout       time.Duration // Kill websocket relays idle for this long (0 = no idle timeout)
	websocketHeartbeatInterval time.Duration // Send downstream app-level websocket heartbeats this often (0 = disabled)
	websocketReadLimit         int64         // Maximum websocket message size
	websocketCompression       bool          // Enable per-message websocket compression (off by default for latency)
	tierThreshold              float64       // Secondary usage % at which we stop preferring a tier (default 0.50)
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

func parseBoolEnv(key string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return def
	}
}

// Global config file reference for pool users config
var globalConfigFile *ConfigFile

func buildConfig() *config {
	cfg := &config{}
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

	cfg.listenAddr = getConfigString("PROXY_LISTEN_ADDR", fileCfg.ListenAddr, "127.0.0.1:8989")
	cfg.responsesBase = mustParse(getenv("UPSTREAM_RESPONSES_BASE", "https://chatgpt.com/backend-api/codex"))
	cfg.whamBase = mustParse(getenv("UPSTREAM_WHAM_BASE", "https://chatgpt.com/backend-api"))
	cfg.refreshBase = mustParse(getenv("UPSTREAM_REFRESH_BASE", "https://auth.openai.com"))
	cfg.geminiBase = mustParse(getenv("UPSTREAM_GEMINI_BASE", "https://cloudcode-pa.googleapis.com"))
	cfg.geminiAPIBase = mustParse(getenv("UPSTREAM_GEMINI_API_BASE", "https://generativelanguage.googleapis.com"))
	cfg.claudeBase = mustParse(getenv("UPSTREAM_CLAUDE_BASE", "https://api.anthropic.com"))
	cfg.kimiBase = mustParse(getenv("UPSTREAM_KIMI_BASE", "https://api.kimi.com/coding"))
	cfg.minimaxBase = mustParse(getenv("UPSTREAM_MINIMAX_BASE", "https://api.minimax.io/anthropic"))
	cfg.zaiBase = mustParse(getenv("UPSTREAM_ZAI_BASE", "https://api.z.ai/api/anthropic"))
	cfg.xiaomiBase = mustParse(getenv("UPSTREAM_XIAOMI_BASE", "https://token-plan-sgp.xiaomimimo.com/anthropic"))
	cfg.grokBase = mustParse(getConfigString("UPSTREAM_GROK_BASE", fileCfg.GrokBase, "https://cli-chat-proxy.grok.com/v1"))
	cfg.poolDir = getConfigString("POOL_DIR", fileCfg.PoolDir, "pool")

	// Refresh often fails for some auth.json fixtures; allow opting out.
	cfg.disableRefresh = getConfigBool("PROXY_DISABLE_REFRESH", fileCfg.DisableRefresh, false)
	cfg.refreshProxyURL = getConfigString("REFRESH_PROXY_URL", fileCfg.RefreshProxyURL, "")

	cfg.debug.Store(getConfigBool("PROXY_DEBUG", fileCfg.Debug, false))
	cfg.logBodies = getenv("PROXY_LOG_BODIES", "0") == "1"
	cfg.bodyLogLimit = 16 * 1024 // 16 KiB
	if v := getenv("PROXY_BODY_LOG_LIMIT", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n > 0 {
			cfg.bodyLogLimit = n
		}
	}
	cfg.claudeTraceDir = strings.TrimSpace(getenv("PROXY_CLAUDE_TRACE_DIR", ""))
	cfg.claudeTraceBodyLimit = 256 * 1024
	if v := getenv("PROXY_CLAUDE_TRACE_BODY_LIMIT", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n > 0 {
			cfg.claudeTraceBodyLimit = n
		}
	}
	cfg.claudeTraceSecrets = getenv("PROXY_CLAUDE_TRACE_INCLUDE_SECRETS", "0") == "1"
	cfg.maxInMemoryBodyBytes = 16 * 1024 * 1024 // 16 MiB
	if v := getenv("PROXY_MAX_INMEM_BODY_BYTES", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n >= 0 {
			cfg.maxInMemoryBodyBytes = n
		}
	}
	cfg.flushInterval = 0
	if v := getenv("PROXY_FLUSH_INTERVAL_MS", ""); v != "" {
		if ms, err := parseInt64(v); err == nil && ms >= 0 {
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
	cfg.adminToken = getConfigString("ADMIN_TOKEN", fileCfg.AdminToken, "")
	cfg.retentionDays = 30
	if v := getenv("PROXY_USAGE_RETENTION_DAYS", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n > 0 {
			cfg.retentionDays = int(n)
		}
	}

	// Request and stream timeouts default to disabled so long-running jobs can finish.
	// Set a positive value to enable a hard timeout.
	cfg.requestTimeout = 0
	if v := getenv("PROXY_REQUEST_TIMEOUT_SECONDS", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n >= 0 {
			cfg.requestTimeout = time.Duration(n) * time.Second
		}
	}
	cfg.streamTimeout = 0
	if v := getenv("PROXY_STREAM_TIMEOUT_SECONDS", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n >= 0 {
			cfg.streamTimeout = time.Duration(n) * time.Second
		}
	}
	cfg.streamIdleTimeout = 0
	if v := getenv("STREAM_IDLE_TIMEOUT_SECONDS", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n >= 0 {
			cfg.streamIdleTimeout = time.Duration(n) * time.Second
		}
	}
	cfg.websocketIdleTimeout = 0
	if v := getenv("WEBSOCKET_IDLE_TIMEOUT_SECONDS", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n >= 0 {
			cfg.websocketIdleTimeout = time.Duration(n) * time.Second
		}
	}
	cfg.websocketHeartbeatInterval = heartbeatInterval
	if v := getenv("WEBSOCKET_HEARTBEAT_SECONDS", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n >= 0 {
			cfg.websocketHeartbeatInterval = time.Duration(n) * time.Second
		}
	}
	cfg.websocketReadLimit = 64 * 1024 * 1024
	if v := getenv("WEBSOCKET_READ_LIMIT_BYTES", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n > 0 {
			cfg.websocketReadLimit = n
		}
	}
	cfg.websocketCompression = parseBoolEnv("WEBSOCKET_COMPRESSION", false)

	// Tier threshold: secondary usage % at which we stop preferring a tier (default 50%)
	cfg.tierThreshold = getConfigFloat64("TIER_THRESHOLD", fileCfg.TierThreshold, 0.50)

	flag.StringVar(&cfg.listenAddr, "listen", cfg.listenAddr, "listen address")
	flag.Parse()
	return cfg
}

func main() {
	cfg := buildConfig()
	startCodexFingerprintUpdater()

	// Create provider registry
	codexProvider := NewCodexProvider(cfg.responsesBase, cfg.whamBase, cfg.refreshBase)
	claudeProvider := NewClaudeProvider(cfg.claudeBase)
	geminiProvider := NewGeminiProvider(cfg.geminiBase, cfg.geminiAPIBase)
	kimiProvider := NewKimiProvider(cfg.kimiBase)
	minimaxProvider := NewMinimaxProvider(cfg.minimaxBase)
	zaiProvider := NewZAIProvider(cfg.zaiBase)
	xiaomiProvider := NewXiaomiProvider(cfg.xiaomiBase)
	grokProvider := NewGrokProvider(cfg.grokBase)
	registry := NewProviderRegistry(codexProvider, claudeProvider, geminiProvider, kimiProvider, minimaxProvider, zaiProvider, xiaomiProvider, grokProvider)

	log.Printf("loading pool from %s", cfg.poolDir)
	accounts, err := loadPool(cfg.poolDir, registry)
	if err != nil {
		log.Fatalf("load pool: %v", err)
	}
	pool := newPoolState(accounts, cfg.debug.Load())
	pool.tierThreshold = cfg.tierThreshold
	codexCount := pool.countByType(AccountTypeCodex)
	claudeCount := pool.countByType(AccountTypeClaude)
	geminiCount := pool.countByType(AccountTypeGemini)
	kimiCount := pool.countByType(AccountTypeKimi)
	minimaxCount := pool.countByType(AccountTypeMinimax)
	zaiCount := pool.countByType(AccountTypeZAI)
	xiaomiCount := pool.countByType(AccountTypeXiaomi)
	grokCount := pool.countByType(AccountTypeGrok)
	if pool.count() == 0 {
		log.Printf("warning: loaded 0 accounts from %s", cfg.poolDir)
	}

	store, err := newUsageStore(cfg.storePath, cfg.retentionDays)
	if err != nil {
		log.Fatalf("open usage store: %v", err)
	}
	defer store.Close()

	// Restore persisted usage totals from BoltDB
	if persisted, err := store.loadAllAccountUsage(); err == nil && len(persisted) > 0 {
		pool.mu.RLock()
		restored := 0
		for _, a := range pool.accounts {
			if usage, ok := persisted[a.ID]; ok {
				a.mu.Lock()
				a.Totals = usage
				a.mu.Unlock()
				restored++
			}
		}
		pool.mu.RUnlock()
		log.Printf("restored usage totals for %d/%d accounts from disk", restored, len(persisted))
	}

	standardTransport := &http.Transport{
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
	_ = http2.ConfigureTransport(standardTransport)

	// Default to the standard Go transport. Set CODEX_TLS_FINGERPRINT=rustls to opt
	// into the experimental uTLS/rustls hybrid transport for ChatGPT/Auth hosts.
	// Set CODEX_TLS_FINGERPRINT=bun for Bun 1.3.12 fingerprint (Anthropic traffic only).
	var transport http.RoundTripper = standardTransport
	switch strings.ToLower(os.Getenv("CODEX_TLS_FINGERPRINT")) {
	case "rustls":
		transport = newRustlsHybridTransport(standardTransport)
		log.Printf("codex rustls/uTLS hybrid transport enabled")
	case "bun":
		transport = newBunHybridTransport(standardTransport)
		log.Printf("bun/uTLS hybrid transport enabled (Anthropic traffic only)")
	case "bun-all":
		transport = createBunTransport()
		log.Printf("bun/uTLS transport enabled (all traffic)")
	}

	// CODEX_ANTHROPIC_PROXY_URL routes Anthropic API traffic through a proxy
	// so it appears to originate from a different IP. Other traffic goes direct.
	if anthropicProxy := os.Getenv("CODEX_ANTHROPIC_PROXY_URL"); anthropicProxy != "" {
		proxyURL, err := url.Parse(anthropicProxy)
		if err != nil {
			log.Fatalf("invalid CODEX_ANTHROPIC_PROXY_URL: %v", err)
		}
		proxyTransport := standardTransport.Clone()
		proxyTransport.Proxy = http.ProxyURL(proxyURL)
		transport = &anthropicHostProxyTransport{
			anthropic: proxyTransport,
			direct:    transport,
		}
		log.Printf("anthropic proxy enabled: %s", proxyURL.Host)
	}

	// Create refresh transport - may use a proxy for token refresh operations
	var refreshTransport http.RoundTripper = transport
	if cfg.refreshProxyURL != "" {
		proxyURL, err := url.Parse(cfg.refreshProxyURL)
		if err != nil {
			log.Fatalf("invalid refresh proxy URL %q: %v", cfg.refreshProxyURL, err)
		}
		refreshProxyTransport := &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
			MaxIdleConns:          20,
			MaxIdleConnsPerHost:   10,
		}
		_ = http2.ConfigureTransport(refreshProxyTransport)
		refreshTransport = refreshProxyTransport
		log.Printf("refresh operations will use proxy: %s", proxyURL.Host)
	}

	// Initialize pool users store if configured
	var poolUsers *PoolUserStore
	// Pool users require a JWT secret. Admin token or friend code provides access control.
	if (cfg.adminToken != "" || cfg.friendCode != "") && getPoolJWTSecret() != "" {
		poolUsersPath := getPoolUsersPath()
		var err error
		poolUsers, err = newPoolUserStore(poolUsersPath)
		if err != nil {
			log.Printf("warning: failed to load pool users: %v", err)
		} else {
			log.Printf("pool users enabled (%d users)", len(poolUsers.List()))
		}
	}

	// Initialize pricing data
	pricing := newPricingData()
	pricing.startPricingRefresh()

	// Initialize analytics store (SQLite)
	analyticsDBPath := "./data/analytics.db"
	analyticsStore, err := newAnalyticsStore(analyticsDBPath)
	if err != nil {
		log.Printf("warning: failed to open analytics store: %v (cost tracking disabled)", err)
	} else {
		defer analyticsStore.Close()
		analyticsStore.seedFromBoltDB(store, pricing)
		analyticsStore.startDailyRollup()
		log.Printf("analytics store initialized at %s", analyticsDBPath)
	}

	var aliasesCfg map[string]string
	if globalConfigFile != nil {
		aliasesCfg = globalConfigFile.ModelAliases
	}

	// Initialize request pacer from env var. Default to disabled so the proxy
	// does not add inter-turn latency unless an operator opts in.
	paceMs := 0
	if v := os.Getenv("CODEX_REQUEST_PACE_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			paceMs = n
		}
	}
	var pacer *requestPacer
	if paceMs > 0 {
		pacer = newRequestPacer(time.Duration(paceMs) * time.Millisecond)
	}

	h := &proxyHandler{
		cfg:              cfg,
		transport:        transport,
		refreshTransport: refreshTransport,
		pool:             pool,
		poolUsers:        poolUsers,
		registry:         registry,
		store:            store,
		analyticsStore:   analyticsStore,
		pricing:          pricing,
		aliases:          newModelAliases(aliasesCfg),
		bruteForce:       newBruteForceTracker(),
		metrics:          newMetrics(),
		recent:           newRecentErrors(50),
		startTime:        time.Now(),
		pacer:            pacer,
	}
	h.startUsagePoller()

	// Probe account UUIDs for Claude OAuth accounts that don't have one yet.
	go h.probeClaudeAccountUUIDs()

	// Background cleanup for request pacer (every 5 minutes)
	if pacer != nil {
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				pacer.cleanup(10 * time.Minute)
			}
		}()
	}

	// Start file watcher for hot-reload of pool directory and config.
	configPath := "config.toml"
	if v := os.Getenv("CONFIG_PATH"); v != "" {
		configPath = v
	}
	if watcher, err := newPoolWatcher(cfg.poolDir, configPath, h); err != nil {
		log.Printf("warning: failed to start file watcher: %v (hot-reload disabled)", err)
	} else {
		defer watcher.close()
	}

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
		MaxUploadBufferPerConnection: 1 << 20, // 1MB
		MaxUploadBufferPerStream:     1 << 20, // 1MB
		MaxReadFrameSize:             1 << 20, // 1MB
	}
	if err := http2.ConfigureServer(srv, http2Srv); err != nil {
		log.Printf("warning: failed to configure HTTP/2 server: %v", err)
	}

	if cfg.adminToken != "" {
		log.Printf("admin token configured (len=%d)", len(cfg.adminToken))
	} else {
		log.Printf("WARNING: no admin token configured")
	}
	log.Printf("codex-pool proxy listening on %s (codex=%d, claude=%d, gemini=%d, kimi=%d, minimax=%d, zai=%d, xiaomi=%d, grok=%d, request_timeout=%v, stream_timeout=%v, stream_idle_timeout=%v, websocket_idle_timeout=%v, websocket_heartbeat_interval=%v, websocket_read_limit=%d)",
		cfg.listenAddr, codexCount, claudeCount, geminiCount, kimiCount, minimaxCount, zaiCount, xiaomiCount, grokCount, cfg.requestTimeout, cfg.streamTimeout, cfg.streamIdleTimeout, cfg.websocketIdleTimeout, cfg.websocketHeartbeatInterval, cfg.websocketReadLimit)
	if cfg.claudeTraceDir != "" {
		log.Printf("claude traffic tracing enabled: dir=%s body_limit=%d include_secrets=%v", cfg.claudeTraceDir, cfg.claudeTraceBodyLimit, cfg.claudeTraceSecrets)
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

type proxyHandler struct {
	cfg              *config
	transport        http.RoundTripper
	refreshTransport http.RoundTripper // Separate transport for refresh ops (may use proxy)
	pool             *poolState
	poolUsers        *PoolUserStore
	registry         *ProviderRegistry
	store            *usageStore
	analyticsStore   *AnalyticsStore
	pricing          *PricingData
	aliases          *modelAliases
	bruteForce       *bruteForceTracker
	metrics          *metrics
	recent           *recentErrors
	inflight         int64
	startTime        time.Time
	pacer            *requestPacer // Per-session request pacing

	// Rate limiting for token refresh operations
	refreshMu       sync.Mutex
	lastRefreshTime time.Time
	refreshCallsMu  sync.Mutex
	refreshCalls    map[string]*refreshCall
}

type refreshCall struct {
	done chan struct{}
	err  error
}

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

func (h *proxyHandler) handleImagesGenerationFanout(w http.ResponseWriter, r *http.Request, body []byte, n int, reqID string) bool {
	if n <= 1 {
		return false
	}
	if n > 10 {
		http.Error(w, "n must be between 1 and 10", http.StatusBadRequest)
		return true
	}
	baseURL := h.getEffectivePublicURL(r)
	endpoint := strings.TrimRight(baseURL, "/") + "/v1/images/generations"
	oneBody := setImagesGenerationCount(body, 1)
	ctx := r.Context()
	client := &http.Client{Timeout: clientOrDefaultTimeout(r, h.cfg.requestTimeout, h.cfg.streamTimeout, oneBody)}
	type imageFanoutResult struct {
		index   int
		body    []byte
		status  int
		header  http.Header
		err     error
		created int64
		data    []any
	}
	results := make([]imageFanoutResult, n)
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(oneBody))
			if err != nil {
				results[i].err = err
				return
			}
			req.Header = cloneHeader(r.Header)
			removeHopByHopHeaders(req.Header)
			removeConflictingProxyHeaders(req.Header)
			req.Header.Del("Accept-Encoding")
			req.Header.Del("Content-Length")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Codex-Pool-Image-Fanout", "1")
			resp, err := client.Do(req)
			if err != nil {
				results[i].err = err
				return
			}
			defer resp.Body.Close()
			respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 80*1024*1024))
			results[i].index = i
			results[i].status = resp.StatusCode
			results[i].header = resp.Header.Clone()
			results[i].body = respBody
			if readErr != nil {
				results[i].err = readErr
				return
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				results[i].err = fmt.Errorf("image fanout request %d failed: %s: %s", i+1, resp.Status, safeText(respBody))
				return
			}
			var data []any
			data, results[i].created, err = appendImagesGenerationData(nil, respBody, "b64_json")
			if err != nil {
				results[i].err = err
				return
			}
			results[i].data = data
		}()
	}
	wg.Wait()
	mergedData := []any{}
	created := time.Now().Unix()
	for _, result := range results {
		if result.err != nil {
			if h.cfg.debug.Load() {
				log.Printf("[%s] image fanout failed: %v", reqID, result.err)
			}
			http.Error(w, result.err.Error(), http.StatusBadGateway)
			return true
		}
		if result.created > 0 && (created == 0 || result.created < created) {
			created = result.created
		}
		mergedData = append(mergedData, result.data...)
	}
	out, err := json.Marshal(map[string]any{"created": created, "data": mergedData})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(out)
	return true
}

func mapResponsesPath(in string) string {
	switch {
	case strings.HasPrefix(in, "/v1/responses/compact") || strings.HasPrefix(in, "/responses/compact"):
		return "/responses/compact"
	case in == "/v1/responses" || in == "/responses":
		return "/responses"
	default:
		return ""
	}
}

func codexPassthroughNeedsBodyRewrite(path string) bool {
	return strings.HasPrefix(path, "/v1/messages") ||
		strings.HasPrefix(path, "/v1/chat/completions") ||
		strings.HasPrefix(path, "/v1/completions")
}

func ensureCodexResponsesCompactBody(body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	out := map[string]any{}
	for _, key := range []string{"model", "input", "instructions", "tools", "tool_choice", "parallel_tool_calls", "reasoning", "service_tier", "text", "previous_response_id"} {
		if v, ok := obj[key]; ok {
			out[key] = v
		}
	}
	if _, ok := out["instructions"]; !ok {
		out["instructions"] = ""
	}
	if input, ok := out["input"].(string); ok {
		out["input"] = []any{
			map[string]any{
				"type": "message",
				"role": "user",
				"content": []any{
					map[string]any{"type": "input_text", "text": input},
				},
			},
		}
	}
	prepareCodexSchemasInBody(out)
	rewritten, err := json.Marshal(out)
	if err != nil {
		return body
	}
	return rewritten
}

func ensureCodexResponsesInstructions(body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	if _, ok := obj["instructions"]; !ok {
		obj["instructions"] = ""
	}
	obj["store"] = false
	obj["stream"] = true
	prepareCodexSchemasInBody(obj)
	sanitizeCodexResponsesParams(obj)
	if input, ok := obj["input"].(string); ok {
		obj["input"] = []any{
			map[string]any{
				"type": "message",
				"role": "user",
				"content": []any{
					map[string]any{"type": "input_text", "text": input},
				},
			},
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

func prepareCodexSchemasInBody(obj map[string]any) {
	if text, _ := obj["text"].(map[string]any); text != nil {
		if format, _ := text["format"].(map[string]any); format != nil {
			if schema, _ := format["schema"].(map[string]any); schema != nil {
				format["schema"] = prepareCodexJSONSchema(schema)
			}
		}
	}
	if tools, ok := obj["tools"].([]any); ok {
		for _, raw := range tools {
			tool, _ := raw.(map[string]any)
			if tool == nil {
				continue
			}
			if params, _ := tool["parameters"].(map[string]any); params != nil {
				tool["parameters"] = prepareCodexJSONSchema(params)
			}
			if fn, _ := tool["function"].(map[string]any); fn != nil {
				if params, _ := fn["parameters"].(map[string]any); params != nil {
					fn["parameters"] = prepareCodexJSONSchema(params)
				}
			}
		}
	}
}

func sanitizeCodexResponsesParams(obj map[string]any) {
	for _, key := range []string{
		"temperature",
		"top_p",
		"presence_penalty",
		"frequency_penalty",
		"max_tokens",
		"max_completion_tokens",
		"max_output_tokens",
		"seed",
		"logprobs",
		"top_logprobs",
		"metadata",
		"prompt_cache_scope",
	} {
		delete(obj, key)
	}
}

func requestHasImageGenerationTool(body []byte) bool {
	var obj any
	if err := json.Unmarshal(body, &obj); err != nil {
		return false
	}
	return valueHasImageGenerationTool(obj)
}

func valueHasImageGenerationTool(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		if typ, _ := x["type"].(string); typ == "image_generation" {
			return true
		}
		for _, child := range x {
			if valueHasImageGenerationTool(child) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if valueHasImageGenerationTool(child) {
				return true
			}
		}
	}
	return false
}

func codexPassthroughRewrite(path string, body []byte) (rewrittenPath string, rewrittenBody []byte, err error) {
	switch {
	case strings.HasPrefix(path, "/v1/messages"):
		rewritten, err := translateClaudeToResponsesRequest(body)
		if err != nil {
			return path, nil, err
		}
		return "/v1/responses", rewritten, nil
	case strings.HasPrefix(path, "/v1/chat/completions"):
		rewritten, err := translateChatCompletionsToResponses(body)
		if err != nil {
			return path, nil, err
		}
		return "/v1/responses", rewritten, nil
	case strings.HasPrefix(path, "/v1/completions"):
		rewritten, err := translateCompletionsToResponses(body)
		if err != nil {
			return path, nil, err
		}
		return "/v1/responses", rewritten, nil
	default:
		return path, body, nil
	}
}

func extractConversationIDFromHeaders(headers http.Header) string {
	for _, key := range []string{
		"session_id",
		"Session_id",
		"Session-Id",
		"conversation_id",
		"Conversation_id",
		"prompt_cache_key",
		"x-codex-conversation-id",
	} {
		if value := strings.TrimSpace(headers.Get(key)); value != "" {
			return value
		}
		for actualKey, values := range headers {
			if !strings.EqualFold(actualKey, key) {
				continue
			}
			for _, value := range values {
				if value = strings.TrimSpace(value); value != "" {
					return value
				}
			}
		}
	}
	return ""
}

func (h *proxyHandler) pinConversationToCyberAccess(conversationID string, accountType AccountType, requiredPlan, clientIP, currentAccountID, reqID string) bool {
	if conversationID == "" || accountType != AccountTypeCodex {
		return false
	}
	exclude := map[string]bool{}
	if currentAccountID != "" {
		exclude[currentAccountID] = true
	}
	acc := h.pool.candidateWithCyberAccess(exclude, accountType, requiredPlan, clientIP)
	if acc == nil {
		if h.cfg.debug.Load() {
			log.Printf("[%s] cyber_policy seen for conversation %s, but no cyber_access account is available", reqID, conversationID)
		}
		return false
	}
	h.pool.pin(conversationID, acc.ID)
	if h.cfg.debug.Load() {
		log.Printf("[%s] pinned conversation %s to cyber_access account %s after cyber_policy", reqID, conversationID, acc.ID)
	}
	return true
}

// shouldRetryBufferedSSEForCyberPolicy decides whether a buffered
// SSE-translation response that hit cyber_policy mid-stream should be
// discarded and retried against a cyber_access account on the next
// attempt of the request loop. Returns true only when (a) we already
// pinned the conversation to a cyber account during this attempt's SSE
// callback (meaning a candidate exists), (b) we actually saw a
// cyber_policy event (gated by acc not being CyberAccess), and (c) the
// caller has retries left. The buffered translator output is empty in
// this case anyway, so retrying is strictly better UX than writing the
// empty translation.
func (h *proxyHandler) shouldRetryBufferedSSEForCyberPolicy(cyberPinned bool, attempt, attempts int, acc *Account, reqID, label string) bool {
	if !cyberPinned || attempt >= attempts || acc == nil || acc.CyberAccess {
		return false
	}
	log.Printf("[%s] buffered %s SSE saw cyber_policy on account %s; retrying on cyber_access account", reqID, label, acc.ID)
	if h.metrics != nil {
		h.metrics.incCyberPolicy(acc.ID, "retry_buffered")
	}
	return true
}

// wrapBufferedSSEWithCyberDetector returns a writer that forwards SSE
// bytes to the buffered translator under, but also drops cyber_policy
// events and flips *cyberPinned when one is seen. Used by the
// non-streaming buffered paths where we can't synthesize a refusal
// inline (the buffered translator owns the final shape) — the loop's
// retry mechanism then discards the buffer and tries a cyber account.
func (h *proxyHandler) wrapBufferedSSEWithCyberDetector(under io.Writer, accountType AccountType, acc *Account, conversationID, requiredPlan, originIP, reqID string, cyberPinned *bool) io.Writer {
	if accountType != AccountTypeCodex || acc == nil || acc.CyberAccess {
		return under
	}
	return &sseInterceptWriter{
		w: under,
		onEvent: func(eventData []byte) (bool, bool) {
			if !isCyberPolicyError(eventData) {
				return false, false
			}
			if h.metrics != nil {
				h.metrics.incCyberPolicy(acc.ID, "suppressed_buffered")
			}
			if h.pinConversationToCyberAccess(conversationID, accountType, requiredPlan, originIP, acc.ID, reqID) {
				if cyberPinned != nil {
					*cyberPinned = true
				}
			}
			return true, true
		},
	}
}

func removeConflictingProxyHeaders(h http.Header) {
	// Remove ALL Cloudflare headers (Cf-*) — our own Cloudflare adds these,
	// and they confuse upstream Cloudflare (e.g. chatgpt.com) into blocking us.
	for key := range h {
		if strings.HasPrefix(strings.ToLower(key), "cf-") {
			h.Del(key)
		}
	}
	h.Del("Cdn-Loop")
	// Remove proxy/forwarding headers added by Caddy or Cloudflare
	h.Del("X-Forwarded-For")
	h.Del("X-Forwarded-Proto")
	h.Del("X-Forwarded-Host")
	h.Del("X-Real-Ip")
	h.Del("Via")
	h.Del("True-Client-Ip")
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
	return extractConversationIDFromObject(obj)
}

func extractConversationIDFromObject(obj map[string]any) string {
	for _, key := range []string{"conversation_id", "conversation", "session_id"} {
		if v, ok := obj[key].(string); ok && v != "" {
			return v
		}
	}
	for _, containerKey := range []string{"metadata", "meta"} {
		if sub, ok := obj[containerKey].(map[string]any); ok {
			for _, key := range []string{"conversation_id", "conversation", "session_id", "user_id"} {
				if v, ok := sub[key].(string); ok && v != "" {
					return v
				}
			}
		}
	}
	return ""
}

func extractRequestedModelFromJSON(blob []byte) string {
	if len(blob) == 0 {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal(blob, &obj); err != nil {
		return ""
	}
	if v, ok := obj["model"].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func stripCodexModelSuffixes(model string) (base string, reasoningEffort string, serviceTier string) {
	base = strings.TrimSpace(model)
	lower := strings.ToLower(base)
	for _, tier := range []string{"fast", "flex"} {
		suffix := "-" + tier
		if strings.HasSuffix(lower, suffix) {
			serviceTier = tier
			if serviceTier == "fast" {
				serviceTier = "priority"
			}
			base = strings.TrimSpace(base[:len(base)-len(suffix)])
			lower = strings.ToLower(base)
			break
		}
	}
	// Order matters: longer suffixes first so -xhigh wins over -high, etc.
	// GPT-5.6 adds max (above xhigh). ultra is multi-agent product mode;
	// map suffix to max for single-request routing through the pool.
	for _, effort := range []string{"xhigh", "minimal", "medium", "ultra", "none", "high", "max", "low"} {
		suffix := "-" + effort
		if strings.HasSuffix(lower, suffix) {
			reasoningEffort = effort
			if effort == "ultra" {
				reasoningEffort = "max"
			}
			base = strings.TrimSpace(base[:len(base)-len(suffix)])
			break
		}
	}
	return base, reasoningEffort, serviceTier
}

func applyCodexModelSuffixControls(body []byte, originalModel string) ([]byte, string) {
	base, effort, serviceTier := stripCodexModelSuffixes(originalModel)
	if base == "" || (base == originalModel && effort == "" && serviceTier == "") {
		return body, originalModel
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body, originalModel
	}
	obj["model"] = base
	if effort != "" {
		reasoning, _ := obj["reasoning"].(map[string]any)
		if reasoning == nil {
			reasoning = map[string]any{}
		}
		if _, ok := reasoning["summary"]; !ok {
			reasoning["summary"] = "auto"
		}
		reasoning["effort"] = effort
		obj["reasoning"] = reasoning
	}
	if serviceTier != "" {
		obj["service_tier"] = serviceTier
	}
	rewritten, err := json.Marshal(obj)
	if err != nil {
		return body, originalModel
	}
	return rewritten, base
}

func modelRequiresCodexPro(model string) bool {
	return strings.EqualFold(strings.TrimSpace(model), "gpt-5.3-codex-spark")
}

const requiredPlanClaudePremium = "claude_premium"

func claudeRequestRequiresPremium(r *http.Request, model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	if strings.Contains(model, "opus") || strings.Contains(model, "[1m]") {
		return true
	}
	if r == nil {
		return false
	}
	for _, beta := range r.Header.Values("anthropic-beta") {
		if strings.Contains(strings.ToLower(beta), "context-1m-") {
			return true
		}
	}
	return false
}

func requiredPlanForRequest(accountType AccountType, r *http.Request, requestedModel string) string {
	if accountType == AccountTypeCodex && modelRequiresCodexPro(requestedModel) {
		return "pro"
	}
	if accountType == AccountTypeClaude && claudeRequestRequiresPremium(r, requestedModel) {
		return requiredPlanClaudePremium
	}
	return ""
}

func isCodexToClaudeModelOverridePath(path string) bool {
	if detectRequestFormat(path) == FormatOpenAI {
		return true
	}
	return strings.HasPrefix(path, "/v1/responses") || strings.HasPrefix(path, "/responses")
}

// modelRouteOverride checks if the requested model should be routed to an external
// provider (Kimi, MiniMax, etc.) instead of the path-detected provider.
// Returns (provider, baseURL, rewrittenBody) or (nil, nil, nil) if no override.
func (h *proxyHandler) modelRouteOverride(path, model string, body []byte) (Provider, *url.URL, []byte) {
	if isKimiModel(model) {
		p := h.registry.ForType(AccountTypeKimi)
		if p == nil {
			return nil, nil, nil
		}
		return p, p.UpstreamURL(path), nil
	}
	if isMinimaxModel(model) {
		p := h.registry.ForType(AccountTypeMinimax)
		if p == nil {
			return nil, nil, nil
		}
		// Rewrite the model name to the canonical upstream name
		canonical := minimaxCanonicalModel(model)
		rewritten := rewriteModelInBody(body, canonical)
		return p, p.UpstreamURL(path), rewritten
	}
	if isZAIModel(model) {
		p := h.registry.ForType(AccountTypeZAI)
		if p == nil {
			return nil, nil, nil
		}
		canonical := zaiCanonicalModel(model)
		rewritten := rewriteModelInBody(body, canonical)
		return p, p.UpstreamURL(path), rewritten
	}
	if isXiaomiModel(model) {
		p := h.registry.ForType(AccountTypeXiaomi)
		if p == nil {
			return nil, nil, nil
		}
		canonical := xiaomiCanonicalModel(model)
		rewritten := rewriteModelInBody(body, canonical)
		return p, p.UpstreamURL(path), rewritten
	}
	if isGrokModel(model) {
		p := h.registry.ForType(AccountTypeGrok)
		if p == nil {
			return nil, nil, nil
		}
		canonical := grokCanonicalModel(model)
		rewritten := rewriteAndSanitizeGrokRequestBody(body, canonical)
		return p, p.UpstreamURL(path), rewritten
	}
	// Cross-format model routing: detect if the model belongs to a different provider
	// than the one the request path would normally select.
	if isOpenAIModel(model) {
		p := h.registry.ForType(AccountTypeCodex)
		if p != nil {
			return p, p.UpstreamURL(path), nil
		}
	}
	if isClaudeModel(model) && !isCodexToClaudeModelOverridePath(path) {
		p := h.registry.ForType(AccountTypeClaude)
		if p != nil {
			canonical := claudeCanonicalModel(model)
			rewritten := rewriteModelInBody(body, canonical)
			return p, p.UpstreamURL(path), rewritten
		}
	}
	return nil, nil, nil
}

const streamedModelRoutePeekBytes = 64 * 1024

func shouldPeekStreamedModelRoute(r *http.Request) bool {
	if r == nil || r.ContentLength < streamedModelRoutePeekBytes {
		return false
	}
	return r.Method == http.MethodPost && r.URL.Path == "/v1/messages"
}

func (h *proxyHandler) applyStreamedModelRoute(r *http.Request, provider Provider, targetBase *url.URL, reqID string) (Provider, *url.URL, error) {
	if r == nil || r.Body == nil || h == nil || h.registry == nil {
		return provider, targetBase, nil
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1/messages" {
		return provider, targetBase, nil
	}
	if strings.TrimSpace(r.Header.Get("Content-Encoding")) != "" {
		return provider, targetBase, nil
	}
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if contentType != "" && !strings.Contains(contentType, "json") {
		return provider, targetBase, nil
	}

	prefix, err := readBodyPrefix(r.Body, streamedModelRoutePeekBytes)
	if err != nil {
		r.Body = &prefixReadCloser{r: bytes.NewReader(prefix), c: r.Body}
		return provider, targetBase, err
	}
	restoreBody := func(replacement []byte) {
		r.Body = &prefixReadCloser{r: io.MultiReader(bytes.NewReader(replacement), r.Body), c: r.Body}
	}

	model, valueStart, valueEnd, ok := findTopLevelJSONStringField(prefix, "model")
	if !ok {
		restoreBody(prefix)
		return provider, targetBase, nil
	}

	requestedModel := strings.TrimSpace(model)
	if resolved, aliased := h.aliases.resolve(requestedModel); aliased {
		if h.cfg != nil && h.cfg.debug.Load() {
			log.Printf("[%s] streamed model alias: %s -> %s", reqID, requestedModel, resolved)
		}
		requestedModel = resolved
	}
	if !isXiaomiModel(requestedModel) {
		restoreBody(prefix)
		return provider, targetBase, nil
	}

	xiaomiProvider := h.registry.ForType(AccountTypeXiaomi)
	if xiaomiProvider == nil {
		restoreBody(prefix)
		return provider, targetBase, nil
	}

	canonical := xiaomiCanonicalModel(requestedModel)
	rewrittenPrefix, delta, err := replaceJSONStringToken(prefix, valueStart, valueEnd, canonical)
	if err != nil {
		restoreBody(prefix)
		return provider, targetBase, err
	}
	if r.ContentLength >= 0 && delta != 0 {
		r.ContentLength += int64(delta)
		r.Header.Del("Content-Length")
	}
	restoreBody(rewrittenPrefix)
	return xiaomiProvider, xiaomiProvider.UpstreamURL(r.URL.Path), nil
}

func readBodyPrefix(body io.Reader, limit int64) ([]byte, error) {
	var buf bytes.Buffer
	_, err := io.CopyN(&buf, body, limit)
	if err == io.EOF {
		err = nil
	}
	return buf.Bytes(), err
}

type prefixReadCloser struct {
	r io.Reader
	c io.Closer
}

func (p *prefixReadCloser) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

func (p *prefixReadCloser) Close() error {
	return p.c.Close()
}

func replaceJSONStringToken(prefix []byte, start, end int, value string) ([]byte, int, error) {
	if start < 0 || end < start || end > len(prefix) {
		return nil, 0, fmt.Errorf("invalid JSON string bounds")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, 0, err
	}
	out := make([]byte, 0, len(prefix)-(end-start)+len(encoded))
	out = append(out, prefix[:start]...)
	out = append(out, encoded...)
	out = append(out, prefix[end:]...)
	return out, len(encoded) - (end - start), nil
}

func findTopLevelJSONStringField(blob []byte, field string) (value string, valueStart int, valueEnd int, ok bool) {
	i := skipJSONWhitespace(blob, 0)
	if i >= len(blob) || blob[i] != '{' {
		return "", 0, 0, false
	}
	i++
	for {
		i = skipJSONWhitespace(blob, i)
		if i >= len(blob) {
			return "", 0, 0, false
		}
		if blob[i] == '}' {
			return "", 0, 0, false
		}
		if blob[i] == ',' {
			i++
			continue
		}
		key, _, _, next, ok := readJSONStringToken(blob, i)
		if !ok {
			return "", 0, 0, false
		}
		i = skipJSONWhitespace(blob, next)
		if i >= len(blob) || blob[i] != ':' {
			return "", 0, 0, false
		}
		i = skipJSONWhitespace(blob, i+1)
		if key == field {
			value, valueStart, valueEnd, _, ok = readJSONStringToken(blob, i)
			return value, valueStart, valueEnd, ok
		}
		next, ok = skipJSONValue(blob, i)
		if !ok {
			return "", 0, 0, false
		}
		i = next
	}
}

func skipJSONWhitespace(blob []byte, i int) int {
	for i < len(blob) {
		switch blob[i] {
		case ' ', '\n', '\r', '\t':
			i++
		default:
			return i
		}
	}
	return i
}

func readJSONStringToken(blob []byte, i int) (value string, start int, end int, next int, ok bool) {
	if i >= len(blob) || blob[i] != '"' {
		return "", 0, 0, 0, false
	}
	start = i
	escaped := false
	for i++; i < len(blob); i++ {
		if escaped {
			escaped = false
			continue
		}
		switch blob[i] {
		case '\\':
			escaped = true
		case '"':
			end = i + 1
			if err := json.Unmarshal(blob[start:end], &value); err != nil {
				return "", 0, 0, 0, false
			}
			return value, start, end, end, true
		}
	}
	return "", 0, 0, 0, false
}

func skipJSONValue(blob []byte, i int) (int, bool) {
	i = skipJSONWhitespace(blob, i)
	if i >= len(blob) {
		return 0, false
	}
	if blob[i] == '"' {
		_, _, _, next, ok := readJSONStringToken(blob, i)
		return next, ok
	}
	if blob[i] != '{' && blob[i] != '[' {
		for i < len(blob) {
			switch blob[i] {
			case ',', '}', ']':
				return i, true
			case ' ', '\n', '\r', '\t':
				return skipJSONWhitespace(blob, i), true
			default:
				i++
			}
		}
		return 0, false
	}

	stack := []byte{blob[i]}
	escaped := false
	inString := false
	for i++; i < len(blob); i++ {
		c := blob[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch c {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			stack = append(stack, c)
		case '}', ']':
			if len(stack) == 0 {
				return 0, false
			}
			open := stack[len(stack)-1]
			if (open == '{' && c != '}') || (open == '[' && c != ']') {
				return 0, false
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return i + 1, true
			}
		}
	}
	return 0, false
}

// rewriteModelInBody replaces the "model" field in a JSON request body.
func rewriteModelInBody(body []byte, newModel string) []byte {
	if len(body) == 0 {
		return nil
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil
	}
	if _, ok := obj["model"]; !ok {
		return nil
	}
	obj["model"] = newModel
	rewritten, err := json.Marshal(obj)
	if err != nil {
		return nil
	}
	return rewritten
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

	// codex_apps MCP and other noop paths must never require a pool token.
	// ServeHTTP already routes these, but keep a guard here in case a future
	// caller reaches proxyRequest with a rewritten / stripped path.
	if shouldNoopCodexPath(r.URL.Path) {
		serveNoopCodexPath(w, r)
		return
	}

	// Determine user ID - either from pool JWT, Claude pool token, or hashed IP
	var userID string
	secret := getPoolJWTSecret()

	// Check for Claude pool tokens first (sk-ant-oat01-pool-* or legacy sk-ant-api-pool-*).
	// Anthropic SDKs commonly send API-key credentials in x-api-key, so accept
	// pool Claude tokens there as well as Authorization: Bearer.
	claudePoolAuthHeader := authHeader
	if claudePoolAuthHeader == "" {
		if apiKey := strings.TrimSpace(r.Header.Get("X-Api-Key")); apiKey != "" {
			claudePoolAuthHeader = "Bearer " + apiKey
		}
	}
	if secret != "" {
		if isClaudePool, uid := isClaudePoolToken(secret, claudePoolAuthHeader); isClaudePool {
			userID = uid
			// Check if user is disabled
			if h.poolUsers != nil {
				if user := h.poolUsers.Get(userID); user != nil && user.Disabled {
					http.Error(w, "pool user disabled", http.StatusForbidden)
					return
				}
			}
			if h.cfg.debug.Load() {
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
				// Check if user is disabled
				if h.poolUsers != nil {
					if user := h.poolUsers.Get(userID); user != nil && user.Disabled {
						http.Error(w, "pool user disabled", http.StatusForbidden)
						return
					}
				}
				if h.cfg.debug.Load() {
					log.Printf("[%s] gemini api key pool user request: user_id=%s", reqID, userID)
				}
			}
		}
	}

	// Check for JWT-based pool tokens (Codex, Gemini OAuth)
	if userID == "" && secret != "" {
		if isPoolUser, uid, _ := isPoolUserToken(secret, authHeader); isPoolUser {
			userID = uid
			// Check if user is disabled
			if h.poolUsers != nil {
				if user := h.poolUsers.Get(userID); user != nil && user.Disabled {
					http.Error(w, "pool user disabled", http.StatusForbidden)
					return
				}
			}
			if h.cfg.debug.Load() {
				log.Printf("[%s] pool user request: user_id=%s", reqID, userID)
			}
		}
	}

	// Check for Gemini OAuth pool tokens (ya29.pool-*)
	if userID == "" && secret != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if isPoolToken, uid := isGeminiOAuthPoolToken(secret, token); isPoolToken {
			userID = uid
			// Check if user is disabled
			if h.poolUsers != nil {
				if user := h.poolUsers.Get(userID); user != nil && user.Disabled {
					http.Error(w, "pool user disabled", http.StatusForbidden)
					return
				}
			}
			if h.cfg.debug.Load() {
				log.Printf("[%s] gemini oauth pool user request: user_id=%s", reqID, userID)
			}
		}
	}

	// Check if this looks like a real provider credential that should be passed through
	// This allows users to use their own API keys while benefiting from the proxy infrastructure
	if userID == "" {
		if isProviderCred, providerType := looksLikeProviderCredential(authHeader); isProviderCred {
			if h.cfg.debug.Load() {
				log.Printf("[%s] pass-through request with %s credential", reqID, providerType)
			}
			h.proxyPassthrough(w, r, reqID, providerType, start)
			return
		}
	}

	// Reject unauthenticated requests - require a valid pool token
	if userID == "" {
		http.Error(w, "unauthorized: valid pool token required", http.StatusUnauthorized)
		return
	}
	originID := hashRequestOrigin(r, poolHashSalt(h.cfg.friendCode))
	originIP := getClientIP(r)
	if h.store != nil && originID != "" && originIP != "" {
		_ = h.store.recordOriginMetadata(originID, originIP, userID, r.UserAgent(), r.URL.Path, time.Now())
	}

	provider, targetBase := h.pickUpstream(r.URL.Path, r.Header)
	if provider == nil || targetBase == nil {
		http.Error(w, "no upstream for path", http.StatusNotFound)
		return
	}
	accountType := provider.Type()

	if isWebSocketUpgradeRequest(r) {
		h.proxyRequestWebSocket(w, r, reqID, userID, originID, provider, targetBase)
		return
	}

	streamBody := shouldStreamBody(r, h.cfg.maxInMemoryBodyBytes)
	if streamBody || shouldPeekStreamedModelRoute(r) {
		var err error
		provider, targetBase, err = h.applyStreamedModelRoute(r, provider, targetBase, reqID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		accountType = provider.Type()
		streamBody = streamBody || accountType == AccountTypeXiaomi
	}
	if streamBody {
		if h.cfg.debug.Load() {
			log.Printf("[%s] streaming request body: method=%s path=%s provider=%s content-length=%d",
				reqID, r.Method, r.URL.Path, accountType, r.ContentLength)
		}
		h.proxyRequestStreamed(w, r, reqID, userID, originID, provider, targetBase)
		return
	}

	bodyBytes, bodySample, err := readBodyForReplay(r.Body, h.cfg.logBodies, h.cfg.bodyLogLimit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/images/generations") {
		if n := imagesGenerationCount(bodyBytes); n > 1 {
			if h.handleImagesGenerationFanout(w, r, bodyBytes, n, reqID) {
				return
			}
		}
	}

	// conversation_id usually comes from request JSON (Codex often includes it).
	inspect := bodyBytes
	if len(inspect) == 0 {
		inspect = bodySample
	}
	inspect = bodyForInspection(r, inspect)
	conversationID := extractConversationIDFromJSON(inspect)
	if conversationID == "" {
		conversationID = extractConversationIDFromHeaders(r.Header)
	}
	// Use Claude Code session ID as fallback for conversation stickiness
	if conversationID == "" {
		for _, key := range []string{"X-Claude-Code-Session-Id", "x-claude-code-session-id"} {
			if v := strings.TrimSpace(r.Header.Get(key)); v != "" {
				conversationID = v
				break
			}
		}
	}
	requestedModel := extractRequestedModelFromJSON(inspect)

	// Resolve model aliases before routing.
	if requestedModel != "" {
		requestedModel, bodyBytes = applyModelAlias(h.aliases, requestedModel, bodyBytes, h.cfg.debug.Load(), reqID)
	}

	if requestedModel != "" && isOpenAIModel(requestedModel) {
		var baseModel string
		bodyBytes, baseModel = applyCodexModelSuffixControls(bodyBytes, requestedModel)
		requestedModel = baseModel
	}

	// Parse thinking budget suffix before routing (e.g. "claude-sonnet-4-5(16384)").
	// Strip suffix so routing sees the base model name.
	if requestedModel != "" {
		baseName, _, hasSuffix := parseThinkingSuffix(requestedModel)
		if hasSuffix {
			requestedModel = baseName
			// Rewrite model in body to the base name for model routing to work.
			if rewritten := rewriteModelInBody(bodyBytes, baseName); rewritten != nil {
				bodyBytes = rewritten
			}
		}
	}

	// Model-based provider override: route to external providers by model name.
	if requestedModel != "" {
		if overrideProvider, overrideBase, rewrittenBody := h.modelRouteOverride(r.URL.Path, requestedModel, bodyBytes); overrideProvider != nil {
			provider = overrideProvider
			targetBase = overrideBase
			accountType = overrideProvider.Type()
			if rewrittenBody != nil {
				bodyBytes = rewrittenBody
			}
		}
	}

	// Inject thinking budget if the original model had a (budget) suffix.
	if requestedModel != "" {
		origModel := extractRequestedModelFromJSON(inspect)
		if origModel != "" {
			_, budget, hasSuffix := parseThinkingSuffix(origModel)
			if hasSuffix && budget > 0 {
				bodyBytes = injectThinkingBudget(bodyBytes, accountType, budget)
				if h.cfg.debug.Load() {
					log.Printf("[%s] thinking suffix: budget=%d provider=%s", reqID, budget, accountType)
				}
			}
		}
	}

	// --- Format translation: detect mismatch between client format and provider format ---
	sourceFormat := detectRequestFormat(r.URL.Path)
	targetFormat := providerTargetFormat(accountType)
	if accountType == AccountTypeClaude && (sourceFormat == FormatOpenAI || strings.HasPrefix(r.URL.Path, "/v1/responses") || strings.HasPrefix(r.URL.Path, "/responses")) {
		http.Error(w, "OpenAI/Codex request formats cannot be translated to Claude", http.StatusBadRequest)
		return
	}
	translateDir := TranslateNone
	if sourceFormat != FormatUnknown && targetFormat != FormatUnknown && sourceFormat != targetFormat {
		if sourceFormat == FormatClaude && targetFormat == FormatOpenAI {
			// Codex backend uses Responses API, not Chat Completions
			if accountType == AccountTypeCodex {
				translateDir = TranslateClaudeToResponses
			} else {
				translateDir = TranslateClaudeToOAI
			}
		} else if sourceFormat == FormatOpenAI && targetFormat == FormatClaude {
			translateDir = TranslateOAIToClaude
		}
	}
	// Special case: Chat Completions -> Codex Responses API
	// When client sends /v1/chat/completions and provider is Codex, translate to Responses API format.
	// The Codex upstream (chatgpt.com/backend-api/codex) only speaks Responses API.
	// Codex always requires streaming, so we track whether the client originally wanted non-streaming.
	clientWantsNonStreaming := false
	imagesResponseFormat := ""
	if len(inspect) > 0 {
		var obj map[string]any
		if json.Unmarshal(inspect, &obj) == nil {
			if s, ok := obj["stream"].(bool); !ok || !s {
				clientWantsNonStreaming = true
			}
		}
	}
	if translateDir == TranslateNone && accountType == AccountTypeCodex && (strings.HasPrefix(r.URL.Path, "/v1/images/generations") || strings.HasPrefix(r.URL.Path, "/v1/images/edits")) {
		translateDir = TranslateImagesToResponses
		clientWantsNonStreaming = true
	}
	if translateDir == TranslateNone && sourceFormat == FormatOpenAI && accountType == AccountTypeCodex {
		if strings.HasPrefix(r.URL.Path, "/v1/completions") && !strings.HasPrefix(r.URL.Path, "/v1/chat/completions") {
			translateDir = TranslateCompletionsToResponses
		} else {
			translateDir = TranslateChatToResponses
		}
	}
	// Special case: Responses API -> Claude Messages API
	// When client sends /responses (e.g. Codex CLI with -m opus) and provider is Claude.
	if translateDir == TranslateNone && accountType == AccountTypeClaude {
		if strings.HasPrefix(r.URL.Path, "/v1/responses") || strings.HasPrefix(r.URL.Path, "/responses") {
			translateDir = TranslateResponsesToClaude
		}
	}

	if translateDir == TranslateNone && accountType == AccountTypeCodex && (strings.HasPrefix(r.URL.Path, "/v1/responses") || strings.HasPrefix(r.URL.Path, "/responses")) {
		if strings.HasPrefix(r.URL.Path, "/v1/responses/compact") || strings.HasPrefix(r.URL.Path, "/responses/compact") {
			bodyBytes = ensureCodexResponsesCompactBody(bodyBytes)
		} else {
			bodyBytes = ensureCodexResponsesInstructions(bodyBytes)
		}
	}

	if translateDir != TranslateNone {
		logTranslation(reqID, translateDir, h.cfg.debug.Load())
		var err error
		switch translateDir {
		case TranslateClaudeToOAI:
			bodyBytes, err = translateRequestBody(bodyBytes, sourceFormat, targetFormat)
			if err != nil {
				http.Error(w, "format translation error: "+err.Error(), http.StatusBadRequest)
				return
			}
			r.URL.Path = "/v1/chat/completions"
		case TranslateOAIToClaude:
			bodyBytes, err = translateRequestBody(bodyBytes, sourceFormat, targetFormat)
			if err != nil {
				http.Error(w, "format translation error: "+err.Error(), http.StatusBadRequest)
				return
			}
			r.URL.Path = "/v1/messages"
		case TranslateChatToResponses:
			bodyBytes, err = translateChatCompletionsToResponses(bodyBytes)
			if err != nil {
				http.Error(w, "format translation error: "+err.Error(), http.StatusBadRequest)
				return
			}
			r.URL.Path = "/v1/responses"
		case TranslateCompletionsToResponses:
			bodyBytes, err = translateCompletionsToResponses(bodyBytes)
			if err != nil {
				http.Error(w, "format translation error: "+err.Error(), http.StatusBadRequest)
				return
			}
			r.URL.Path = "/v1/responses"
		case TranslateImagesToResponses:
			if strings.HasPrefix(r.URL.Path, "/v1/images/edits") {
				bodyBytes, imagesResponseFormat, err = translateImagesEditToResponses(bodyBytes, r.Header.Get("Content-Type"))
			} else {
				bodyBytes, imagesResponseFormat, err = translateImagesGenerationToResponses(bodyBytes)
			}
			if err != nil {
				http.Error(w, "format translation error: "+err.Error(), http.StatusBadRequest)
				return
			}
			r.URL.Path = "/v1/responses"
		case TranslateResponsesToClaude:
			bodyBytes, err = translateResponsesToClaudeRequest(bodyBytes)
			if err != nil {
				http.Error(w, "format translation error: "+err.Error(), http.StatusBadRequest)
				return
			}
			r.URL.Path = "/v1/messages"
		case TranslateClaudeToResponses:
			bodyBytes, err = translateClaudeToResponsesRequest(bodyBytes)
			if err != nil {
				http.Error(w, "format translation error: "+err.Error(), http.StatusBadRequest)
				return
			}
			r.URL.Path = "/v1/responses"
		}
	}

	if accountType == AccountTypeGrok {
		bodyBytes = rewriteAndSanitizeGrokRequestBody(bodyBytes, requestedModel)
	}

	if h.cfg.debug.Load() && conversationID == "" && len(inspect) > 0 {
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

	if h.cfg.debug.Load() {
		log.Printf("[%s] incoming %s %s provider=%s conv_id=%s user_id=%s origin_id=%s authZ_len=%d chatgpt-id=%q content-type=%q content-encoding=%q body_bytes=%d",
			reqID,
			r.Method,
			r.URL.Path,
			accountType,
			conversationID,
			userID,
			originID,
			len(r.Header.Get("Authorization")),
			r.Header.Get("ChatGPT-Account-ID"),
			r.Header.Get("Content-Type"),
			r.Header.Get("Content-Encoding"),
			len(bodyBytes),
		)
		if requestedModel != "" {
			log.Printf("[%s] requested model=%s", reqID, requestedModel)
		}
	}
	if h.cfg.logBodies && len(bodySample) > 0 {
		log.Printf("[%s] request body sample (%d bytes): %s", reqID, len(bodySample), safeText(bodySample))
	}

	// Determine timeout: honour X-Stainless-Timeout from the Anthropic SDK when present,
	// otherwise fall back to streaming vs non-streaming defaults.
	timeout := clientOrDefaultTimeout(r, h.cfg.requestTimeout, h.cfg.streamTimeout, inspect)

	ctx := r.Context()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

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
	cyberAccessRetry := false
	requiredPlan := requiredPlanForRequest(accountType, r, requestedModel)

	const maxCooldownWait = 10 * time.Second // max time to wait for a rate-limited account
	const preferredImageCodexAccountID = "neon"
	imageGenerationRequest := accountType == AccountTypeCodex && requestHasImageGenerationTool(bodyBytes)

	for attempt := 1; attempt <= attempts; attempt++ {
		var acc *Account
		if imageGenerationRequest && attempt == 1 {
			acc = h.pool.candidateByID(preferredImageCodexAccountID, accountType, requiredPlan, originIP)
			if acc != nil && h.cfg.debug.Load() {
				log.Printf("[%s] routing image generation request to codex account %s", reqID, acc.ID)
			}
		}
		if acc == nil && cyberAccessRetry {
			acc = h.pool.candidateWithCyberAccess(exclude, accountType, requiredPlan, originIP)
			if acc != nil && h.cfg.debug.Load() {
				log.Printf("[%s] routing cyber_policy retry to %s account %s", reqID, accountType, acc.ID)
			}
		}
		if acc == nil && !cyberAccessRetry {
			candidateConversationID := conversationID
			if imageGenerationRequest {
				candidateConversationID = ""
			}
			acc = h.pool.candidate(candidateConversationID, exclude, accountType, requiredPlan, originIP)
		}
		if acc == nil {
			// All accounts excluded or rate-limited. If there are rate-limited
			// accounts, wait for the shortest cooldown instead of 503 immediately.
			if cooldown := h.pool.nearestCooldown(accountType, nil); cooldown > 0 {
				wait := cooldown
				if wait > maxCooldownWait {
					wait = maxCooldownWait
				}
				if h.cfg.debug.Load() {
					log.Printf("[%s] all %s accounts exhausted, waiting %s for cooldown", reqID, accountType, wait)
				}
				select {
				case <-time.After(wait):
					// Retry with fresh exclude set.
					exclude = map[string]bool{}
					continue
				case <-ctx.Done():
				}
			}
			if lastErr != nil {
				http.Error(w, lastErr.Error(), http.StatusServiceUnavailable)
			} else {
				if requiredPlan != "" {
					http.Error(w, fmt.Sprintf("no live %s %s accounts for model %s", accountType, requiredPlan, requestedModel), http.StatusServiceUnavailable)
				} else {
					http.Error(w, fmt.Sprintf("no live %s accounts", accountType), http.StatusServiceUnavailable)
				}
			}
			return
		}
		exclude[acc.ID] = true

		atomic.AddInt64(&acc.Inflight, 1)
		atomic.AddInt64(&h.inflight, 1)

		resp, sampleBuf, refreshFailed, err := h.tryOnce(ctx, r, bodyBytes, targetBase, provider, acc, reqID, translateDir, requestedModel, userID, originID, conversationID)

		atomic.AddInt64(&acc.Inflight, -1)
		atomic.AddInt64(&h.inflight, -1)

		if err != nil {
			lastErr = err
			// Don't retry if client already disconnected — context is dead,
			// every subsequent tryOnce will also fail instantly.
			if ctx.Err() != nil {
				log.Printf("[%s] account %s: request ended after %dms due to context error: %v", reqID, acc.ID, time.Since(start).Milliseconds(), ctx.Err())
				break
			}
			h.recent.add(err.Error())
			if h.cfg.debug.Load() {
				log.Printf("[%s] attempt %d/%d account=%s failed: %v", reqID, attempt, attempts, acc.ID, err)
			}
			continue
		}
		lastStatus = resp.StatusCode
		cyberPinned := false

		// --- Error classification & handling ---
		errClass := classifyStatus(resp.StatusCode)

		// For classes that need the body, read it now.
		if errClass != ErrorClassNone {
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			resp.Body.Close()
			errBody = bodyForInspection(nil, errBody)
			errBodyStr := string(errBody)

			if accountType == AccountTypeCodex && isCyberPolicyError(errBody) && !acc.CyberAccess {
				cyberAccessRetry = true
				lastErr = fmt.Errorf("upstream %s from non-cyber-access account %s: %s", resp.Status, acc.ID, errBodyStr)
				h.recent.add(lastErr.Error())
				if h.metrics != nil {
					h.metrics.incCyberPolicy(acc.ID, "retry_4xx")
				}
				if h.cfg.debug.Load() {
					log.Printf("[%s] retrying cyber_policy response from account %s on a cyber_access account", reqID, acc.ID)
				}
				continue
			}

			// Refine classification with body content.
			if acc.Type == AccountTypeCodex && errClass == ErrorClassInvalid && isCodexModelUnavailableError(errBody) {
				errClass = ErrorClassNotFound
				if h.cfg.debug.Load() {
					log.Printf("[%s] reclassified codex 400 as model/account mismatch for account %s", reqID, acc.ID)
				}
			}
			if acc.Type == AccountTypeClaude && isClaudeOrganizationDisabled(errBody) {
				h.disableAccountPermanently(acc, reqID, safeText(errBody))
				lastErr = fmt.Errorf("claude organization disabled for account %s", acc.ID)
				h.recent.add(lastErr.Error())
				continue
			}

			// Cloudflare bot challenges return 403 with HTML — not an auth failure.
			// Reclassify as transient so accounts don't accumulate auth penalties.
			if errClass == ErrorClassAuth && isCloudflareChallenge(errBody, resp.Header) {
				errClass = ErrorClassTransient
				if h.cfg.debug.Load() {
					log.Printf("[%s] reclassified 403 as cloudflare challenge for account %s", reqID, acc.ID)
				}
			}

			if errClass == ErrorClassPayment && isDeactivatedWorkspace(errBody) {
				acc.mu.Lock()
				acc.Dead = true
				acc.Penalty += 100.0
				acc.mu.Unlock()
				log.Printf("[%s] marking account %s as DEAD: %s", reqID, acc.ID, errBodyStr)
				if err := saveAccount(acc); err != nil {
					log.Printf("[%s] warning: failed to save dead account %s: %v", reqID, acc.ID, err)
				}
				lastErr = fmt.Errorf("account deactivated: %s", errBodyStr)
				h.recent.add(lastErr.Error())
				continue
			}

			switch errClass {
			case ErrorClassRateLimit:
				h.applyRateLimit(acc, resp.Header)
				acc.mu.Lock()
				acc.Penalty += 0.2
				acc.mu.Unlock()

			case ErrorClassAuth:
				markedDead, penaltyNow := applyProxyAuthFailure(acc, refreshFailed)
				if markedDead {
					log.Printf("[%s] account %s DEAD: %d refresh failed, body=%s", reqID, acc.ID, resp.StatusCode, errBodyStr)
					if err := saveAccount(acc); err != nil {
						log.Printf("[%s] warning: failed to save dead account %s: %v", reqID, acc.ID, err)
					}
				} else {
					var respHdrs []string
					for k, v := range resp.Header {
						respHdrs = append(respHdrs, fmt.Sprintf("%s=%s", k, v[0]))
					}
					log.Printf("[%s] account %s got %d, penalty now %.1f, body=%s, resp_headers=%v", reqID, acc.ID, resp.StatusCode, penaltyNow, errBodyStr, respHdrs)
				}

			case ErrorClassPayment:
				// Non-deactivated payment error — heavy penalty but not dead.
				acc.mu.Lock()
				acc.Penalty += 50.0
				acc.mu.Unlock()

			case ErrorClassTransient:
				acc.mu.Lock()
				acc.Penalty += 0.3
				acc.mu.Unlock()

			case ErrorClassNotFound:
				acc.mu.Lock()
				acc.Penalty += 0.1
				acc.mu.Unlock()
			}

			if errClass.Retryable() {
				if len(errBody) > 0 {
					lastErr = fmt.Errorf("upstream %s: %s", resp.Status, errBodyStr)
				} else {
					lastErr = fmt.Errorf("upstream %s", resp.Status)
				}
				h.recent.add(lastErr.Error())
				if h.cfg.debug.Load() {
					log.Printf("[%s] attempt %d/%d account=%s status=%d class=%s refreshFailed=%v",
						reqID, attempt, attempts, acc.ID, resp.StatusCode, errClass, refreshFailed)
				}
				continue
			}

			// Non-retryable error (400, unknown) — return to client.
			// Translate error body if format translation is active.
			if translateDir != TranslateNone {
				translated := translateErrorBody(errBody, targetFormat, sourceFormat)
				resp.Body = io.NopCloser(bytes.NewReader(translated))
			} else {
				resp.Body = io.NopCloser(strings.NewReader(errBodyStr))
			}
		}

		// Success path — reset exponential backoff.
		acc.mu.Lock()
		acc.BackoffLevel = 0
		acc.mu.Unlock()

		provider.ParseUsageHeaders(acc, resp.Header)
		h.logRateLimitResponseHeaders(reqID, acc.Type, resp.Header)

		// Snapshot rate limits from headers for use in SSE callback
		// (Claude SSE events carry 0% — real data comes from headers)
		acc.mu.Lock()
		headerPrimaryPct := acc.Usage.PrimaryUsedPercent
		headerSecondaryPct := acc.Usage.SecondaryUsedPercent
		acc.mu.Unlock()

		// Prepare response headers.
		copyHeader(w.Header(), resp.Header)
		removeHopByHopHeaders(w.Header())
		h.replaceUsageHeaders(w.Header())

		// Inject Claude models into model catalog response
		if strings.Contains(r.URL.Path, "codex/models") && resp.StatusCode == 200 {
			w.Header().Del("Content-Length")
			w.Header().Del("Content-Encoding") // We'll return uncompressed JSON
			respBody, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr == nil {
				modified := injectClaudeModels(respBody)
				w.WriteHeader(resp.StatusCode)
				w.Write(modified)
			} else {
				w.WriteHeader(http.StatusBadGateway)
			}
			return
		}

		flusher, _ := w.(http.Flusher)
		respContentType := resp.Header.Get("Content-Type")
		isSSE := provider.DetectsSSE(r.URL.Path, respContentType)
		// When translating to Responses API, the path-based SSE detection may
		// incorrectly flag non-SSE error responses (plain JSON 4xx/5xx) as SSE.
		// Check the actual content-type on error responses to avoid feeding
		// plain JSON through the SSE translator (which would silently drop it).
		if isSSE && resp.StatusCode >= 400 {
			if !strings.Contains(strings.ToLower(respContentType), "text/event-stream") {
				isSSE = false
			}
		}
		if isSSE {
			applyStreamingResponseHeaders(w.Header())
		}
		if h.cfg.debug.Load() {
			log.Printf("[%s] response: isSSE=%v content-type=%s translateDir=%d status=%d", reqID, isSSE, respContentType, translateDir, resp.StatusCode)
		}

		// Client wanted non-streaming but Codex requires streaming:
		// buffer SSE events and assemble a non-streaming response.
		if clientWantsNonStreaming && isSSE && translateDir == TranslateNone && accountType == AccountTypeCodex && strings.HasPrefix(r.URL.Path, "/v1/responses") {
			w.Header().Del("Content-Length")
			w.Header().Set("Content-Type", "application/json")

			bufWriter := &responsesBufferingWriter{model: requestedModel}
			inspectWriter := h.wrapBufferedSSEWithCyberDetector(bufWriter, accountType, acc, conversationID, requiredPlan, originIP, reqID, &cyberPinned)
			if _, err := io.Copy(inspectWriter, resp.Body); err != nil {
				if h.cfg.debug.Load() {
					log.Printf("[%s] buffering Responses SSE error: %v", reqID, err)
				}
			}
			resp.Body.Close()

			if h.shouldRetryBufferedSSEForCyberPolicy(cyberPinned, attempt, attempts, acc, reqID, "responses") {
				cyberAccessRetry = true
				continue
			}

			w.WriteHeader(resp.StatusCode)
			w.Write(bufWriter.Result())
		} else if clientWantsNonStreaming && isSSE && translateDir == TranslateClaudeToResponses {
			w.Header().Del("Content-Length")
			w.Header().Set("Content-Type", "application/json")

			usageCallback := func(data []byte) {
				if sampleBuf != nil {
					sampleBuf.Write(data)
				}
				if accountType == AccountTypeCodex && !acc.CyberAccess && isCyberPolicyError(data) {
					if h.pinConversationToCyberAccess(conversationID, accountType, requiredPlan, originIP, acc.ID, reqID) {
						cyberPinned = true
					}
					return
				}
				var obj map[string]any
				if json.Unmarshal(data, &obj) == nil {
					if ru := provider.ParseUsage(obj); ru != nil {
						if ru.PrimaryUsedPct == 0 && headerPrimaryPct > 0 {
							ru.PrimaryUsedPct = headerPrimaryPct
						}
						if ru.SecondaryUsedPct == 0 && headerSecondaryPct > 0 {
							ru.SecondaryUsedPct = headerSecondaryPct
						}
						ru.UserID = userID
						ru.OriginID = originID
						ru.AccountType = acc.Type
						h.recordUsage(acc, *ru)
					}
				}
			}

			bufWriter := &responsesToClaudeBufferingWriter{
				callback: usageCallback,
				debug:    h.cfg.debug.Load(),
				reqID:    reqID,
				model:    requestedModel,
			}

			if _, err := io.Copy(bufWriter, resp.Body); err != nil {
				if h.cfg.debug.Load() {
					log.Printf("[%s] buffering Claude SSE error: %v", reqID, err)
				}
			}
			resp.Body.Close()

			if h.shouldRetryBufferedSSEForCyberPolicy(cyberPinned, attempt, attempts, acc, reqID, "claude") {
				cyberAccessRetry = true
				continue
			}

			result := bufWriter.Result()
			w.WriteHeader(resp.StatusCode)
			w.Write(result)
		} else if clientWantsNonStreaming && isSSE && translateDir == TranslateImagesToResponses {
			w.Header().Del("Content-Length")
			w.Header().Set("Content-Type", "application/json")

			bufWriter := &responsesBufferingWriter{model: requestedModel}
			inspectWriter := h.wrapBufferedSSEWithCyberDetector(bufWriter, accountType, acc, conversationID, requiredPlan, originIP, reqID, &cyberPinned)
			if _, err := io.Copy(inspectWriter, resp.Body); err != nil {
				if h.cfg.debug.Load() {
					log.Printf("[%s] buffering Images SSE error: %v", reqID, err)
				}
			}
			resp.Body.Close()
			if h.shouldRetryBufferedSSEForCyberPolicy(cyberPinned, attempt, attempts, acc, reqID, "images") {
				cyberAccessRetry = true
				continue
			}
			result := bufWriter.Result()
			translated, err := translateResponsesToImagesGeneration(result, imagesResponseFormat)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			w.WriteHeader(resp.StatusCode)
			w.Write(translated)
		} else if clientWantsNonStreaming && isSSE && translateDir == TranslateCompletionsToResponses {
			w.Header().Del("Content-Length")
			w.Header().Set("Content-Type", "application/json")

			usageCallback := func(data []byte) {
				if sampleBuf != nil {
					sampleBuf.Write(data)
				}
				if accountType == AccountTypeCodex && !acc.CyberAccess && isCyberPolicyError(data) {
					if h.pinConversationToCyberAccess(conversationID, accountType, requiredPlan, originIP, acc.ID, reqID) {
						cyberPinned = true
					}
					return
				}
				var obj map[string]any
				if json.Unmarshal(data, &obj) == nil {
					if ru := provider.ParseUsage(obj); ru != nil {
						if ru.PrimaryUsedPct == 0 && headerPrimaryPct > 0 {
							ru.PrimaryUsedPct = headerPrimaryPct
						}
						if ru.SecondaryUsedPct == 0 && headerSecondaryPct > 0 {
							ru.SecondaryUsedPct = headerSecondaryPct
						}
						ru.UserID = userID
						ru.OriginID = originID
						ru.AccountType = acc.Type
						h.recordUsage(acc, *ru)
					}
				}
			}

			bufWriter := &responsesToCompletionsBufferingWriter{
				callback: usageCallback,
				debug:    h.cfg.debug.Load(),
				reqID:    reqID,
			}

			if _, err := io.Copy(bufWriter, resp.Body); err != nil {
				if h.cfg.debug.Load() {
					log.Printf("[%s] buffering completions SSE error: %v", reqID, err)
				}
			}
			resp.Body.Close()

			if h.shouldRetryBufferedSSEForCyberPolicy(cyberPinned, attempt, attempts, acc, reqID, "completions") {
				cyberAccessRetry = true
				continue
			}

			result := bufWriter.Result()
			w.WriteHeader(resp.StatusCode)
			w.Write(result)
		} else if clientWantsNonStreaming && isSSE && translateDir == TranslateChatToResponses {
			w.Header().Del("Content-Length")
			w.Header().Set("Content-Type", "application/json")

			usageCallback := func(data []byte) {
				if sampleBuf != nil {
					sampleBuf.Write(data)
				}
				if accountType == AccountTypeCodex && !acc.CyberAccess && isCyberPolicyError(data) {
					if h.pinConversationToCyberAccess(conversationID, accountType, requiredPlan, originIP, acc.ID, reqID) {
						cyberPinned = true
					}
					return
				}
				var obj map[string]any
				if json.Unmarshal(data, &obj) == nil {
					if ru := provider.ParseUsage(obj); ru != nil {
						if ru.PrimaryUsedPct == 0 && headerPrimaryPct > 0 {
							ru.PrimaryUsedPct = headerPrimaryPct
						}
						if ru.SecondaryUsedPct == 0 && headerSecondaryPct > 0 {
							ru.SecondaryUsedPct = headerSecondaryPct
						}
						ru.UserID = userID
						ru.OriginID = originID
						ru.AccountType = acc.Type
						h.recordUsage(acc, *ru)
					}
				}
			}

			bufWriter := &responsesToChatCompletionsBufferingWriter{
				callback: usageCallback,
				debug:    h.cfg.debug.Load(),
				reqID:    reqID,
			}

			if _, err := io.Copy(bufWriter, resp.Body); err != nil {
				if h.cfg.debug.Load() {
					log.Printf("[%s] buffering SSE error: %v", reqID, err)
				}
			}
			resp.Body.Close()

			if h.shouldRetryBufferedSSEForCyberPolicy(cyberPinned, attempt, attempts, acc, reqID, "chat") {
				cyberAccessRetry = true
				continue
			}

			result := bufWriter.Result()
			w.WriteHeader(resp.StatusCode)
			w.Write(result)
		} else if !isSSE && translateDir != TranslateNone {
			// Non-SSE format translation: buffer the whole body, translate, write.
			w.Header().Del("Content-Length")
			w.Header().Set("Content-Type", "application/json")

			respBody, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				h.recent.add(readErr.Error())
				h.metrics.inc("error", acc.ID)
				return
			}
			// Let the existing usage/sample logic see the raw body
			if sampleBuf != nil {
				sampleBuf.Write(respBody)
			}
			h.updateUsageFromBody(acc, respBody, userID, originID)

			var translated []byte
			if resp.StatusCode >= 400 {
				// Error response - translate error format
				if translateDir == TranslateClaudeToResponses {
					// Translate Codex error to Claude error format
					translated = translateErrorToClaudeFormat(respBody, resp.StatusCode)
				} else if translateDir == TranslateChatToResponses || translateDir == TranslateCompletionsToResponses || translateDir == TranslateImagesToResponses || translateDir == TranslateResponsesToClaude {
					translated = respBody // Pass through error as-is
				} else {
					translated = translateErrorBody(respBody, targetFormat, sourceFormat)
				}
			} else if translateDir == TranslateResponsesToClaude {
				var trErr error
				translated, trErr = translateClaudeRespToResponses(respBody)
				if trErr != nil {
					if h.cfg.debug.Load() {
						log.Printf("[%s] claude->responses translation error: %v", reqID, trErr)
					}
					translated = respBody
				}
			} else if translateDir == TranslateChatToResponses {
				var trErr error
				translated, trErr = translateResponsesToChatCompletions(respBody)
				if trErr != nil {
					if h.cfg.debug.Load() {
						log.Printf("[%s] responses->chat translation error: %v", reqID, trErr)
					}
					translated = respBody
				}
			} else if translateDir == TranslateCompletionsToResponses {
				var trErr error
				translated, trErr = translateResponsesToCompletions(respBody)
				if trErr != nil {
					if h.cfg.debug.Load() {
						log.Printf("[%s] responses->completions translation error: %v", reqID, trErr)
					}
					translated = respBody
				}
			} else if translateDir == TranslateImagesToResponses {
				var trErr error
				translated, trErr = translateResponsesToImagesGeneration(respBody, imagesResponseFormat)
				if trErr != nil {
					if h.cfg.debug.Load() {
						log.Printf("[%s] responses->images translation error: %v", reqID, trErr)
					}
					translated = respBody
				}
			} else {
				var trErr error
				translated, trErr = translateResponseBody(respBody, targetFormat, sourceFormat, requestedModel)
				if trErr != nil {
					if h.cfg.debug.Load() {
						log.Printf("[%s] response translation error: %v", reqID, trErr)
					}
					translated = respBody
				}
			}
			w.WriteHeader(resp.StatusCode)
			w.Write(translated)
		} else {
			// Normal response path (streaming or no translation needed)
			if isSSE && translateDir != TranslateNone {
				w.Header().Del("Content-Length")
				w.Header().Set("Content-Type", "text/event-stream")
			}
			w.WriteHeader(resp.StatusCode)

			var writer io.Writer = w
			var fw *flushWriter
			var hw *heartbeatWriter
			if isSSE && flusher != nil {
				fw = &flushWriter{w: w, f: flusher, flushInterval: h.cfg.flushInterval}
				hw = newHeartbeatWriter(fw, flusher)
				writer = hw
			}

			var claudeAccum *RequestUsage

			usageCallback := func(data []byte) {
				if accountType == AccountTypeCodex && !acc.CyberAccess && isCyberPolicyError(data) {
					if h.pinConversationToCyberAccess(conversationID, accountType, requiredPlan, originIP, acc.ID, reqID) {
						cyberPinned = true
						cancel()
					}
					return
				}
				var obj map[string]any
				if err := json.Unmarshal(data, &obj); err != nil {
					var arr []map[string]any
					if err2 := json.Unmarshal(data, &arr); err2 != nil || len(arr) == 0 {
						if h.cfg.debug.Load() {
							log.Printf("[%s] SSE callback: failed to parse JSON: %v", reqID, err)
						}
						return
					}
					obj = arr[0]
				}
				ru := provider.ParseUsage(obj)
				if ru == nil {
					return
				}

				if acc.Type == AccountTypeClaude {
					if claudeAccum == nil {
						claudeAccum = ru
					} else {
						claudeAccum.OutputTokens = ru.OutputTokens
						claudeAccum.BillableTokens = clampNonNegative(
							claudeAccum.InputTokens - claudeAccum.CachedInputTokens - claudeAccum.CacheCreationTokens + ru.OutputTokens)
						ru = claudeAccum
						claudeAccum = nil
						ru.AccountID = acc.ID
						ru.UserID = userID
						ru.OriginID = originID
						ru.AccountType = acc.Type
						acc.mu.Lock()
						ru.PlanType = acc.PlanType
						acc.mu.Unlock()
						if ru.PrimaryUsedPct == 0 && headerPrimaryPct > 0 {
							ru.PrimaryUsedPct = headerPrimaryPct
						}
						if ru.SecondaryUsedPct == 0 && headerSecondaryPct > 0 {
							ru.SecondaryUsedPct = headerSecondaryPct
						}
						if ru.Model == "" {
							ru.Model = requestedModel
						}
						h.recordUsage(acc, *ru)
					}
					return
				}
				ru.AccountID = acc.ID
				ru.UserID = userID
				ru.OriginID = originID
				ru.AccountType = acc.Type
				acc.mu.Lock()
				ru.PlanType = acc.PlanType
				acc.mu.Unlock()
				if ru.Model == "" {
					ru.Model = requestedModel
				}
				h.recordUsage(acc, *ru)
			}

			if isSSE {
				if translateDir == TranslateCompletionsToResponses {
					writer = &responsesToCompletionsWriter{
						w:        writer,
						callback: usageCallback,
						debug:    h.cfg.debug.Load(),
						reqID:    reqID,
					}
				} else if translateDir == TranslateChatToResponses {
					writer = &responsesToChatCompletionsWriter{
						w:        writer,
						callback: usageCallback,
						debug:    h.cfg.debug.Load(),
						reqID:    reqID,
					}
				} else if translateDir == TranslateResponsesToClaude {
					// Claude SSE response → Responses API SSE
					writer = &claudeToResponsesWriter{
						w:        writer,
						callback: usageCallback,
						debug:    h.cfg.debug.Load(),
						reqID:    reqID,
					}
				} else if translateDir == TranslateClaudeToResponses {
					// Responses API SSE → Claude SSE
					writer = &responsesToClaudeWriter{
						w:        writer,
						callback: usageCallback,
						debug:    h.cfg.debug.Load(),
						reqID:    reqID,
					}
				} else if translateDir != TranslateNone {
					// Response direction is opposite of request direction:
					// TranslateOAIToClaude request → response comes in Claude format → translate to OAI
					// TranslateClaudeToOAI request → response comes in OAI format → translate to Claude
					responseDir := TranslateClaudeToOAI
					if translateDir == TranslateClaudeToOAI {
						responseDir = TranslateOAIToClaude
					}
					writer = &sseTranslateWriter{
						w:         writer,
						direction: responseDir,
						callback:  usageCallback,
						debug:     h.cfg.debug.Load(),
						reqID:     reqID,
					}
				} else {
					needsPolicyInspection := accountType == AccountTypeCodex && !acc.CyberAccess
					needsUsageInspection := sampleBuf != nil
					if needsPolicyInspection || needsUsageInspection {
						interceptWriter := &sseInterceptWriter{
							w:        writer,
							callback: usageCallback,
						}
						if needsPolicyInspection {
							suppressor := &cyberPolicyHTTPSuppressor{
								h:              h,
								reqID:          reqID,
								conversationID: conversationID,
								requiredPlan:   requiredPlan,
								clientIP:       originIP,
								accountID:      acc.ID,
								pinned:         &cyberPinned,
							}
							interceptWriter.onEvent = suppressor.onEvent
						}
						writer = interceptWriter
					}
				}
			}

			var idleReader *idleTimeoutReader
			if isSSE && h.cfg.streamIdleTimeout > 0 {
				idleReader = newIdleTimeoutReader(resp.Body, h.cfg.streamIdleTimeout, cancel)
				resp.Body = idleReader
			}

			_, copyErr := io.Copy(writer, resp.Body)
			resp.Body.Close()
			if hw != nil {
				hw.Stop()
			}
			if fw != nil {
				fw.stop()
			}

			if claudeAccum != nil {
				claudeAccum.AccountID = acc.ID
				claudeAccum.UserID = userID
				claudeAccum.OriginID = originID
				claudeAccum.AccountType = acc.Type
				acc.mu.Lock()
				claudeAccum.PlanType = acc.PlanType
				acc.mu.Unlock()
				if claudeAccum.PrimaryUsedPct == 0 && headerPrimaryPct > 0 {
					claudeAccum.PrimaryUsedPct = headerPrimaryPct
				}
				if claudeAccum.SecondaryUsedPct == 0 && headerSecondaryPct > 0 {
					claudeAccum.SecondaryUsedPct = headerSecondaryPct
				}
				if claudeAccum.Model == "" {
					claudeAccum.Model = requestedModel
				}
				h.recordUsage(acc, *claudeAccum)
			}

			if copyErr != nil {
				if ctx.Err() == nil {
					// Only record as error if client didn't disconnect.
					h.recent.add(copyErr.Error())
					h.metrics.inc("error", acc.ID)
				}
				if idleReader != nil {
					log.Printf("[%s] SSE stream error (account=%s): %v", reqID, acc.ID, copyErr)
				}
				return
			}

			respSample := []byte(nil)
			if sampleBuf != nil {
				respSample = sampleBuf.Bytes()
			}
			if h.cfg.logBodies && len(respSample) > 0 {
				log.Printf("[%s] response body sample (%d bytes): %s", reqID, len(respSample), safeText(respSample))
			}
			if !isSSE && len(respSample) > 0 {
				h.updateUsageFromBody(acc, respSample, userID, originID)
			}
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if conversationID == "" {
				if sampleBuf != nil && sampleBuf.Len() > 0 {
					conversationID = extractConversationIDFromSSE(sampleBuf.Bytes())
				}
			}
			if conversationID != "" && !cyberPinned {
				h.pool.pin(conversationID, acc.ID)
			}
			acc.mu.Lock()
			acc.LastUsed = time.Now()
			if acc.Penalty > 0 {
				acc.Penalty *= 0.5
				if acc.Penalty < 0.01 {
					acc.Penalty = 0
				}
			}
			acc.mu.Unlock()
		}

		h.metrics.inc(strconv.Itoa(resp.StatusCode), acc.ID)

		if h.cfg.debug.Load() {
			log.Printf("[%s] done status=%d account=%s duration_ms=%d", reqID, resp.StatusCode, acc.ID, time.Since(start).Milliseconds())
		}
		return
	}

	// All attempts failed.
	if ctx.Err() != nil {
		// Client disconnected — no point sending an error response.
		return
	}
	status := http.StatusBadGateway
	if lastStatus == http.StatusTooManyRequests {
		status = http.StatusTooManyRequests
	}
	if lastErr == nil {
		lastErr = errors.New("all attempts failed")
	}
	http.Error(w, lastErr.Error(), status)
}

func (h *proxyHandler) proxyRequestWebSocket(
	w http.ResponseWriter,
	r *http.Request,
	reqID string,
	userID string,
	originID string,
	provider Provider,
	targetBase *url.URL,
) {
	start := time.Now()
	accountType := provider.Type()

	conversationID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	if conversationID == "" {
		conversationID = extractConversationIDFromHeaders(r.Header)
	}
	// Use Claude Code session ID as fallback for conversation stickiness
	if conversationID == "" {
		for _, key := range []string{"X-Claude-Code-Session-Id", "x-claude-code-session-id"} {
			if v := strings.TrimSpace(r.Header.Get(key)); v != "" {
				conversationID = v
				break
			}
		}
	}

	requiredPlan := requiredPlanForRequest(accountType, r, "")
	clientIP := getClientIP(r)
	selectionConversationID := conversationID
	if selectionConversationID == "" && accountType == AccountTypeCodex {
		fallbackID := userID
		if fallbackID == "" {
			fallbackID = originID
		}
		if fallbackID == "" {
			fallbackID = clientIP
		}
		selectionConversationID = "cyber-fallback:" + fallbackID
	}
	acc := h.pool.candidate(selectionConversationID, map[string]bool{}, accountType, requiredPlan, clientIP)
	if acc == nil {
		http.Error(w, fmt.Sprintf("no live %s accounts", accountType), http.StatusServiceUnavailable)
		return
	}

	atomic.AddInt64(&acc.Inflight, 1)
	atomic.AddInt64(&h.inflight, 1)
	// inflightAcc tracks the account that currently owns the inflight
	// credit. The codex websocket relay swaps it to a cyber-access
	// account on cyber_policy; we transfer the credit at that moment
	// so the deferred decrement still touches the right account.
	inflightAcc := acc
	defer func() {
		atomic.AddInt64(&inflightAcc.Inflight, -1)
		atomic.AddInt64(&h.inflight, -1)
	}()

	refreshFailed := false
	if !h.cfg.disableRefresh && h.needsRefresh(acc) {
		if err := h.refreshAccount(r.Context(), acc); err != nil {
			if isRateLimitError(err) {
				h.applyRateLimit(acc, nil)
			} else {
				refreshFailed = true
			}
			if h.cfg.debug.Load() {
				log.Printf("[%s] refresh %s failed before websocket request: %v", reqID, acc.ID, err)
			}
		}
	}

	acc.mu.Lock()
	access := acc.AccessToken
	acc.mu.Unlock()
	if access == "" {
		http.Error(w, fmt.Sprintf("account %s has empty access token", acc.ID), http.StatusServiceUnavailable)
		return
	}

	outURL := new(url.URL)
	*outURL = *r.URL
	outURL.Scheme = targetBase.Scheme
	outURL.Host = targetBase.Host
	outURL.Path = singleJoin(targetBase.Path, provider.NormalizePath(r.URL.Path))

	// For Claude OAuth tokens, add beta=true query param (required for OAuth to work)
	if provider.Type() == AccountTypeClaude && strings.HasPrefix(access, "sk-ant-oat") {
		q := outURL.Query()
		q.Set("beta", "true")
		outURL.RawQuery = q.Encode()
	}

	// Build upstream headers: clone client headers, replace auth.
	upstreamHeaders := cloneHeader(r.Header)
	upstreamHeaders.Del("Authorization")
	upstreamHeaders.Del("ChatGPT-Account-ID")
	upstreamHeaders.Del("X-Api-Key")
	upstreamHeaders.Del("x-goog-api-key")
	removeConflictingProxyHeaders(upstreamHeaders)

	// Use a temporary request to set provider auth headers.
	tmpReq := &http.Request{Header: upstreamHeaders}
	provider.SetAuthHeaders(tmpReq, acc)
	upstreamHeaders = tmpReq.Header

	if h.cfg.debug.Load() {
		log.Printf("[%s] websocket tunnel -> %s (account=%s)", reqID, outURL.String(), acc.ID)
	}

	cyberPinned := false
	relayLabel := fmt.Sprintf("%s account=%s", reqID, acc.ID)
	readLimit := effectiveWebSocketReadLimit(accountType, h.cfg.websocketReadLimit)
	downstreamHeartbeatInterval := time.Duration(0)
	if accountType == AccountTypeCodex {
		downstreamHeartbeatInterval = h.cfg.websocketHeartbeatInterval
	}

	// Every Codex websocket goes through the cyber-aware relay so we can
	// universally suppress cyber_policy frames before they reach the
	// client. Non-cyber accounts additionally get a one-shot hot-swap to
	// a cyber_access account on the first cyber_policy hit.
	if accountType == AccountTypeCodex {
		swap := h.relayCodexWithCyberSwap(w, r, codexCyberSwapOptions{
			ReqID:                       reqID,
			Provider:                    provider,
			InitialAccount:              acc,
			InitialOutURL:               outURL,
			InitialUpstreamHeaders:      upstreamHeaders,
			ConversationID:              conversationID,
			RequiredPlan:                requiredPlan,
			ClientIP:                    clientIP,
			IdleTimeout:                 h.cfg.websocketIdleTimeout,
			DownstreamHeartbeatInterval: downstreamHeartbeatInterval,
			ReadLimit:                   readLimit,
			CompressionEnabled:          h.cfg.websocketCompression,
			LogLabel:                    relayLabel,
			SetActiveAccount: func(next *Account) {
				prev := inflightAcc
				if prev == next || next == nil {
					return
				}
				atomic.AddInt64(&next.Inflight, 1)
				atomic.AddInt64(&prev.Inflight, -1)
				inflightAcc = next
			},
		})
		finalAcc := acc
		if swap.finalAccount != nil {
			finalAcc = swap.finalAccount
		}
		if swap.err != nil {
			h.recent.add(swap.err.Error())
			h.metrics.inc("error", finalAcc.ID)
			if h.cfg.debug.Load() {
				log.Printf("[%s] websocket tunnel error (account=%s): %v", reqID, finalAcc.ID, swap.err)
			}
			return
		}
		if swap.statusCode != 0 {
			h.metrics.inc(strconv.Itoa(swap.statusCode), finalAcc.ID)
		}
		h.applyWebSocketStatusEffects(reqID, finalAcc, conversationID, swap.swapped, refreshFailed, swap.statusCode)
		if h.cfg.debug.Load() {
			log.Printf("[%s] websocket done status=%d account=%s user=%s origin=%s duration_ms=%d cyber_swapped=%v", reqID, swap.statusCode, finalAcc.ID, userID, originID, time.Since(start).Milliseconds(), swap.swapped)
		}
		return
	}

	statusCode, err := relayWebSocket(w, r, outURL, upstreamHeaders, webSocketRelayOptions{
		IdleTimeout:                 h.cfg.websocketIdleTimeout,
		DownstreamHeartbeatInterval: downstreamHeartbeatInterval,
		ReadLimit:                   readLimit,
		CompressionEnabled:          h.cfg.websocketCompression,
		LogLabel:                    relayLabel,
		Debug:                       h.cfg.debug.Load(),
	})

	if err != nil {
		h.recent.add(err.Error())
		h.metrics.inc("error", acc.ID)
		if h.cfg.debug.Load() {
			log.Printf("[%s] websocket tunnel error (account=%s): %v", reqID, acc.ID, err)
		}
		return
	}

	if statusCode != 0 {
		h.metrics.inc(strconv.Itoa(statusCode), acc.ID)
	}

	h.applyWebSocketStatusEffects(reqID, acc, conversationID, cyberPinned, refreshFailed, statusCode)

	if h.cfg.debug.Load() {
		log.Printf("[%s] websocket done status=%d account=%s user=%s origin=%s duration_ms=%d", reqID, statusCode, acc.ID, userID, originID, time.Since(start).Milliseconds())
	}
}

// applyWebSocketStatusEffects runs the post-relay account bookkeeping
// (rate-limit cooldown, auth-failure marking, success-path penalty
// decay, conversation pinning) shared between the Codex cyber-aware
// relay and the legacy passthrough/Claude/Gemini relay.
func (h *proxyHandler) applyWebSocketStatusEffects(reqID string, acc *Account, conversationID string, cyberPinned, refreshFailed bool, statusCode int) {
	switch {
	case statusCode == http.StatusTooManyRequests:
		h.applyRateLimit(acc, nil)
		acc.mu.Lock()
		acc.Penalty += 1.0
		acc.mu.Unlock()
	case statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden:
		markedDead, _ := applyProxyAuthFailure(acc, refreshFailed)
		if markedDead {
			if err := saveAccount(acc); err != nil {
				log.Printf("[%s] warning: failed to save dead account %s: %v", reqID, acc.ID, err)
			}
		}
	case statusCode == http.StatusSwitchingProtocols || (statusCode >= 200 && statusCode < 300):
		if conversationID != "" && !cyberPinned {
			h.pool.pin(conversationID, acc.ID)
		}
		acc.mu.Lock()
		acc.LastUsed = time.Now()
		acc.BackoffLevel = 0
		if acc.Penalty > 0 {
			acc.Penalty *= 0.5
			if acc.Penalty < 0.01 {
				acc.Penalty = 0
			}
		}
		acc.mu.Unlock()
	}
}

func (h *proxyHandler) proxyPassthroughWebSocket(
	w http.ResponseWriter,
	r *http.Request,
	reqID string,
	providerType AccountType,
	provider Provider,
	targetBase *url.URL,
	start time.Time,
) {
	outURL := new(url.URL)
	*outURL = *r.URL
	outURL.Scheme = targetBase.Scheme
	outURL.Host = targetBase.Host
	outURL.Path = singleJoin(targetBase.Path, provider.NormalizePath(r.URL.Path))

	// For Claude OAuth passthrough tokens, add beta=true query param.
	if providerType == AccountTypeClaude {
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimPrefix(auth, "Bearer ")
			if strings.HasPrefix(token, "sk-ant-oat") {
				q := outURL.Query()
				q.Set("beta", "true")
				outURL.RawQuery = q.Encode()
			}
		}
	}

	upstreamHeaders := cloneHeader(r.Header)
	removeConflictingProxyHeaders(upstreamHeaders)
	if providerType == AccountTypeClaude && upstreamHeaders.Get("anthropic-version") == "" {
		upstreamHeaders.Set("anthropic-version", ccAnthropicVersion)
	}

	if h.cfg.debug.Load() {
		log.Printf("[%s] passthrough websocket tunnel -> %s", reqID, outURL.String())
	}

	readLimit := effectiveWebSocketReadLimit(providerType, h.cfg.websocketReadLimit)
	downstreamHeartbeatInterval := time.Duration(0)
	if providerType == AccountTypeCodex {
		downstreamHeartbeatInterval = h.cfg.websocketHeartbeatInterval
	}
	statusCode, err := relayWebSocket(w, r, outURL, upstreamHeaders, webSocketRelayOptions{
		IdleTimeout:                 h.cfg.websocketIdleTimeout,
		DownstreamHeartbeatInterval: downstreamHeartbeatInterval,
		ReadLimit:                   readLimit,
		CompressionEnabled:          h.cfg.websocketCompression,
		LogLabel:                    reqID + " passthrough",
		Debug:                       h.cfg.debug.Load(),
	})

	if err != nil {
		h.recent.add(err.Error())
		h.metrics.inc("error", "passthrough")
		if h.cfg.debug.Load() {
			log.Printf("[%s] passthrough websocket tunnel error: %v", reqID, err)
		}
		return
	}
	if statusCode != 0 {
		h.metrics.inc(strconv.Itoa(statusCode), "passthrough")
	}
	if h.cfg.debug.Load() {
		log.Printf("[%s] passthrough websocket done status=%d duration_ms=%d", reqID, statusCode, time.Since(start).Milliseconds())
	}
}

// relayWebSocket accepts a client WS upgrade and opens a separate WS
// connection to the upstream server, then relays JSON messages between
// them at the application level. Unlike raw TCP tunneling, this works
// through Cloudflare (which negotiates h2 and can't tunnel raw WS
// frames) because each side is an independent WS connection.
//
// Flow:
//  1. Dial upstream WS first so we can mirror selected handshake state.
//  2. Accept the client WS upgrade with the negotiated subprotocol.
//  3. Relay messages bidirectionally until either side closes.
type webSocketRelayOptions struct {
	IdleTimeout                 time.Duration
	DownstreamHeartbeatInterval time.Duration
	ReadLimit                   int64
	CompressionEnabled          bool
	LogLabel                    string
	Debug                       bool
	OnUpstreamResponse          func(*http.Response)
	OnUpstreamMessage           func([]byte) error
	OnClientMessage             func([]byte) error
}

const codexWebSocketReadLimit = 512 * 1024 * 1024

func effectiveWebSocketReadLimit(accountType AccountType, configured int64) int64 {
	if configured <= 0 {
		configured = 64 * 1024 * 1024
	}
	if accountType == AccountTypeCodex && configured < codexWebSocketReadLimit {
		return codexWebSocketReadLimit
	}
	return configured
}

func relayWebSocket(
	w http.ResponseWriter,
	clientReq *http.Request,
	upstreamURL *url.URL,
	upstreamHeaders http.Header,
	opts webSocketRelayOptions,
) (int, error) {
	ctx := clientReq.Context()

	wsURL := *upstreamURL
	upstreamConn, upstreamResp, _, err := dialUpstreamWebSocket(ctx, &wsURL, upstreamHeaders, clientReq.Header, opts.ReadLimit, opts.CompressionEnabled)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return 0, err
	}
	defer upstreamConn.CloseNow()
	if opts.OnUpstreamResponse != nil {
		opts.OnUpstreamResponse(upstreamResp)
	}

	if turnState := upstreamResp.Header.Get("x-codex-turn-state"); turnState != "" {
		w.Header().Set("x-codex-turn-state", turnState)
	}

	acceptOpts := &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	}
	if opts.CompressionEnabled {
		acceptOpts.CompressionMode = websocket.CompressionNoContextTakeover
	}
	if subprotocol := upstreamConn.Subprotocol(); subprotocol != "" {
		acceptOpts.Subprotocols = []string{subprotocol}
	}

	clientConn, err := websocket.Accept(w, clientReq, acceptOpts)
	if err != nil {
		upstreamConn.Close(websocket.StatusInternalError, "client accept failed")
		return 0, fmt.Errorf("accept client WS: %w", err)
	}
	defer clientConn.CloseNow()
	clientConn.SetReadLimit(opts.ReadLimit)

	log.Printf("[ws-relay %s] connected to %s, relaying messages", opts.LogLabel, wsURL.Host)

	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()

	clientWriter := &webSocketWriter{conn: clientConn}
	upstreamWriter := &webSocketWriter{conn: upstreamConn}

	errc := make(chan error, 2)
	stopHeartbeat := startWebSocketHeartbeat(relayCtx, clientWriter, opts.DownstreamHeartbeatInterval)
	defer stopHeartbeat()

	go func() {
		errc <- relayMessages(relayCtx, upstreamConn, clientWriter, opts.LogLabel, "upstream->client", opts.IdleTimeout, opts.Debug, opts.OnUpstreamMessage)
	}()
	go func() {
		errc <- relayMessages(relayCtx, clientConn, upstreamWriter, opts.LogLabel, "client->upstream", opts.IdleTimeout, opts.Debug, opts.OnClientMessage)
	}()

	relayErr := <-errc
	relayCancel()

	closeCode := websocket.StatusNormalClosure
	closeMsg := "relay ended"
	if relayErr != nil {
		if code := websocket.CloseStatus(relayErr); code != -1 {
			closeCode = code
		}
		closeMsg = relayErr.Error()
		if len(closeMsg) > 120 {
			closeMsg = closeMsg[:120]
		}
	}
	clientConn.Close(closeCode, closeMsg)
	upstreamConn.Close(closeCode, closeMsg)

	if relayErr != nil && !errors.Is(relayErr, context.Canceled) &&
		!strings.Contains(relayErr.Error(), "closed") &&
		!strings.Contains(relayErr.Error(), "EOF") &&
		websocket.CloseStatus(relayErr) == -1 {
		return 101, relayErr
	}
	return 101, nil
}

type webSocketWriter struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (w *webSocketWriter) Write(ctx context.Context, msgType websocket.MessageType, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.conn.Write(ctx, msgType, data)
}

func (w *webSocketWriter) Ping(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.conn.Ping(ctx)
}

func (w *webSocketWriter) CopyFrom(ctx context.Context, msgType websocket.MessageType, src io.Reader) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	writer, err := w.conn.Writer(ctx, msgType)
	if err != nil {
		return err
	}
	_, copyErr := io.CopyBuffer(writer, src, make([]byte, 32*1024))
	closeErr := writer.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func startWebSocketHeartbeat(ctx context.Context, dst *webSocketWriter, interval time.Duration) func() {
	if interval <= 0 {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		timer := time.NewTimer(interval)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-timer.C:
				if err := dst.Ping(ctx); err != nil {
					return
				}
				timer.Reset(interval)
			}
		}
	}()
	return func() { close(done) }
}

// relayMessages reads messages from src and writes them to dst until
// the context is cancelled or an error occurs. If idleTimeout > 0 the
// connection is force-closed when no frame arrives within that window.
//
// We use a time.AfterFunc watchdog instead of context.WithTimeout because
// coder/websocket closes the connection when the read context is cancelled,
// which would tear the relay down on every successful frame.
func relayMessages(ctx context.Context, src *websocket.Conn, dst *webSocketWriter, logLabel, label string, idleTimeout time.Duration, debug bool, onMessage func([]byte) error) error {
	if !debug && onMessage == nil {
		return relayMessagesStreaming(ctx, src, dst, label, idleTimeout)
	}
	var idleTimer *time.Timer
	if idleTimeout > 0 {
		idleTimer = time.AfterFunc(idleTimeout, func() {
			src.Close(websocket.StatusPolicyViolation, fmt.Sprintf("idle for %v", idleTimeout))
		})
		defer idleTimer.Stop()
	}
	for {
		if idleTimer != nil {
			idleTimer.Reset(idleTimeout)
		}
		msgType, data, err := src.Read(ctx)
		if err != nil {
			return fmt.Errorf("%s read: %w", label, err)
		}
		if debug {
			logRelayFrame(logLabel, label, msgType, data)
		}
		if onMessage != nil {
			if err := onMessage(data); err != nil {
				return err
			}
		}
		if err := dst.Write(ctx, msgType, data); err != nil {
			return fmt.Errorf("%s write: %w", label, err)
		}
	}
}

func relayMessagesStreaming(ctx context.Context, src *websocket.Conn, dst *webSocketWriter, label string, idleTimeout time.Duration) error {
	var idleTimer *time.Timer
	if idleTimeout > 0 {
		idleTimer = time.AfterFunc(idleTimeout, func() {
			src.Close(websocket.StatusPolicyViolation, fmt.Sprintf("idle for %v", idleTimeout))
		})
		defer idleTimer.Stop()
	}
	for {
		if idleTimer != nil {
			idleTimer.Reset(idleTimeout)
		}
		msgType, reader, err := src.Reader(ctx)
		if err != nil {
			return fmt.Errorf("%s read: %w", label, err)
		}
		if err := dst.CopyFrom(ctx, msgType, reader); err != nil {
			return fmt.Errorf("%s write: %w", label, err)
		}
	}
}

func logRelayFrame(logLabel, label string, msgType websocket.MessageType, data []byte) {
	summary := data
	suffix := ""
	if len(summary) > 200 {
		summary = summary[:200]
		suffix = "..."
	}
	log.Printf("[ws-relay %s] %s: type=%v len=%d %s%s", logLabel, label, msgType, len(data), string(summary), suffix)
}

func (h *proxyHandler) proxyRequestStreamed(w http.ResponseWriter, r *http.Request, reqID, userID, originID string, provider Provider, targetBase *url.URL) {
	start := time.Now()
	accountType := provider.Type()

	requiredPlan := requiredPlanForRequest(accountType, r, "")
	clientIP := getClientIP(r)
	acc := h.pool.candidate("", map[string]bool{}, accountType, requiredPlan, clientIP)
	if acc == nil {
		http.Error(w, fmt.Sprintf("no live %s accounts", accountType), http.StatusServiceUnavailable)
		return
	}

	atomic.AddInt64(&acc.Inflight, 1)
	atomic.AddInt64(&h.inflight, 1)
	defer func() {
		atomic.AddInt64(&acc.Inflight, -1)
		atomic.AddInt64(&h.inflight, -1)
	}()

	// For streamed-body requests we can't inspect the body, so pass nil.
	// clientOrDefaultTimeout will still check X-Stainless-Timeout header.
	timeout := clientOrDefaultTimeout(r, h.cfg.requestTimeout, h.cfg.streamTimeout, nil)

	ctx := r.Context()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	// Refresh before building headers to ensure we use the latest token.
	refreshFailed := false
	if !h.cfg.disableRefresh && h.needsRefresh(acc) {
		if err := h.refreshAccount(ctx, acc); err != nil {
			if isRateLimitError(err) {
				h.applyRateLimit(acc, nil)
			} else {
				refreshFailed = true
			}
			if h.cfg.debug.Load() {
				log.Printf("[%s] refresh %s failed before streamed request: %v", reqID, acc.ID, err)
			}
		}
	}

	outURL := new(url.URL)
	*outURL = *r.URL
	outURL.Scheme = targetBase.Scheme
	outURL.Host = targetBase.Host
	outURL.Path = singleJoin(targetBase.Path, provider.NormalizePath(r.URL.Path))

	acc.mu.Lock()
	access := acc.AccessToken
	acc.mu.Unlock()
	if access == "" {
		http.Error(w, fmt.Sprintf("account %s has empty access token", acc.ID), http.StatusServiceUnavailable)
		return
	}

	// For Claude OAuth tokens, add beta=true query param (required for OAuth to work)
	if provider.Type() == AccountTypeClaude && strings.HasPrefix(access, "sk-ant-oat") {
		q := outURL.Query()
		q.Set("beta", "true")
		outURL.RawQuery = q.Encode()
	}

	var reqSample *bytes.Buffer
	var body io.Reader = r.Body
	if h.cfg.logBodies && h.cfg.bodyLogLimit > 0 {
		reqSample = &bytes.Buffer{}
		body = io.TeeReader(r.Body, &limitedWriter{w: reqSample, n: h.cfg.bodyLogLimit})
	}

	outReq, err := http.NewRequestWithContext(ctx, r.Method, outURL.String(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	outReq.Host = targetBase.Host
	outReq.Header = cloneHeader(r.Header)
	removeHopByHopHeaders(outReq.Header)
	removeConflictingProxyHeaders(outReq.Header)
	if r.ContentLength >= 0 {
		outReq.ContentLength = r.ContentLength
	}

	// Always overwrite client-provided auth; the proxy is the single source of truth.
	outReq.Header.Del("Authorization")
	outReq.Header.Del("X-Api-Key")
	outReq.Header.Del("x-goog-api-key")

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

	// Use provider's SetAuthHeaders method for provider-specific auth
	provider.SetAuthHeaders(outReq, acc)

	// Force uncompressed responses — SSE frame parsing and client decompression
	// break on gzip-compressed streams that split across TCP segments.
	outReq.Header.Set("Accept-Encoding", "identity")

	if h.cfg.debug.Load() {
		authHeader := outReq.Header.Get("Authorization")
		authLen := len(authHeader)
		authPreview := ""
		if authLen > 20 {
			authPreview = authHeader[:20] + "..."
		} else if authLen > 0 {
			authPreview = authHeader
		}
		log.Printf("[%s] streamed -> %s %s (account=%s account_id=%s auth_len=%d auth=%s)", reqID, outReq.Method, outReq.URL.String(), acc.ID, acc.AccountID, authLen, authPreview)
	}

	resp, err := h.transport.RoundTrip(outReq)
	captureCodexResponseState(acc, resp, reqID)
	if err != nil {
		acc.mu.Lock()
		acc.Penalty += 0.2
		acc.mu.Unlock()
		h.recent.add(err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if h.cfg.logBodies && reqSample != nil && reqSample.Len() > 0 {
		log.Printf("[%s] request body sample (%d bytes): %s", reqID, reqSample.Len(), safeText(reqSample.Bytes()))
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		h.applyRateLimit(acc, resp.Header)
		acc.mu.Lock()
		acc.Penalty += 0.2
		acc.mu.Unlock()
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Log the error body for debugging
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		decompressed := bodyForInspection(nil, errBody) // nil request - will auto-detect gzip
		log.Printf("[%s] account %s got %d from %s, body=%s", reqID, acc.ID, resp.StatusCode, outReq.URL.Host, safeText(decompressed))
		// Replace body so client still gets the error
		resp.Body = io.NopCloser(bytes.NewReader(errBody))

		markedDead, _ := applyProxyAuthFailure(acc, refreshFailed)
		if markedDead {
			if err := saveAccount(acc); err != nil {
				log.Printf("[%s] warning: failed to save dead account %s: %v", reqID, acc.ID, err)
			}
		}
	} else if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
		acc.mu.Lock()
		acc.Penalty += 0.3
		acc.mu.Unlock()
	}

	provider.ParseUsageHeaders(acc, resp.Header)
	h.logRateLimitResponseHeaders(reqID, acc.Type, resp.Header)

	// Snapshot rate limits from headers for use in SSE callback
	acc.mu.Lock()
	headerPrimaryPct := acc.Usage.PrimaryUsedPercent
	headerSecondaryPct := acc.Usage.SecondaryUsedPercent
	acc.mu.Unlock()

	// Write response to client.
	copyHeader(w.Header(), resp.Header)
	removeHopByHopHeaders(w.Header())
	h.replaceUsageHeaders(w.Header())
	flusher, _ := w.(http.Flusher)
	respContentType := resp.Header.Get("Content-Type")
	isSSE := provider.DetectsSSE(r.URL.Path, respContentType)
	if isSSE {
		applyStreamingResponseHeaders(w.Header())
	}
	w.WriteHeader(resp.StatusCode)

	var writer io.Writer = w
	var fw *flushWriter
	var hw2 *heartbeatWriter
	if isSSE && flusher != nil {
		fw = &flushWriter{w: w, f: flusher, flushInterval: h.cfg.flushInterval}
		hw2 = newHeartbeatWriter(fw, flusher)
		writer = hw2
	}

	// Tee a bounded sample for usage extraction and conversation pinning.
	sampleLimit := int64(16 * 1024)
	if h.cfg.logBodies && h.cfg.bodyLogLimit > 0 {
		sampleLimit = h.cfg.bodyLogLimit
	}
	sampleBuf := &bytes.Buffer{}
	resp.Body = struct {
		io.Reader
		io.Closer
	}{
		Reader: io.TeeReader(resp.Body, &limitedWriter{w: sampleBuf, n: sampleLimit}),
		Closer: resp.Body,
	}

	// Claude sends usage across two SSE events (message_start: input, message_delta: output).
	// Accumulate them into a single RequestUsage before recording.
	// Declared outside the if-block so it can be flushed after io.Copy completes.
	var claudeAccum2 *RequestUsage
	cyberPinned := false
	conversationID := extractConversationIDFromHeaders(r.Header)
	// Use Claude Code session ID as fallback for conversation stickiness
	if conversationID == "" {
		for _, key := range []string{"X-Claude-Code-Session-Id", "x-claude-code-session-id"} {
			if v := strings.TrimSpace(r.Header.Get(key)); v != "" {
				conversationID = v
				break
			}
		}
	}

	if isSSE {
		interceptWriter := &sseInterceptWriter{
			w: writer,
			callback: func(data []byte) {
				if accountType == AccountTypeCodex && !acc.CyberAccess && isCyberPolicyError(data) {
					if h.pinConversationToCyberAccess(conversationID, accountType, requiredPlan, clientIP, acc.ID, reqID) {
						cyberPinned = true
						cancel()
					}
					return
				}
				var obj map[string]any
				if err := json.Unmarshal(data, &obj); err != nil {
					var arr []map[string]any
					if err2 := json.Unmarshal(data, &arr); err2 != nil || len(arr) == 0 {
						return
					}
					obj = arr[0]
				}
				ru := provider.ParseUsage(obj)
				if ru == nil {
					return
				}

				// For Claude, accumulate input (message_start) and output (message_delta)
				// into a single record before emitting.
				if acc.Type == AccountTypeClaude {
					if claudeAccum2 == nil {
						claudeAccum2 = ru
					} else {
						claudeAccum2.OutputTokens = ru.OutputTokens
						claudeAccum2.BillableTokens = clampNonNegative(
							claudeAccum2.InputTokens - claudeAccum2.CachedInputTokens + ru.OutputTokens)
						ru = claudeAccum2
						claudeAccum2 = nil
						ru.AccountID = acc.ID
						ru.UserID = userID
						ru.OriginID = originID
						ru.AccountType = acc.Type
						acc.mu.Lock()
						ru.PlanType = acc.PlanType
						acc.mu.Unlock()
						// Bridge rate limits from response headers
						if ru.PrimaryUsedPct == 0 && headerPrimaryPct > 0 {
							ru.PrimaryUsedPct = headerPrimaryPct
						}
						if ru.SecondaryUsedPct == 0 && headerSecondaryPct > 0 {
							ru.SecondaryUsedPct = headerSecondaryPct
						}
						h.recordUsage(acc, *ru)
					}
					return
				}
				// Non-Claude: record immediately
				ru.AccountID = acc.ID
				ru.UserID = userID
				ru.OriginID = originID
				ru.AccountType = acc.Type
				acc.mu.Lock()
				ru.PlanType = acc.PlanType
				acc.mu.Unlock()
				h.recordUsage(acc, *ru)
			},
		}
		if accountType == AccountTypeCodex && !acc.CyberAccess {
			suppressor := &cyberPolicyHTTPSuppressor{
				h:              h,
				reqID:          reqID,
				conversationID: conversationID,
				requiredPlan:   requiredPlan,
				clientIP:       clientIP,
				accountID:      acc.ID,
				pinned:         &cyberPinned,
			}
			interceptWriter.onEvent = suppressor.onEvent
		}
		writer = interceptWriter
	}

	// Wrap response body with idle timeout to kill zombie SSE connections.
	var idleReader *idleTimeoutReader
	if isSSE && h.cfg.streamIdleTimeout > 0 {
		idleReader = newIdleTimeoutReader(resp.Body, h.cfg.streamIdleTimeout, cancel)
		resp.Body = idleReader
	}

	_, copyErr := io.Copy(writer, resp.Body)
	if hw2 != nil {
		hw2.Stop()
	}
	if fw != nil {
		fw.stop()
	}

	// Flush any accumulated Claude usage that wasn't emitted (e.g., stream ended
	// without message_delta, or only got message_start before error/disconnect).
	if claudeAccum2 != nil {
		claudeAccum2.AccountID = acc.ID
		claudeAccum2.UserID = userID
		claudeAccum2.OriginID = originID
		claudeAccum2.AccountType = acc.Type
		acc.mu.Lock()
		claudeAccum2.PlanType = acc.PlanType
		acc.mu.Unlock()
		if claudeAccum2.PrimaryUsedPct == 0 && headerPrimaryPct > 0 {
			claudeAccum2.PrimaryUsedPct = headerPrimaryPct
		}
		if claudeAccum2.SecondaryUsedPct == 0 && headerSecondaryPct > 0 {
			claudeAccum2.SecondaryUsedPct = headerSecondaryPct
		}
		// Model should already be set from ParseUsage (extracted from message_start)
		h.recordUsage(acc, *claudeAccum2)
		claudeAccum2 = nil
	}

	if copyErr != nil {
		if ctx.Err() == nil {
			h.recent.add(copyErr.Error())
			h.metrics.inc("error", acc.ID)
		}
		if idleReader != nil {
			log.Printf("[%s] SSE stream error (account=%s): %v", reqID, acc.ID, copyErr)
		}
		return
	}

	respSample := sampleBuf.Bytes()
	if h.cfg.logBodies && len(respSample) > 0 {
		log.Printf("[%s] response body sample (%d bytes): %s", reqID, len(respSample), safeText(respSample))
	}
	if !isSSE && len(respSample) > 0 {
		h.updateUsageFromBody(acc, respSample, userID, originID)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if conversationID == "" && len(respSample) > 0 {
			conversationID = extractConversationIDFromSSE(respSample)
		}
		if conversationID != "" && !cyberPinned {
			h.pool.pin(conversationID, acc.ID)
		}
		acc.mu.Lock()
		acc.LastUsed = time.Now()
		if acc.Penalty > 0 {
			acc.Penalty *= 0.5
			if acc.Penalty < 0.01 {
				acc.Penalty = 0
			}
		}
		acc.mu.Unlock()
	}

	h.metrics.inc(strconv.Itoa(resp.StatusCode), acc.ID)

	if h.cfg.debug.Load() {
		log.Printf("[%s] streamed done status=%d account=%s duration_ms=%d", reqID, resp.StatusCode, acc.ID, time.Since(start).Milliseconds())
	}
}

// clientOrDefaultTimeout picks the request timeout. If the client sent X-Stainless-Timeout
// (Anthropic SDK), use that. Otherwise fall back to streaming vs non-streaming defaults.
func clientOrDefaultTimeout(r *http.Request, reqTimeout, streamTimeout time.Duration, body []byte) time.Duration {
	const codexExpectedStreamTimeout = 5 * time.Minute

	isStreaming := strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream")
	if !isStreaming && len(body) > 0 {
		var obj map[string]any
		if json.Unmarshal(body, &obj) == nil {
			if s, ok := obj["stream"].(bool); ok && s {
				isStreaming = true
			}
		}
	}
	isImageGeneration := len(body) > 0 && requestHasImageGenerationTool(body)

	// Streaming requests can run for a long time. Use the configured stream
	// timeout only; a zero value means no hard cap.
	if isStreaming {
		return streamTimeout
	}

	// Honour SDK/client-requested timeouts for non-streaming requests, but do
	// not let short 60s/120s client defaults cut off image generation before
	// Codex's expected 300s window.
	if v := r.Header.Get("X-Stainless-Timeout"); v != "" {
		if secs, err := strconv.ParseFloat(v, 64); err == nil && secs > 0 {
			requested := time.Duration(secs * float64(time.Second))
			if isImageGeneration && requested < codexExpectedStreamTimeout {
				return codexExpectedStreamTimeout
			}
			return requested
		}
	}
	if isImageGeneration && reqTimeout > 0 && reqTimeout < codexExpectedStreamTimeout {
		return codexExpectedStreamTimeout
	}
	return reqTimeout
}

func (h *proxyHandler) logRateLimitResponseHeaders(reqID string, accountType AccountType, hdr http.Header) {
	if h == nil || !h.cfg.debug.Load() {
		return
	}
	if hdr == nil {
		return
	}

	keys := []string{
		"anthropic-ratelimit-unified-primary-utilization",
		"anthropic-ratelimit-unified-secondary-utilization",
		"anthropic-ratelimit-unified-tokens-utilization",
		"anthropic-ratelimit-unified-requests-utilization",
		"anthropic-ratelimit-unified-5h-utilization",
		"anthropic-ratelimit-unified-7d-utilization",
		"anthropic-ratelimit-unified-reset",
		"anthropic-ratelimit-unified-primary-reset",
		"anthropic-ratelimit-unified-secondary-reset",
		"anthropic-ratelimit-unified-tokens-reset",
		"anthropic-ratelimit-unified-requests-reset",
		"anthropic-ratelimit-unified-5h-reset",
		"anthropic-ratelimit-unified-7d-reset",
		"anthropic-ratelimit-unified-status",
		"anthropic-ratelimit-unified-5h-status",
		"anthropic-ratelimit-unified-7d-status",
		"x-ratelimit-limit-requests",
		"x-ratelimit-remaining-requests",
		"x-ratelimit-reset-requests",
		"x-ratelimit-limit-tokens",
		"x-ratelimit-remaining-tokens",
		"x-ratelimit-reset-tokens",
		"x-ratelimit-limit",
		"x-ratelimit-remaining",
		"x-ratelimit-reset",
	}

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		if v := strings.TrimSpace(hdr.Get(key)); v != "" {
			parts = append(parts, key+"="+v)
		}
	}

	if len(parts) == 0 {
		for key := range hdr {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "ratelimit") || strings.Contains(lower, "rate-limit") || strings.Contains(lower, "anthropic-ratelimit") {
				parts = append(parts, key+"="+hdr.Get(key))
			}
		}
	}

	if len(parts) == 0 {
		return
	}
	log.Printf("[%s] upstream %s rate-limit headers: %s", reqID, accountType, strings.Join(parts, ", "))
}

func isRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "rate limited") || strings.Contains(msg, "too many requests") || strings.Contains(msg, "429")
}

func parseRetryAfter(h http.Header) (time.Duration, bool) {
	if h == nil {
		return 0, false
	}
	val := strings.TrimSpace(h.Get("Retry-After"))
	if val == "" {
		return 0, false
	}
	if secs, err := strconv.ParseInt(val, 10, 64); err == nil {
		if secs <= 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if when, err := http.ParseTime(val); err == nil {
		wait := time.Until(when)
		if wait <= 0 {
			return 0, false
		}
		return wait, true
	}
	return 0, false
}

// backoffDuration returns the exponential backoff for the given level.
// Formula: min(1s * 2^level, 30m). Level 0 = 1s, 1 = 2s, 2 = 4s, ... 10 = ~17m, 11+ = 30m.
func backoffDuration(level int) time.Duration {
	const base = 1 * time.Second
	const maxBackoff = 30 * time.Minute
	d := base << uint(level) // 1s * 2^level
	if d > maxBackoff || d <= 0 {
		return maxBackoff
	}
	return d
}

func (h *proxyHandler) applyRateLimit(a *Account, hdr http.Header) time.Duration {
	if a == nil {
		return 0
	}

	// Try multiple sources for the cooldown duration, in priority order:
	// 1. anthropic-ratelimit-unified-reset (precise reset timestamp from Claude)
	// 2. Retry-After header (standard HTTP)
	// 3. Exponential backoff (fallback)
	wait := time.Duration(0)
	gotPreciseReset := false

	if hdr != nil {
		// Check Claude's unified reset headers for a precise reset time.
		for _, key := range []string{
			"anthropic-ratelimit-unified-reset",
			"anthropic-ratelimit-unified-primary-reset",
			"anthropic-ratelimit-unified-5h-reset",
		} {
			if resetStr := hdr.Get(key); resetStr != "" {
				if resetAt, ok := parseRateLimitReset(resetStr); ok && resetAt.After(time.Now()) {
					wait = time.Until(resetAt)
					gotPreciseReset = true
					break
				}
			}
		}
	}

	if !gotPreciseReset {
		if w, ok := parseRetryAfter(hdr); ok {
			wait = w
		} else {
			a.mu.Lock()
			wait = backoffDuration(a.BackoffLevel)
			a.mu.Unlock()
		}
	}

	// Always bump backoff level so repeated rate limits get longer fallbacks.
	a.mu.Lock()
	a.BackoffLevel++
	a.mu.Unlock()

	// Also parse full rate limit utilization from the 429 response headers.
	// This updates the account's usage snapshot so candidate selection
	// can factor in the current utilization level.
	if hdr != nil {
		snap, ok := parseClaudeResponseRateLimits(hdr)
		if ok {
			a.mu.Lock()
			a.Usage = mergeUsage(a.Usage, snap)
			a.mu.Unlock()
		}
	}

	until := time.Now().Add(wait)
	if wait <= 0 {
		return 0
	}

	a.mu.Lock()
	if a.RateLimitUntil.Before(until) {
		a.RateLimitUntil = until
	}
	a.mu.Unlock()
	if h.cfg.debug.Load() {
		log.Printf("rate-limit backoff: account=%s level=%d wait=%s precise=%v", a.ID, a.BackoffLevel, wait, gotPreciseReset)
	}
	return wait
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

	// Pool-generated Claude tokens (current and legacy) should NOT be passed through.
	// These are fake Claude OAuth/API-looking tokens that identify pool users.
	if strings.HasPrefix(token, ClaudePoolTokenPrefix) || strings.HasPrefix(token, ClaudePoolTokenLegacyPrefix) {
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

	path := r.URL.Path
	originalPath := path
	if providerType == AccountTypeCodex {
		if shouldNoopCodexPath(path) {
			serveNoopCodexPath(w, r)
			return
		}
	}

	targetBase := provider.UpstreamURL(path)
	if isWebSocketUpgradeRequest(r) {
		h.proxyPassthroughWebSocket(w, r, reqID, providerType, provider, targetBase, start)
		return
	}
	streamBody := shouldStreamBody(r, h.cfg.maxInMemoryBodyBytes)
	if providerType == AccountTypeCodex && codexPassthroughNeedsBodyRewrite(path) {
		streamBody = false
	}
	if streamBody {
		if h.cfg.debug.Load() {
			log.Printf("[%s] passthrough streaming body: method=%s path=%s provider=%s content-length=%d",
				reqID, r.Method, r.URL.Path, providerType, r.ContentLength)
		}
		h.proxyPassthroughStreamed(w, r, reqID, providerType, provider, targetBase, start)
		return
	}

	bodyBytes, bodySample, err := readBodyForReplay(r.Body, h.cfg.logBodies, h.cfg.bodyLogLimit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	passthroughTranslateDir := TranslateNone
	if providerType == AccountTypeCodex {
		if strings.HasPrefix(originalPath, "/v1/completions") && !strings.HasPrefix(originalPath, "/v1/chat/completions") {
			passthroughTranslateDir = TranslateCompletionsToResponses
		} else if strings.HasPrefix(originalPath, "/v1/chat/completions") {
			passthroughTranslateDir = TranslateChatToResponses
		} else if strings.HasPrefix(originalPath, "/v1/messages") {
			passthroughTranslateDir = TranslateClaudeToResponses
		}
		path, bodyBytes, err = codexPassthroughRewrite(path, bodyBytes)
		if err != nil {
			http.Error(w, "format translation error: "+err.Error(), http.StatusBadRequest)
			return
		}
		targetBase = provider.UpstreamURL(path)
		r = r.Clone(r.Context())
		r.URL.Path = path
	}

	if h.cfg.debug.Load() {
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

	timeout := clientOrDefaultTimeout(r, h.cfg.requestTimeout, h.cfg.streamTimeout, bodyBytes)

	ctx := r.Context()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

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
	removeConflictingProxyHeaders(outReq.Header)

	// Force uncompressed responses — SSE streams break with on-the-fly decompression.
	outReq.Header.Set("Accept-Encoding", "identity")

	// For Claude, ensure required headers are set
	if providerType == AccountTypeClaude {
		if outReq.Header.Get("anthropic-version") == "" {
			outReq.Header.Set("anthropic-version", ccAnthropicVersion)
		}
	}

	if h.cfg.debug.Load() {
		log.Printf("[%s] passthrough -> %s %s", reqID, outReq.Method, outReq.URL.String())
	}

	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		if providerType == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
			h.writeClaudeTrace(reqID, "passthrough", "", hashRequestOrigin(r, poolHashSalt(h.cfg.friendCode)), nil, r, bodyBytes, outReq, bodyBytes, nil, TranslateNone, nil, err.Error())
		}
		h.recent.add(err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if providerType == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
		sampleLimit := h.claudeTraceSampleLimit(16 * 1024)
		if h.cfg.logBodies && h.cfg.bodyLogLimit > 0 {
			sampleLimit = h.claudeTraceSampleLimit(h.cfg.bodyLogLimit)
		}
		h.attachClaudeTrace(reqID, "passthrough", "", hashRequestOrigin(r, poolHashSalt(h.cfg.friendCode)), nil, r, bodyBytes, outReq, bodyBytes, resp, TranslateNone, &bytes.Buffer{}, sampleLimit)
	}

	respContentType := resp.Header.Get("Content-Type")
	isSSE := provider.DetectsSSE(r.URL.Path, respContentType)
	if isSSE && resp.StatusCode >= 400 && !strings.Contains(strings.ToLower(respContentType), "text/event-stream") {
		isSSE = false
	}
	clientWantsNonStreaming := true
	if len(bodyBytes) > 0 {
		var obj map[string]any
		if json.Unmarshal(bodyBytes, &obj) == nil {
			if stream, ok := obj["stream"].(bool); ok && stream {
				clientWantsNonStreaming = false
			}
		}
	}
	if passthroughTranslateDir != TranslateNone && resp.StatusCode < 400 && clientWantsNonStreaming && isSSE {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Del("Content-Length")
		if passthroughTranslateDir == TranslateCompletionsToResponses {
			bufWriter := &responsesToCompletionsBufferingWriter{debug: h.cfg.debug.Load(), reqID: reqID}
			_, _ = io.Copy(bufWriter, resp.Body)
			w.WriteHeader(resp.StatusCode)
			w.Write(bufWriter.Result())
			return
		}
		if passthroughTranslateDir == TranslateChatToResponses {
			bufWriter := &responsesToChatCompletionsBufferingWriter{debug: h.cfg.debug.Load(), reqID: reqID}
			_, _ = io.Copy(bufWriter, resp.Body)
			w.WriteHeader(resp.StatusCode)
			w.Write(bufWriter.Result())
			return
		}
	}
	if passthroughTranslateDir != TranslateNone && resp.StatusCode < 400 && !isSSE {
		respBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusBadGateway)
			return
		}
		translated := respBody
		if passthroughTranslateDir == TranslateCompletionsToResponses {
			if b, err := translateResponsesToCompletions(respBody); err == nil {
				translated = b
			}
		} else if passthroughTranslateDir == TranslateChatToResponses {
			if b, err := translateResponsesToChatCompletions(respBody); err == nil {
				translated = b
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		w.Write(translated)
		return
	}

	// Write response to client
	copyHeader(w.Header(), resp.Header)
	removeHopByHopHeaders(w.Header())
	h.logRateLimitResponseHeaders(reqID, providerType, resp.Header)
	h.replaceUsageHeaders(w.Header())
	if isSSE && passthroughTranslateDir != TranslateNone {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Del("Content-Length")
	}
	w.WriteHeader(resp.StatusCode)

	flusher, _ := w.(http.Flusher)

	var writer io.Writer = w
	if isSSE && flusher != nil {
		fw := &flushWriter{w: w, f: flusher, flushInterval: h.cfg.flushInterval}
		writer = fw
		defer fw.stop()
	}
	if isSSE && passthroughTranslateDir == TranslateCompletionsToResponses {
		writer = &responsesToCompletionsWriter{w: writer, debug: h.cfg.debug.Load(), reqID: reqID}
	} else if isSSE && passthroughTranslateDir == TranslateChatToResponses {
		writer = &responsesToChatCompletionsWriter{w: writer, debug: h.cfg.debug.Load(), reqID: reqID}
	}

	// Wrap response body with idle timeout to kill zombie SSE connections.
	var idleReader *idleTimeoutReader
	if isSSE && h.cfg.streamIdleTimeout > 0 {
		idleReader = newIdleTimeoutReader(resp.Body, h.cfg.streamIdleTimeout, cancel)
		defer idleReader.Close()
	}

	if _, copyErr := io.Copy(writer, resp.Body); copyErr != nil {
		if r.Context().Err() == nil {
			h.recent.add(copyErr.Error())
			h.metrics.inc("error", "passthrough")
		}
		if idleReader != nil {
			log.Printf("[%s] passthrough SSE stream error: %v", reqID, copyErr)
		}
		return
	}

	h.metrics.inc(strconv.Itoa(resp.StatusCode), "passthrough")

	if h.cfg.debug.Load() {
		log.Printf("[%s] passthrough done status=%d duration_ms=%d", reqID, resp.StatusCode, time.Since(start).Milliseconds())
	}
}

func (h *proxyHandler) proxyPassthroughStreamed(w http.ResponseWriter, r *http.Request, reqID string, providerType AccountType, provider Provider, targetBase *url.URL, start time.Time) {
	timeout := clientOrDefaultTimeout(r, h.cfg.requestTimeout, h.cfg.streamTimeout, nil)

	ctx := r.Context()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	// Build the outgoing request - preserving the original Authorization header
	outURL := new(url.URL)
	*outURL = *r.URL
	outURL.Scheme = targetBase.Scheme
	outURL.Host = targetBase.Host
	outURL.Path = singleJoin(targetBase.Path, provider.NormalizePath(r.URL.Path))

	var reqSample *bytes.Buffer
	var body io.Reader = r.Body
	if (h.cfg.logBodies && h.cfg.bodyLogLimit > 0) || (providerType == AccountTypeClaude && h.cfg.claudeTraceEnabled()) {
		sampleLimit := h.cfg.bodyLogLimit
		if sampleLimit <= 0 || (providerType == AccountTypeClaude && h.cfg.claudeTraceEnabled() && h.cfg.claudeTraceBodyLimit > sampleLimit) {
			sampleLimit = h.cfg.claudeTraceBodyLimit
		}
		reqSample = &bytes.Buffer{}
		body = io.TeeReader(r.Body, &limitedWriter{w: reqSample, n: sampleLimit})
	}

	outReq, err := http.NewRequestWithContext(ctx, r.Method, outURL.String(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	outReq.Host = targetBase.Host
	outReq.Header = cloneHeader(r.Header)
	removeHopByHopHeaders(outReq.Header)
	removeConflictingProxyHeaders(outReq.Header)
	if r.ContentLength >= 0 {
		outReq.ContentLength = r.ContentLength
	}

	// Force uncompressed responses — SSE streams break with on-the-fly decompression.
	outReq.Header.Set("Accept-Encoding", "identity")

	// For Claude, ensure required headers are set
	if providerType == AccountTypeClaude {
		if outReq.Header.Get("anthropic-version") == "" {
			outReq.Header.Set("anthropic-version", ccAnthropicVersion)
		}
	}

	if h.cfg.debug.Load() {
		log.Printf("[%s] passthrough streamed -> %s %s", reqID, outReq.Method, outReq.URL.String())
	}

	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		if providerType == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
			var reqBody []byte
			if reqSample != nil {
				reqBody = reqSample.Bytes()
			}
			h.writeClaudeTrace(reqID, "passthrough_streamed", "", hashRequestOrigin(r, poolHashSalt(h.cfg.friendCode)), nil, r, reqBody, outReq, reqBody, nil, TranslateNone, nil, err.Error())
		}
		h.recent.add(err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if providerType == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
		var reqBody []byte
		if reqSample != nil {
			reqBody = reqSample.Bytes()
		}
		sampleLimit := h.claudeTraceSampleLimit(16 * 1024)
		if h.cfg.logBodies && h.cfg.bodyLogLimit > 0 {
			sampleLimit = h.claudeTraceSampleLimit(h.cfg.bodyLogLimit)
		}
		h.attachClaudeTrace(reqID, "passthrough_streamed", "", hashRequestOrigin(r, poolHashSalt(h.cfg.friendCode)), nil, r, reqBody, outReq, reqBody, resp, TranslateNone, &bytes.Buffer{}, sampleLimit)
	}

	if h.cfg.logBodies && reqSample != nil && reqSample.Len() > 0 {
		log.Printf("[%s] passthrough request body sample (%d bytes): %s", reqID, reqSample.Len(), safeText(reqSample.Bytes()))
	}

	// Write response to client
	copyHeader(w.Header(), resp.Header)
	removeHopByHopHeaders(w.Header())
	h.logRateLimitResponseHeaders(reqID, providerType, resp.Header)
	h.replaceUsageHeaders(w.Header())
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

	// Wrap response body with idle timeout to kill zombie SSE connections.
	var idleReader *idleTimeoutReader
	if isSSE && h.cfg.streamIdleTimeout > 0 {
		idleReader = newIdleTimeoutReader(resp.Body, h.cfg.streamIdleTimeout, cancel)
		defer idleReader.Close()
	}

	if _, copyErr := io.Copy(writer, resp.Body); copyErr != nil {
		h.recent.add(copyErr.Error())
		h.metrics.inc("error", "passthrough")
		if idleReader != nil {
			log.Printf("[%s] passthrough streamed SSE error: %v", reqID, copyErr)
		}
		return
	}

	h.metrics.inc(strconv.Itoa(resp.StatusCode), "passthrough")

	if h.cfg.debug.Load() {
		log.Printf("[%s] passthrough streamed done status=%d duration_ms=%d", reqID, resp.StatusCode, time.Since(start).Milliseconds())
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
	translateDir TranslateDirection,
	requestedModel string,
	userID string,
	originID string,
	conversationID string,
) (*http.Response, *bytes.Buffer, bool, error) {
	if acc == nil {
		return nil, nil, false, errors.New("nil account")
	}
	refreshFailed := false // Track if refresh was attempted but failed
	rawIncomingBody := append([]byte(nil), bodyBytes...)
	if provider.Type() == AccountTypeGrok {
		bodyBytes = rewriteAndSanitizeGrokRequestBody(bodyBytes, requestedModel)
	}

	if !h.cfg.disableRefresh && h.needsRefresh(acc) {
		if err := h.refreshAccount(ctx, acc); err != nil {
			if isRateLimitError(err) {
				h.applyRateLimit(acc, nil)
			}
			if h.cfg.debug.Load() {
				log.Printf("[%s] refresh %s failed: %v (continuing with existing token)", reqID, acc.ID, err)
			}
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

	var claudeToolNameMapper map[string]string

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
		removeConflictingProxyHeaders(outReq.Header)

		// Always overwrite client-provided auth; the proxy is the single source of truth.
		outReq.Header.Del("Authorization")
		outReq.Header.Del("ChatGPT-Account-ID")
		outReq.Header.Del("X-Api-Key") // Remove Claude API key from client (might be pool token)
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
		if provider.Type() == AccountTypeGrok {
			outReq.Header.Set("x-grok-model-override", grokCanonicalModel(requestedModel))
			outReq.Header.Set("x-grok-context-window", strconv.Itoa(grokModelContextWindow(requestedModel)))
			outReq.Header.Set("x-grok-max-completion-tokens", strconv.Itoa(grokModelMaxCompletionTokens(requestedModel)))
			if conversationID != "" {
				outReq.Header.Set("x-grok-conv-id", conversationID)
			}
		}

		if provider.Type() == AccountTypeClaude && translateDir == TranslateNone && strings.HasPrefix(access, "sk-ant-oat") {
			outReq.Header.Set("anthropic-beta", appendAnthropicBeta(outReq.Header.Get("anthropic-beta"), betaOAuth))
		}

		// When translating, body size changes — remove the client's Content-Length
		// so Go's HTTP client recalculates it from the actual body.
		if translateDir != TranslateNone {
			outReq.Header.Del("Content-Length")
			outReq.ContentLength = int64(len(bodyBytes))
		}

		// Always request uncompressed responses. SSE is a line-oriented text
		// protocol — gzip/br compression breaks incremental frame parsing in
		// sseInterceptWriter and causes ZlibError in clients (e.g. Bun's
		// fetch) when compressed chunks split across TCP segments. Deleting
		// the header entirely would let Go's transport auto-add gzip, so we
		// must explicitly set identity.
		outReq.Header.Set("Accept-Encoding", "identity")

		// Force uncompressed response for model catalog so we can inject Claude models
		if strings.Contains(in.URL.Path, "codex/models") {
			outReq.Header.Set("Accept-Encoding", "identity")
		}

		// Adjust headers when doing format translation
		if translateDir == TranslateClaudeToOAI || translateDir == TranslateClaudeToResponses {
			// Client sent Claude headers but upstream is OpenAI/Codex — remove Claude-specific headers
			outReq.Header.Del("anthropic-version")
			outReq.Header.Del("anthropic-beta")
			outReq.Header.Del("anthropic-dangerous-direct-browser-access")
			outReq.Header.Del("Sec-Fetch-Mode")
			outReq.Header.Del("Accept-Language")
			outReq.Header.Del("X-App")
			// Remove x-stainless-* headers (Anthropic SDK internals)
			for key := range outReq.Header {
				if strings.HasPrefix(strings.ToLower(key), "x-stainless-") {
					outReq.Header.Del(key)
				}
			}
			// For Codex Responses API, force SSE accept since Codex always streams
			if translateDir == TranslateClaudeToResponses {
				outReq.Header.Set("Accept", "text/event-stream")
			}
		} else if translateDir == TranslateChatToResponses || translateDir == TranslateCompletionsToResponses || translateDir == TranslateImagesToResponses {
			outReq.Header.Set("Accept", "text/event-stream")
			outReq.Header.Set("Content-Type", "application/json")
		} else if translateDir == TranslateOAIToClaude || translateDir == TranslateResponsesToClaude {
			// Client sent OpenAI/Responses format but upstream is Claude — make request
			// indistinguishable from a native Claude Code request.
			isOAuth := strings.HasPrefix(access, "sk-ant-oat")
			is1M := strings.Contains(strings.ToLower(requestedModel), "[1m]")

			// Parse translated body to detect streaming and fast mode
			acceptHeader := "application/json"
			isFastMode := false
			var bodyObj map[string]any
			if json.Unmarshal(bodyBytes, &bodyObj) == nil {
				if s, ok := bodyObj["stream"].(bool); ok && s {
					acceptHeader = "text/event-stream"
				}
				if sp, ok := bodyObj["speed"].(string); ok && sp == "fast" {
					isFastMode = true
				}

				// Pace requests per session to avoid burst patterns
				sessionID := ccSessionHeader(in, userID)
				h.pacer.wait(sessionID)

				// Wire fingerprint functions: metadata, system blocks, ordered keys, CCH hash
				// Guarded behind CODEX_INJECT_CLAUDE_FP=1 — disabled by default after
				// suspected account bans from mismatched billing fingerprints.
				if os.Getenv("CODEX_INJECT_CLAUDE_FP") == "1" {
					acc.mu.Lock()
					accUUID := acc.AccountUUID
					acc.mu.Unlock()

					// 1. Inject metadata.user_id with account UUID, device ID, session ID
					ccInjectMetadata(bodyObj, accUUID, userID, sessionID)

					// 2. Inject system blocks only if client didn't already send them
					if !bodyHasClaudeSystemBlocks(bodyObj) {
						bodyBytes = ccInjectSystemBlocks(bodyObj, bodyBytes)
						// Re-parse after system block injection modified bodyBytes
						json.Unmarshal(bodyBytes, &bodyObj)
					}

					// 3. Re-serialize with ordered keys matching Claude Code
					if reordered, err := orderedMarshal(bodyObj, claudeBodyKeyOrder); err == nil {
						bodyBytes = reordered
					}

					// 4. Replace CCH placeholder with computed xxhash
					bodyBytes = ccReplaceCCHPlaceholder(bodyBytes)
				}
			}
			// Extract the model from the translated body (canonical name)
			bodyModel := ""
			if m, ok := bodyObj["model"].(string); ok {
				bodyModel = m
			}
			if bodyModel == "" {
				bodyModel = requestedModel
			}

			outReq.Header.Set("anthropic-version", ccAnthropicVersion)
			hasStructuredOutputs := ccRequestHasStructuredOutputs(bodyObj)
			hasTaskBudget := ccRequestHasTaskBudget(bodyObj)
			outReq.Header.Set("anthropic-beta", ccBetaHeader(bodyModel, isOAuth, is1M, isFastMode, hasStructuredOutputs, hasTaskBudget))
			outReq.Header.Set("anthropic-dangerous-direct-browser-access", "true")
			outReq.Header.Set("User-Agent", ccUserAgent())
			outReq.Header.Set("X-Claude-Code-Session-Id", ccSessionHeader(in, userID))
			outReq.Header.Set("X-App", "cli")
			outReq.Header.Set("x-client-request-id", uuid.NewString())
			outReq.Header.Set("Accept", acceptHeader)
			outReq.Header.Set("Accept-Language", "*")
			outReq.Header.Set("Content-Type", "application/json")
			outReq.Header.Set("Sec-Fetch-Mode", "cors")
			// Add x-stainless headers to match Anthropic SDK fingerprint
			ccStainlessHeaders(outReq.Header.Set)
			// Remove any OpenAI-specific headers that might leak
			outReq.Header.Del("openai-beta")
			outReq.Header.Del("openai-organization")
		}

		// Debug: log ALL outgoing headers
		if h.cfg.debug.Load() {
			var hdrs []string
			for k, v := range outReq.Header {
				val := v[0]
				if len(val) > 80 {
					val = val[:80]
				}
				hdrs = append(hdrs, fmt.Sprintf("%s=%s", k, val))
			}
			log.Printf("[%s] ALL outgoing headers (%s): %v", reqID, provider.Type(), hdrs)
		}

		// Keep the original User-Agent from the client - don't override it
		return outReq, nil
	}

	outReq, err := buildReq()
	if err != nil {
		if provider.Type() == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
			h.writeClaudeTrace(reqID, "pool", userID, originID, acc, in, rawIncomingBody, nil, bodyBytes, nil, translateDir, nil, err.Error())
		}
		return nil, nil, false, err
	}

	if h.cfg.debug.Load() {
		acc.mu.Lock()
		log.Printf("[%s] -> %s %s (account=%s account_id=%s)", reqID, outReq.Method, outReq.URL.String(), acc.ID, acc.AccountID)
		acc.mu.Unlock()
	}

	resp, err := h.transport.RoundTrip(outReq)
	captureCodexResponseState(acc, resp, reqID)
	if resp != nil && len(claudeToolNameMapper) > 0 {
		resp.Header.Del("Content-Length")
		resp.Body = newClaudeToolNameReadCloser(resp.Body, claudeToolNameMapper)
	}
	if err != nil {
		if provider.Type() == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
			h.writeClaudeTrace(reqID, "pool", userID, originID, acc, in, rawIncomingBody, outReq, bodyBytes, resp, translateDir, nil, err.Error())
		}
		acc.mu.Lock()
		acc.Penalty += 0.2
		acc.mu.Unlock()
		return nil, nil, false, err
	}

	// If we got a 401/403, try to refresh and retry on the *same* account once.
	if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && !h.cfg.disableRefresh {
		// Log the error response body for debugging
		if h.cfg.debug.Load() {
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
					if provider.Type() == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
						h.writeClaudeTrace(reqID, "pool", userID, originID, acc, in, rawIncomingBody, nil, bodyBytes, nil, translateDir, nil, err.Error())
					}
					return nil, nil, false, err
				}
				if h.cfg.debug.Load() {
					acc.mu.Lock()
					log.Printf("[%s] retry after refresh -> %s %s (account=%s account_id=%s)", reqID, outReq.Method, outReq.URL.String(), acc.ID, acc.AccountID)
					acc.mu.Unlock()
				}
				resp, err = h.transport.RoundTrip(outReq)
				captureCodexResponseState(acc, resp, reqID)
				if resp != nil && len(claudeToolNameMapper) > 0 {
					resp.Header.Del("Content-Length")
					resp.Body = newClaudeToolNameReadCloser(resp.Body, claudeToolNameMapper)
				}
				if err != nil {
					if provider.Type() == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
						h.writeClaudeTrace(reqID, "pool", userID, originID, acc, in, rawIncomingBody, outReq, bodyBytes, resp, translateDir, nil, err.Error())
					}
					acc.mu.Lock()
					acc.Penalty += 0.2
					acc.mu.Unlock()
					return nil, nil, false, err
				}
				// Log response after retry
				if h.cfg.debug.Load() && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
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
				if isRateLimitError(err) {
					h.applyRateLimit(acc, nil)
				} else if strings.Contains(errStr, "invalid_grant") || strings.Contains(errStr, "refresh_token_reused") {
					// If refresh token is permanently invalid, mark account as dead immediately
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
				if h.cfg.debug.Load() {
					log.Printf("[%s] refresh failed for %s: %v (refreshFailed=%v)", reqID, acc.ID, err, refreshFailed)
				}
			}
		} else {
			// No refresh token available - can't recover from 401/403
			refreshFailed = true
		}
	}

	// Tee a bounded response sample only when later code needs it. Pass-through SSE
	// stays on the direct upstream->client path so first tokens are not delayed by
	// accounting-only parsing or sampling.
	sampleLimit := int64(16 * 1024)
	if h.cfg.logBodies && h.cfg.bodyLogLimit > 0 {
		sampleLimit = h.cfg.bodyLogLimit
	}
	sampleLimit = h.claudeTraceSampleLimit(sampleLimit)
	var buf *bytes.Buffer
	if provider.Type() == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
		buf = &bytes.Buffer{}
		h.attachClaudeTrace(reqID, "pool", userID, originID, acc, in, rawIncomingBody, outReq, bodyBytes, resp, translateDir, buf, sampleLimit)
	} else if shouldSampleResponseBodyForRequest(provider, acc, in.URL.Path, resp, translateDir, conversationID, h.cfg.logBodies) {
		buf = &bytes.Buffer{}
		resp.Body = struct {
			io.Reader
			io.Closer
		}{
			Reader: io.TeeReader(resp.Body, &limitedWriter{w: buf, n: sampleLimit}),
			Closer: resp.Body,
		}
	}
	return resp, buf, refreshFailed, nil
}

func applyStreamingResponseHeaders(header http.Header) {
	header.Set("X-Accel-Buffering", "no")
	header.Set("Connection", "keep-alive")
	cacheControl := header.Get("Cache-Control")
	if cacheControl == "" {
		header.Set("Cache-Control", "no-cache, no-transform")
	} else if !strings.Contains(strings.ToLower(cacheControl), "no-transform") {
		header.Set("Cache-Control", cacheControl+", no-transform")
	}
}

func shouldSampleResponseBodyForRequest(provider Provider, acc *Account, path string, resp *http.Response, translateDir TranslateDirection, conversationID string, logBodies bool) bool {
	if provider == nil || resp == nil {
		return true
	}
	if logBodies || translateDir != TranslateNone {
		return true
	}
	if !provider.DetectsSSE(path, resp.Header.Get("Content-Type")) {
		return true
	}
	if provider.Type() == AccountTypeCodex {
		if acc != nil && !acc.CyberAccess {
			return true
		}
		return conversationID == ""
	}
	return false
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
	key := fmt.Sprintf("%s:%s", a.Type, a.ID)

	h.refreshCallsMu.Lock()
	if h.refreshCalls == nil {
		h.refreshCalls = map[string]*refreshCall{}
	}
	if existing, ok := h.refreshCalls[key]; ok {
		h.refreshCallsMu.Unlock()
		<-existing.done
		return existing.err
	}
	call := &refreshCall{done: make(chan struct{})}
	h.refreshCalls[key] = call
	h.refreshCallsMu.Unlock()

	defer func() {
		h.refreshCallsMu.Lock()
		delete(h.refreshCalls, key)
		h.refreshCallsMu.Unlock()
		close(call.done)
	}()

	err := h.refreshAccountOnce(ctx, a)
	call.err = err
	return err
}

func (h *proxyHandler) refreshAccountOnce(ctx context.Context, a *Account) error {
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
	err := provider.RefreshToken(ctx, a, h.refreshTransport)

	a.mu.Lock()
	a.LastRefresh = time.Now().UTC()
	a.mu.Unlock()

	// Always save to disk after refresh (success or failure)
	// - On success: persist the new access token
	// - On failure: persist LastRefresh to prevent retrying for 1 hour
	if saveErr := saveAccount(a); saveErr != nil {
		log.Printf("warning: failed to save account %s after refresh: %v", a.ID, saveErr)
	}

	return err
}

func (h *proxyHandler) updateUsageFromBody(a *Account, sample []byte, userID, originID string) {
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
				ru.UserID = userID
				ru.OriginID = originID
				ru.AccountType = a.Type
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
			a.applyRateLimitObject(rl)
		}

		// Legacy: response object with usage
		if resp, ok := obj["response"].(map[string]any); ok {
			if rl, ok := resp["rate_limit"].(map[string]any); ok {
				a.applyRateLimitObject(rl)
			}
			if ru := parseRequestUsage(resp); ru != nil {
				ru.AccountID = a.ID
				ru.UserID = userID
				ru.OriginID = originID
				ru.AccountType = a.Type
				a.mu.Lock()
				ru.PlanType = a.PlanType
				a.mu.Unlock()
				h.recordUsage(a, *ru)
			}
		}

		// Legacy: direct usage object
		if ru := parseRequestUsage(obj); ru != nil {
			ru.AccountID = a.ID
			ru.UserID = userID
			ru.OriginID = originID
			ru.AccountType = a.Type
			a.mu.Lock()
			ru.PlanType = a.PlanType
			a.mu.Unlock()
			h.recordUsage(a, *ru)
		}
	}
}
