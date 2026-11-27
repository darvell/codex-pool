package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/http2"
)

func main() {
	cfg := buildConfig()
	duckPath := getenv("DUCKDB_PATH", "./data/usage.duckdb")
	cfg.duckPath = duckPath
	maintenanceActions := 0
	for _, value := range []string{cfg.backupDir, cfg.restoreManifest, cfg.compactBoltOutput} {
		if value != "" {
			maintenanceActions++
		}
	}
	if maintenanceActions > 1 {
		log.Fatal("choose only one maintenance operation")
	}
	if cfg.backupDir != "" {
		manifest, err := createPairedBackup(cfg.storePath, duckPath, cfg.backupDir)
		if err != nil {
			log.Fatalf("create paired backup: %v", err)
		}
		log.Printf("paired backup created: %s", manifest)
		return
	}
	if cfg.restoreManifest != "" {
		if err := restorePairedBackup(cfg.restoreManifest, cfg.storePath, duckPath); err != nil {
			log.Fatalf("restore paired backup: %v", err)
		}
		log.Printf("paired backup restored from %s", cfg.restoreManifest)
		return
	}
	if cfg.compactBoltOutput != "" {
		result, err := compactUsageDatabase(cfg.storePath, cfg.compactBoltOutput)
		if err != nil {
			log.Fatalf("compact Bolt database: %v", err)
		}
		log.Printf("Bolt database compacted: rows=%d before=%d after=%d output=%s", result.RewrittenRows, result.BeforeBytes, result.AfterBytes, cfg.compactBoltOutput)
		return
	}
	startCodexFingerprintUpdater()

	codexProvider := NewCodexProviderWithRealtime(cfg.responsesBase, cfg.realtimeBase, cfg.whamBase, cfg.refreshBase)
	claudeProvider := NewClaudeProvider(cfg.claudeBase)
	geminiProvider := NewGeminiProvider(cfg.geminiBase, cfg.geminiAPIBase)
	antigravityProvider := NewAntigravityProvider(cfg.antigravityDailyBase, cfg.antigravityProdBase)
	kimiProvider := NewKimiProvider(cfg.kimiBase)
	minimaxProvider := NewMinimaxProvider(cfg.minimaxBase)
	zaiProvider := NewZAIProvider(cfg.zaiBase)
	xiaomiProvider := NewXiaomiProvider(cfg.xiaomiBase)
	grokProvider := NewGrokProvider(cfg.grokBase)
	adverserialProvider := NewAdverserialProvider(cfg.adverserialBase)
	opencodeGoProvider := NewOpencodeGoProvider(cfg.opencodeGoBase, cfg.opencodeZenBase)
	mistralProvider := NewMistralProvider(cfg.mistralBase)
	registry := NewProviderRegistry(codexProvider, claudeProvider, geminiProvider, antigravityProvider, kimiProvider, minimaxProvider, zaiProvider, xiaomiProvider, grokProvider, adverserialProvider, opencodeGoProvider, mistralProvider, newMistralVibeProvider(cfg.mistralBase))

	log.Printf("loading pool from %s", cfg.poolDir)
	accounts, err := loadPool(cfg.poolDir, registry)
	if err != nil {
		log.Fatalf("load pool: %v", err)
	}
	pool := newPoolState(accounts, cfg.debug.Load())
	pool.applySettings(poolSettings{debug: cfg.debug.Load(), tierThreshold: cfg.tierThreshold})
	codexCount := pool.countByType(AccountTypeCodex)
	claudeCount := pool.countByType(AccountTypeClaude)
	geminiCount := pool.countByType(AccountTypeGemini)
	antigravityCount := pool.countByType(AccountTypeAntigravity)
	kimiCount := pool.countByType(AccountTypeKimi)
	minimaxCount := pool.countByType(AccountTypeMinimax)
	zaiCount := pool.countByType(AccountTypeZAI)
	xiaomiCount := pool.countByType(AccountTypeXiaomi)
	grokCount := pool.countByType(AccountTypeGrok)
	adverserialCount := pool.countByType(AccountTypeAdverserial)
	opencodeGoCount := pool.countByType(AccountTypeOpencodeGo)
	mistralCount := pool.countByType(AccountTypeMistral)
	if pool.count() == 0 {
		log.Printf("warning: loaded 0 accounts from %s", cfg.poolDir)
	}

	store, err := newUsageStore(cfg.storePath, cfg.retentionDays)
	if err != nil {
		log.Fatalf("open usage store: %v", err)
	}
	defer store.Close()
	reserveBytes := int64(64 << 20)
	if value := os.Getenv("ANALYTICS_EMERGENCY_RESERVE_BYTES"); value != "" {
		if parsed, parseErr := strconv.ParseInt(value, 10, 64); parseErr == nil && parsed > 0 {
			reserveBytes = parsed
		}
	}
	if err := store.configureAnalyticsReserve(cfg.storePath+".analytics-reserve", reserveBytes); err != nil {
		log.Fatalf("allocate analytics emergency reserve: %v", err)
	}

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
		ResponseHeaderTimeout: 0,
		ExpectContinueTimeout: 5 * time.Second,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
	}
	// A pooled HTTP/2 connection that a NAT or middlebox drops silently looks
	// alive to both ends, and every stream placed on it hangs until TCP gives
	// up minutes later. Probe idle connections and close the ones that stop
	// answering.
	if h2, err := http2.ConfigureTransports(standardTransport); err == nil {
		h2.ReadIdleTimeout = upstreamHTTP2ReadIdleTimeout
		h2.PingTimeout = upstreamHTTP2PingTimeout
	}
	antigravityTransport := cloneAntigravityHTTP11Transport(standardTransport)

	// Anthropic traffic defaults to the Node.js 24.x uTLS profile used by Claude
	// Code. Other providers retain their existing transports.
	var transport http.RoundTripper = newBunHybridTransport(standardTransport)
	switch strings.ToLower(os.Getenv("CODEX_TLS_FINGERPRINT")) {
	case "rustls":
		transport = newRustlsHybridTransport(standardTransport)
		log.Printf("codex rustls/uTLS hybrid transport enabled")
	case "off", "go", "standard":
		transport = standardTransport
		log.Printf("standard Go TLS transport enabled")
	case "bun":
		transport = newBunHybridTransport(standardTransport)
		log.Printf("Node.js/uTLS hybrid transport enabled (Anthropic traffic only)")
	case "bun-all":
		transport = createBunTransport()
		log.Printf("Node.js/uTLS transport enabled (all traffic)")
	default:
		log.Printf("Node.js/uTLS hybrid transport enabled by default (Anthropic traffic only)")
	}

	if anthropicProxy := os.Getenv("CODEX_ANTHROPIC_PROXY_URL"); anthropicProxy != "" {
		proxyURL, err := url.Parse(anthropicProxy)
		if err != nil {
			log.Fatalf("invalid CODEX_ANTHROPIC_PROXY_URL: %v", err)
		}
		proxyTransport := createBunTransportWithProxy(proxyURL)
		transport = &anthropicHostProxyTransport{
			anthropic: proxyTransport,
			direct:    transport,
		}
		log.Printf("anthropic proxy enabled: %s", proxyURL.Host)
	}

	// Token refreshes must use the server's direct egress. Refresh is a
	// credential-maintenance operation, not provider traffic, and sending it
	// through the Anthropic/residential proxy makes transient proxy failures
	// look like account failures.
	refreshTransport := &http.Transport{
		Proxy: nil,
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
	_ = http2.ConfigureTransport(refreshTransport)
	if cfg.refreshProxyURL != "" {
		log.Printf("ignoring refresh_proxy_url; token refreshes always use direct server egress")
	}

	var poolUsers *PoolUserStore

	if cfg.poolJWTSecret() != "" {
		poolUsersPath := cfg.poolUsersPath()
		var err error
		poolUsers, err = newPoolUserStore(poolUsersPath)
		if err != nil {
			log.Printf("warning: failed to load pool users: %v", err)
		} else {
			log.Printf("pool users enabled (%d users)", len(poolUsers.List()))
		}
	}

	passport, passportErr := newPassportStore(store.db, poolUsers, passportOptions{jwtSecret: cfg.poolJWTSecret(), legacyAnalyticsSalt: cfg.legacyFriendCode})
	if passportErr != nil {
		log.Fatalf("failed to initialize Pool Passport: %v", passportErr)
	}
	log.Printf("Pool Passport initialized (%d principals)", len(passport.principals))

	pricing := newPricingData()
	pricing.startPricingRefresh()

	// Initialize canonical DuckDB analytics. SQLite remains during migration.
	duckAnalytics, duckErr := newDuckAnalytics(duckPath, store.db)
	if duckErr != nil {
		log.Printf("warning: failed to open DuckDB analytics: %v (durable outbox will accumulate)", duckErr)
	} else {
		defer duckAnalytics.Close()
		log.Printf("DuckDB analytics initialized")
	}

	analyticsDBPath := "./data/analytics.db"
	analyticsStore, err := newAnalyticsStore(analyticsDBPath)
	if err != nil {
		log.Printf("warning: failed to open analytics store: %v (cost tracking disabled)", err)
	} else {
		defer analyticsStore.Close()
		analyticsStore.enableAsyncWrites()
		go func() {
			if err := analyticsStore.rebuildPricingFromBoltDB(store, pricing); err != nil {
				log.Printf("warning: failed to rebuild analytics pricing: %v", err)
				analyticsStore.seedFromBoltDB(store, pricing)
			}
		}()
		analyticsStore.startDailyRollup()
		log.Printf("analytics store initialized at %s", analyticsDBPath)
	}

	var aliasesCfg, redirectsCfg, tierCfg map[string]string
	var effortByUser, effortByOrigin map[string]string
	if cfg.file != nil {
		aliasesCfg = cfg.file.ModelAliases
		redirectsCfg = cfg.file.ModelRedirectsByOrigin
		tierCfg = cfg.file.ServiceTierByOrigin
		effortByUser = cfg.file.MaxReasoningEffortByUser
		effortByOrigin = cfg.file.MaxReasoningEffortByOrigin
	}

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
		cfg:                  cfg,
		transport:            newUpstreamTransport(transport, cfg.maxInMemoryBodyBytes),
		antigravityTransport: newUpstreamTransport(antigravityTransport, cfg.maxInMemoryBodyBytes),
		refreshTransport:     refreshTransport,
		pool:                 pool,
		poolUsers:            poolUsers,
		passport:             passport,
		registry:             registry,
		store:                store,
		analyticsStore:       analyticsStore,
		duckAnalytics:        duckAnalytics,
		pricing:              pricing,
		aliases:              newModelAliases(aliasesCfg),
		modelRedirects:       newModelRedirects(redirectsCfg),
		serviceTierOverride:  newModelRedirects(tierCfg),
		effortCap:            newEffortCap(effortByUser, effortByOrigin),
		bruteForce:           newBruteForceTracker(),
		metrics:              newMetrics(),
		recent:               newRecentErrors(50),
		startTime:            time.Now(),
		pacer:                pacer,
		largeReplayBodies:    make(chan struct{}, 1),
		responsesSpoolBodies: make(chan struct{}, 1),
	}
	if store != nil {
		contextStore, err := newNativeContextStore(store.db)
		if err != nil {
			log.Fatalf("initialize native context store: %v", err)
		}
		h.nativeContext = &nativeContext{store: contextStore, pool: pool, provider: registry.ForType(AccountTypeCodex), transport: h.transport, refresh: h.refreshAccountAfterAuthFailure}
		chatGPTOrigin, chatGPTIssuer := chatGPTOrigins()
		h.chatGPT, err = newChatGPTGateway(store.db, pool, chatGPTOrigin, chatGPTIssuer, h.transport)
		if err != nil {
			log.Fatalf("initialize ChatGPT gateway: %v", err)
		}
		h.chatGPT.refresh = h.refreshAccountAfterAuthFailure
	}
	h.startUsagePoller()
	// Quota-waste sampling is independent of request-derived quota intelligence;
	// it records idle and unhealthy accounts from provider-owned snapshots.
	h.startQuotaWasteObserver()
	if getenv("PROXY_ENABLE_QUOTA_INTELLIGENCE", "1") != "0" {
		h.startQuotaIntelligenceRefresher()
	} else {
		log.Printf("quota intelligence disabled by PROXY_ENABLE_QUOTA_INTELLIGENCE")
	}
	startAntigravityVersionUpdater(context.Background())
	h.startAntigravityModelPoller()
	h.startProviderModelPoller()

	go h.probeClaudeAccountUUIDs()

	if pacer != nil {
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				pacer.cleanup(10 * time.Minute)
			}
		}()
	}

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
		IdleTimeout:       5 * time.Minute,
	}

	http2Srv := &http2.Server{
		MaxConcurrentStreams:         250,
		IdleTimeout:                  5 * time.Minute,
		MaxUploadBufferPerConnection: 1 << 20,
		MaxUploadBufferPerStream:     1 << 20,
		MaxReadFrameSize:             1 << 20,
	}
	if err := http2.ConfigureServer(srv, http2Srv); err != nil {
		log.Printf("warning: failed to configure HTTP/2 server: %v", err)
	}

	if cfg.adminToken != "" {
		log.Printf("admin token configured (len=%d)", len(cfg.adminToken))
	} else {
		log.Printf("WARNING: no admin token configured")
	}
	log.Printf("codex-pool proxy listening on %s (codex=%d, claude=%d, gemini=%d, antigravity=%d, kimi=%d, minimax=%d, zai=%d, xiaomi=%d, grok=%d, adverserial=%d, opencode_go=%d, mistral=%d, request_timeout=%v, stream_timeout=%v, stream_idle_timeout=%v, upstream_first_byte_timeout=%v, websocket_idle_timeout=%v, websocket_heartbeat_interval=%v, websocket_read_limit=%d)",
		cfg.listenAddr, codexCount, claudeCount, geminiCount, antigravityCount, kimiCount, minimaxCount, zaiCount, xiaomiCount, grokCount, adverserialCount, opencodeGoCount, mistralCount, cfg.requestTimeout, cfg.streamTimeout, cfg.streamIdleTimeout, cfg.upstreamFirstByteTimeout, cfg.websocketIdleTimeout, cfg.websocketHeartbeatInterval, cfg.websocketReadLimit)
	if cfg.claudeTraceDir != "" {
		log.Printf("claude traffic tracing enabled: dir=%s body_limit=%d include_secrets=%v", cfg.claudeTraceDir, cfg.claudeTraceBodyLimit, cfg.claudeTraceSecrets)
	}
	shutdownCtx, stopShutdownSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopShutdownSignals()
	if err := serveUntilShutdown(srv, h, shutdownCtx.Done(), cfg.shutdownGrace); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func serveUntilShutdown(srv *http.Server, h *proxyHandler, shutdown <-chan struct{}, grace time.Duration) error {
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-shutdown:
	}

	registry := h.webSocketRegistry()
	registry.beginDrain()
	log.Printf("shutdown requested: draining %d websocket sessions for up to %s", registry.count(), grace)

	drainCtx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- srv.Shutdown(drainCtx)
	}()

	drained := registry.wait(drainCtx)
	if !drained {
		remaining := registry.count()
		log.Printf("shutdown grace expired with %d websocket sessions; sending service-restart closes", remaining)
		registry.forceCloseAll()
	}
	_ = srv.Close()

	select {
	case err := <-shutdownDone:
		if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-time.After(time.Second):
	}
	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-time.After(time.Second):
	}
	log.Printf("shutdown complete")
	return nil
}
