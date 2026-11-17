package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type config struct {
	file                   *ConfigFile
	listenAddr             string
	responsesBase          *url.URL
	realtimeBase           *url.URL
	whamBase               *url.URL
	refreshBase            *url.URL
	geminiBase             *url.URL // Gemini CloudCode endpoint (for OAuth/Code Assist mode)
	geminiAPIBase          *url.URL // Gemini API endpoint (for API key mode)
	antigravityDailyBase   *url.URL
	antigravityProdBase    *url.URL
	antigravityOnboardBase *url.URL
	claudeBase             *url.URL
	kimiBase               *url.URL
	minimaxBase            *url.URL
	zaiBase                *url.URL
	xiaomiBase             *url.URL
	grokBase               *url.URL
	adverserialBase        *url.URL
	opencodeGoBase         *url.URL
	opencodeZenBase        *url.URL
	mistralBase            *url.URL
	poolDir                string

	disableRefresh  bool
	refreshProxyURL string

	debug                      atomic.Bool
	logBodies                  bool
	bodyLogLimit               int64
	claudeTraceDir             string
	claudeTraceBodyLimit       int64
	claudeTraceSecrets         bool
	maxInMemoryBodyBytes       int64
	maxSpoolBodyBytes          int64
	maxWireBodyBytes           int64
	responsesBodyTimeout       time.Duration
	flushInterval              time.Duration
	usageRefresh               time.Duration
	maxAttempts                int
	storePath                  string
	retentionDays              int
	legacyFriendCode           string
	adminToken                 string
	backupDir                  string
	restoreManifest            string
	compactBoltOutput          string
	duckPath                   string
	requestTimeout             time.Duration
	streamTimeout              time.Duration
	streamIdleTimeout          time.Duration
	upstreamFirstByteTimeout   time.Duration
	websocketIdleTimeout       time.Duration
	websocketHeartbeatInterval time.Duration
	websocketReadLimit         int64
	websocketCompression       bool // Negotiate per-message compression independently on each websocket
	shutdownGrace              time.Duration
	tierThreshold              float64 // Secondary usage % at which we stop preferring a tier (default 0.50)
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

func buildConfig() *config {
	cfg := &config{}
	configFile, err := loadConfigFile("config.toml")
	if err != nil {
		log.Printf("warning: failed to load config.toml: %v", err)
	}
	cfg.file = configFile

	var fileCfg ConfigFile
	if configFile != nil {
		fileCfg = *configFile
	}

	cfg.listenAddr = getConfigString("PROXY_LISTEN_ADDR", fileCfg.ListenAddr, "127.0.0.1:8989")
	cfg.responsesBase = mustParse(getenv("UPSTREAM_RESPONSES_BASE", "https://chatgpt.com/backend-api/codex"))
	// Realtime is served by the public OpenAI API, not the ChatGPT Codex
	// Responses backend. Codex OAuth access tokens are accepted there.
	cfg.realtimeBase = mustParse(getenv("UPSTREAM_REALTIME_BASE", "https://api.openai.com"))
	cfg.whamBase = mustParse(getenv("UPSTREAM_WHAM_BASE", "https://chatgpt.com/backend-api"))
	cfg.refreshBase = mustParse(getenv("UPSTREAM_REFRESH_BASE", "https://auth.openai.com"))
	cfg.geminiBase = mustParse(getenv("UPSTREAM_GEMINI_BASE", "https://cloudcode-pa.googleapis.com"))
	cfg.geminiAPIBase = mustParse(getenv("UPSTREAM_GEMINI_API_BASE", "https://generativelanguage.googleapis.com"))
	cfg.antigravityDailyBase = mustParse(getenv("UPSTREAM_ANTIGRAVITY_DAILY_BASE", "https://daily-cloudcode-pa.googleapis.com"))
	cfg.antigravityProdBase = mustParse(getenv("UPSTREAM_ANTIGRAVITY_BASE", "https://cloudcode-pa.googleapis.com"))
	cfg.antigravityOnboardBase = mustParse(getenv("UPSTREAM_ANTIGRAVITY_ONBOARD_BASE", "https://daily-cloudcode-pa.googleapis.com"))
	cfg.claudeBase = mustParse(getenv("UPSTREAM_CLAUDE_BASE", "https://api.anthropic.com"))
	cfg.kimiBase = mustParse(getenv("UPSTREAM_KIMI_BASE", "https://api.kimi.com/coding"))
	cfg.minimaxBase = mustParse(getenv("UPSTREAM_MINIMAX_BASE", "https://api.minimax.io/anthropic"))
	cfg.zaiBase = mustParse(getenv("UPSTREAM_ZAI_BASE", "https://api.z.ai/api/anthropic"))
	cfg.xiaomiBase = mustParse(getenv("UPSTREAM_XIAOMI_BASE", "https://token-plan-sgp.xiaomimimo.com/anthropic"))
	cfg.grokBase = mustParse(getConfigString("UPSTREAM_GROK_BASE", fileCfg.GrokBase, "https://cli-chat-proxy.grok.com/v1"))
	// Wallet keys work only on the shim. platform.adverserial.ai/api is the
	// chat product and returns 403 "Use of API key is not enabled".
	cfg.adverserialBase = mustParse(getenv("UPSTREAM_ADVERSERIAL_BASE", "https://api.adverserial.ai"))
	cfg.opencodeGoBase = mustParse(getenv("UPSTREAM_OPENCODE_GO_BASE", "https://opencode.ai/zen/go/v1"))
	cfg.opencodeZenBase = mustParse(getenv("UPSTREAM_OPENCODE_ZEN_BASE", "https://opencode.ai/zen/v1"))
	cfg.mistralBase = mustParse(getenv("UPSTREAM_MISTRAL_BASE", "https://api.mistral.ai"))
	cfg.poolDir = getConfigString("POOL_DIR", fileCfg.PoolDir, "pool")

	cfg.disableRefresh = getConfigBool("PROXY_DISABLE_REFRESH", fileCfg.DisableRefresh, false)
	cfg.refreshProxyURL = getConfigString("REFRESH_PROXY_URL", fileCfg.RefreshProxyURL, "")

	cfg.debug.Store(getConfigBool("PROXY_DEBUG", fileCfg.Debug, false))
	cfg.logBodies = getenv("PROXY_LOG_BODIES", "0") == "1"
	cfg.bodyLogLimit = 16 * 1024
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
	cfg.maxInMemoryBodyBytes = 16 * 1024 * 1024
	if v := getenv("PROXY_MAX_INMEM_BODY_BYTES", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n >= 0 {
			cfg.maxInMemoryBodyBytes = n
		}
	}
	cfg.maxSpoolBodyBytes = 1024 * 1024 * 1024 // 1 GiB decoded disk-backed request ceiling
	if v := getenv("PROXY_MAX_SPOOL_BODY_BYTES", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n > 0 {
			cfg.maxSpoolBodyBytes = n
		}
	}
	cfg.maxWireBodyBytes = cfg.maxSpoolBodyBytes
	if v := getenv("PROXY_MAX_WIRE_BODY_BYTES", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n > 0 {
			cfg.maxWireBodyBytes = n
		}
	}
	cfg.responsesBodyTimeout = 120 * time.Second
	if v := getenv("PROXY_RESPONSES_BODY_TIMEOUT_SECONDS", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n > 0 {
			cfg.responsesBodyTimeout = time.Duration(n) * time.Second
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
	cfg.legacyFriendCode = getConfigString("FRIEND_CODE", fileCfg.LegacyFriendCode, "")
	cfg.adminToken = getConfigString("ADMIN_TOKEN", fileCfg.AdminToken, "")
	cfg.retentionDays = 30
	if v := getenv("PROXY_USAGE_RETENTION_DAYS", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n > 0 {
			cfg.retentionDays = int(n)
		}
	}

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
	// Headers and the first websocket frame are bounded by default so a silent
	// upstream becomes a JSON/websocket error inside Cloudflare's window.
	// STREAM_IDLE_TIMEOUT_SECONDS still defaults off: it would cut a live
	// generation, which this deadline must not do. Set the env var to 0 to
	// restore the old unbounded wait.
	cfg.upstreamFirstByteTimeout = defaultUpstreamFirstByteTimeout
	if v := getenv("UPSTREAM_FIRST_BYTE_TIMEOUT_SECONDS", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n >= 0 {
			cfg.upstreamFirstByteTimeout = time.Duration(n) * time.Second
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
	cfg.websocketCompression = parseBoolEnv("WEBSOCKET_COMPRESSION", true)
	cfg.shutdownGrace = 30 * time.Second
	if v := getenv("PROXY_SHUTDOWN_GRACE_SECONDS", ""); v != "" {
		if n, err := parseInt64(v); err == nil && n >= 0 {
			cfg.shutdownGrace = time.Duration(n) * time.Second
		}
	}

	cfg.tierThreshold = getConfigFloat64("TIER_THRESHOLD", fileCfg.TierThreshold, 0.50)

	flag.StringVar(&cfg.listenAddr, "listen", cfg.listenAddr, "listen address")
	flag.StringVar(&cfg.backupDir, "backup-dir", "", "create an offline paired Bolt/DuckDB backup in this directory, then exit")
	flag.StringVar(&cfg.restoreManifest, "restore-manifest", "", "restore Bolt/DuckDB from a paired backup manifest, then exit")
	flag.StringVar(&cfg.compactBoltOutput, "compact-bolt-output", "", "write a compacted, optimized copy of the offline Bolt database, then exit")
	flag.Parse()
	return cfg
}

func (cfg *config) poolJWTSecret() string {
	var value string
	if cfg != nil && cfg.file != nil {
		value = cfg.file.PoolUsers.JWTSecret
	}
	return getConfigString("POOL_JWT_SECRET", value, "")
}

func (cfg *config) poolUsersPath() string {
	var value string
	if cfg != nil && cfg.file != nil {
		value = cfg.file.PoolUsers.StoragePath
	}
	return getConfigString("POOL_USERS_PATH", value, "./data/pool_users.json")
}

func (cfg *config) publicURL() string {
	var value string
	if cfg != nil && cfg.file != nil {
		value = cfg.file.PublicURL
	}
	return strings.TrimSuffix(getConfigString("PUBLIC_URL", value, ""), "/")
}
