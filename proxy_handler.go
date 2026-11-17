package main

import (
	"context"
	"net/http"
	"sync"
	"time"
)

type proxyHandler struct {
	cfg                  *config
	transport            http.RoundTripper
	antigravityTransport http.RoundTripper
	refreshTransport     http.RoundTripper
	pool                 *poolState
	poolUsers            *PoolUserStore
	passport             *PassportStore
	registry             *ProviderRegistry
	store                *usageStore
	nativeContext        *nativeContext
	chatGPT              *chatGPTGateway
	analyticsStore       *AnalyticsStore
	duckAnalytics        *DuckAnalytics
	pricing              *PricingData
	aliases              *modelAliases
	modelRedirects       *modelRedirects
	serviceTierOverride  *modelRedirects
	effortCap            *effortCap
	bruteForce           *bruteForceTracker
	metrics              *metrics
	recent               *recentErrors
	inflight             int64
	startTime            time.Time
	pacer                *requestPacer
	webSocketRegistryMu  sync.Mutex
	webSockets           *webSocketRegistry
	// Large JSON rewrites temporarily hold several copies of a request. This
	// deliberately serializes only those requests on a small production host.
	largeReplayBodies chan struct{}
	// Disk-backed Responses bodies retain decoded and transformed temporary files
	// through upstream replay, independently of the in-memory rewrite gate.
	responsesSpoolBodies chan struct{}

	refreshMu       sync.Mutex
	lastRefreshTime time.Time
	refreshes       refreshGroup
	usagePollMu     sync.Mutex
	quotaIntelMu    sync.RWMutex
	quotaIntelBusy  bool
	quotaIntel      quotaIntelligenceSnapshot

	// turnStateOrigins tracks which Codex account minted the
	// x-codex-turn-state blob each downstream session currently holds, so
	// failover retries and hot-swaps can strip a known cross-account echo
	// instead of replaying it to an account that did not mint it.
	turnStateMu      sync.Mutex
	turnStateOrigins map[string]codexTurnStateOrigin
	turnStateWrites  uint64
}

const largeReplayBodyThreshold = 8 * 1024 * 1024

// acquireLargeReplayBody serializes requests whose JSON rewrite retains large
// raw, decoded, and re-marshaled copies simultaneously. Small requests remain
// fully concurrent. A missing channel keeps lightweight test handlers working.
func (h *proxyHandler) acquireResponsesSpool(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h == nil || h.responsesSpoolBodies == nil {
		return func() {}, nil
	}
	select {
	case h.responsesSpoolBodies <- struct{}{}:
		return sync.OnceFunc(func() { <-h.responsesSpoolBodies }), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *proxyHandler) acquireLargeReplayBody(ctx context.Context, contentLength int64) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h == nil || h.largeReplayBodies == nil || contentLength >= 0 && contentLength <= largeReplayBodyThreshold {
		return func() {}, nil
	}
	select {
	case h.largeReplayBodies <- struct{}{}:
		return sync.OnceFunc(func() { <-h.largeReplayBodies }), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
