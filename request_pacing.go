package main

import (
	"sync"
	"time"
)

// requestPacer enforces a minimum time gap between requests for the same session.
// This prevents burst patterns that could fingerprint the proxy as non-human traffic.
type requestPacer struct {
	mu      sync.Mutex
	lastReq map[string]time.Time
	minGap  time.Duration
}

// newRequestPacer creates a pacer with the given minimum gap between requests
// for the same session ID. If minGap is zero, the pacer is a no-op.
func newRequestPacer(minGap time.Duration) *requestPacer {
	return &requestPacer{
		lastReq: make(map[string]time.Time),
		minGap:  minGap,
	}
}

// wait blocks until at least minGap has elapsed since the last request for the
// given session ID. If sessionID is empty, this is a no-op.
func (p *requestPacer) wait(sessionID string) {
	if p == nil || p.minGap == 0 || sessionID == "" {
		return
	}

	p.mu.Lock()
	last, ok := p.lastReq[sessionID]
	now := time.Now()
	p.lastReq[sessionID] = now
	p.mu.Unlock()

	if !ok {
		return
	}

	elapsed := now.Sub(last)
	if elapsed < p.minGap {
		time.Sleep(p.minGap - elapsed)
	}
}

// cleanup removes entries older than maxAge from the pacer's tracking map.
// Call this periodically to prevent unbounded memory growth.
func (p *requestPacer) cleanup(maxAge time.Duration) {
	if p == nil {
		return
	}

	cutoff := time.Now().Add(-maxAge)
	p.mu.Lock()
	defer p.mu.Unlock()

	for id, last := range p.lastReq {
		if last.Before(cutoff) {
			delete(p.lastReq, id)
		}
	}
}

// size returns the number of tracked sessions (for diagnostics).
func (p *requestPacer) size() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.lastReq)
}
