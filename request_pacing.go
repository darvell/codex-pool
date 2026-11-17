package main

import (
	"sync"
	"time"
)

type requestPacer struct {
	mu      sync.Mutex
	lastReq map[string]time.Time
	minGap  time.Duration
}

func newRequestPacer(minGap time.Duration) *requestPacer {
	return &requestPacer{
		lastReq: make(map[string]time.Time),
		minGap:  minGap,
	}
}

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
