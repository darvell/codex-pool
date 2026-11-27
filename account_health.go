package main

import (
	"math"
	"time"
)

// Each account keeps exponentially weighted averages of how often attempts
// fail and how long upstream takes to start answering. Selection scales an
// account's score by them, and a sticky conversation leaves an account whose
// averages cross the escape thresholds.
//
// Samples fade toward neutral while an account sits idle, so an account
// that stopped receiving traffic after a bad spell earns it back.

const (
	healthSampleWeight = 0.2

	// healthHalfLife is how long an idle account takes to shed half of its
	// recorded failure rate.
	healthHalfLife = 2 * time.Minute

	// healthLatencyMaxAge drops a latency average nobody has refreshed.
	healthLatencyMaxAge = 10 * time.Minute

	// healthyLatency is the time to first response below which an account
	// takes no latency penalty.
	healthyLatency = 3 * time.Second

	minHealthErrorFactor   = 0.2
	minHealthLatencyFactor = 0.25

	stickyEscapeErrorRate = 0.5
	stickyEscapeLatency   = 15 * time.Second
)

type healthOutcome int

const (
	healthSuccess healthOutcome = iota
	healthFailure
)

type accountHealth struct {
	errorRate  float64
	latency    float64 // seconds
	hasLatency bool
	lastSample time.Time
}

// observeHealth records one attempt. A success carries the time upstream
// took to start answering; a failure carries none.
func (a *Account) observeHealth(outcome healthOutcome, latency time.Duration) {
	if a == nil {
		return
	}
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	h := &a.health
	h.errorRate = h.decayedErrorRate(now)
	sample := 0.0
	if outcome == healthFailure {
		sample = 1
	}
	h.errorRate += healthSampleWeight * (sample - h.errorRate)

	if outcome == healthSuccess && latency > 0 {
		seconds := latency.Seconds()
		if !h.hasLatency || now.Sub(h.lastSample) > healthLatencyMaxAge {
			h.latency = seconds
		} else {
			h.latency += healthSampleWeight * (seconds - h.latency)
		}
		h.hasLatency = true
	}
	h.lastSample = now
}

func (h accountHealth) decayedErrorRate(now time.Time) float64 {
	if h.lastSample.IsZero() || h.errorRate == 0 {
		return h.errorRate
	}
	idle := now.Sub(h.lastSample)
	if idle <= 0 {
		return h.errorRate
	}
	return h.errorRate * math.Exp2(-float64(idle)/float64(healthHalfLife))
}

func (h accountHealth) currentLatency(now time.Time) (time.Duration, bool) {
	if !h.hasLatency || now.Sub(h.lastSample) > healthLatencyMaxAge {
		return 0, false
	}
	return time.Duration(h.latency * float64(time.Second)), true
}

// healthFactorLocked returns the multiplier, in (0, 1], that selection
// applies to an account's score and routing weight. The caller holds a.mu.
func healthFactorLocked(a *Account, now time.Time) float64 {
	factor := math.Max(1-a.health.decayedErrorRate(now), minHealthErrorFactor)
	if latency, ok := a.health.currentLatency(now); ok && latency > healthyLatency {
		factor *= math.Max(float64(healthyLatency)/float64(latency), minHealthLatencyFactor)
	}
	return factor
}

// healthEscapesStickyLocked reports whether a pinned conversation should
// leave this account. Moving loses the warm prompt cache, so only a clearly
// failing or slow account sheds its pins. The caller holds a.mu.
func healthEscapesStickyLocked(a *Account, now time.Time) bool {
	latency, hasLatency := a.health.currentLatency(now)
	return a.health.decayedErrorRate(now) > stickyEscapeErrorRate || (hasLatency && latency > stickyEscapeLatency)
}
