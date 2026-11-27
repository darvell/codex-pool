package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

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

// isPermanentRefreshTokenError reports auth-server failures that mean the
// refresh token can never recover without a fresh login. OpenAI currently
// returns code refresh_token_invalidated ("Your session has ended") rather
// than classic invalid_grant; both (and reuse) must retire the account.
func isPermanentRefreshTokenError(err error) bool {
	if errors.Is(err, errCodexBlocked) {
		return true
	}
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"invalid_grant",
		"refresh_token_reused",
		"refresh_token_invalidated",
		"session has ended",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// maxSameAccountOverloadRetries bounds how often one request retries a
// capacity shed on the account that returned it before moving elsewhere. A
// single shed is often a blip, and retrying in place keeps the warm prompt
// cache. A repeat usually means upstream is shedding that account for
// minutes, so the request moves and the account cools down.
const maxSameAccountOverloadRetries = 1

// serverOverloadCooldown keeps new requests off an account that shed the
// same request twice.
const serverOverloadCooldown = 30 * time.Second

func applyServerOverloadCooldown(account *Account) {
	if account == nil {
		return
	}
	until := time.Now().Add(serverOverloadCooldown)
	account.mu.Lock()
	if account.RateLimitUntil.Before(until) {
		account.RateLimitUntil = until
	}
	account.mu.Unlock()
}

// serverOverloadRetryDelay paces a retry after a capacity shed. The
// provider's hint wins when present, from the Retry-After or Retry-After-Ms
// header or the headers it echoes inside the error body; otherwise the delay
// doubles from 500ms. Either way the wait stays under maxDelay so one shed
// cannot park a request for minutes.
func serverOverloadRetryDelay(h http.Header, body []byte, retry int) time.Duration {
	const (
		baseDelay = 500 * time.Millisecond
		maxDelay  = 8 * time.Second
	)
	if retry < 1 {
		retry = 1
	}
	if delay, ok := overloadRetryHint(h, body); ok {
		if delay > maxDelay {
			return maxDelay
		}
		return delay
	}
	delay := baseDelay << uint(retry-1)
	if delay > maxDelay || delay <= 0 {
		return maxDelay
	}
	return delay
}

func overloadRetryHint(h http.Header, body []byte) (time.Duration, bool) {
	if delay, ok := parseRetryAfter(h); ok {
		return delay, true
	}
	if delay, ok := parseRetryDuration(h.Get("Retry-After-Ms"), time.Millisecond); ok {
		return delay, true
	}
	var envelope struct {
		Error struct {
			Headers map[string]any `json:"headers"`
		} `json:"error"`
		Response struct {
			Error struct {
				Headers map[string]any `json:"headers"`
			} `json:"error"`
		} `json:"response"`
	}
	if len(body) == 0 || json.Unmarshal(body, &envelope) != nil {
		return 0, false
	}
	for _, echoed := range []map[string]any{envelope.Error.Headers, envelope.Response.Error.Headers} {
		if raw, ok := echoed["retry-after"]; ok {
			if delay, ok := parseRetryDuration(fmt.Sprint(raw), time.Second); ok {
				return delay, true
			}
		}
		if raw, ok := echoed["retry-after-ms"]; ok {
			if delay, ok := parseRetryDuration(fmt.Sprint(raw), time.Millisecond); ok {
				return delay, true
			}
		}
	}
	return 0, false
}

func parseRetryDuration(raw string, unit time.Duration) (time.Duration, bool) {
	n, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return time.Duration(n * float64(unit)), true
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

func backoffDuration(level int) time.Duration {
	const base = 1 * time.Second
	const maxBackoff = 30 * time.Minute
	d := base << uint(level)
	if d > maxBackoff || d <= 0 {
		return maxBackoff
	}
	return d
}

func (h *proxyHandler) applyRateLimit(a *Account, hdr http.Header) time.Duration {
	if a == nil {
		return 0
	}

	wait := time.Duration(0)
	gotPreciseReset := false

	if hdr != nil {
		// Prefer the latest explicit reset. A 429 can exhaust more than one
		// request or token window, and retrying at the earlier boundary just
		// produces another 429.
		var preciseReset time.Time
		for _, key := range []string{
			"anthropic-ratelimit-unified-reset",
			"anthropic-ratelimit-unified-primary-reset",
			"anthropic-ratelimit-unified-5h-reset",
			"x-ratelimit-reset-requests",
			"x-ratelimit-reset-tokens",
			"x-ratelimit-reset",
		} {
			if resetStr := hdr.Get(key); resetStr != "" {
				if resetAt, ok := parseRateLimitReset(resetStr); ok && resetAt.After(time.Now()) && resetAt.After(preciseReset) {
					preciseReset = resetAt
				}
			}
		}
		if !preciseReset.IsZero() {
			wait = time.Until(preciseReset)
			gotPreciseReset = true
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

	a.mu.Lock()
	a.BackoffLevel++
	a.mu.Unlock()

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
