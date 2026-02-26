package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (h *proxyHandler) startUsagePoller() {
	if h == nil || h.cfg.usageRefresh <= 0 {
		return
	}
	// Fetch usage immediately on startup
	go h.refreshUsageIfStale()

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

	for i, a := range accs {
		// Stagger requests to avoid rate limiting
		// Usage polling should not sleep minutes between accounts; refreshAccount already rate limits OAuth.
		if i > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		if a == nil {
			continue
		}
		a.mu.Lock()
		dead := a.Dead
		hasToken := a.AccessToken != ""
		retrievedAt := a.Usage.RetrievedAt
		accType := a.Type
		rateLimitUntil := a.RateLimitUntil
		a.mu.Unlock()

		if dead || !hasToken {
			continue
		}
		if !rateLimitUntil.IsZero() && rateLimitUntil.After(now) {
			continue
		}

		// Gemini accounts don't have WHAM usage endpoint, but still need refresh
		if accType == AccountTypeGemini {
			if !h.cfg.disableRefresh && h.needsRefresh(a) {
				if err := h.refreshAccount(context.Background(), a); err != nil {
					if isRateLimitError(err) {
						h.applyRateLimit(a, nil, defaultRateLimitBackoff)
						continue
					}
					log.Printf("proactive refresh for %s failed: %v", a.ID, err)
				} else {
					a.mu.Lock()
					if a.Dead {
						log.Printf("resurrecting account %s after successful refresh", a.ID)
						a.Dead = false
						a.Penalty = 0
					}
					a.mu.Unlock()
					log.Printf("gemini refresh %s: success", a.ID)
				}
			}
			continue
		}

		// Claude accounts have their own usage endpoint
		if accType == AccountTypeClaude {
			// Proactive refresh for OAuth tokens
			if !h.cfg.disableRefresh && h.needsRefresh(a) {
				if err := h.refreshAccount(context.Background(), a); err != nil {
					if isRateLimitError(err) {
						h.applyRateLimit(a, nil, defaultRateLimitBackoff)
						continue
					}
					log.Printf("proactive refresh for %s failed: %v", a.ID, err)
				} else {
					a.mu.Lock()
					if a.Dead {
						log.Printf("resurrecting account %s after successful refresh", a.ID)
						a.Dead = false
						a.Penalty = 0
					}
					a.mu.Unlock()
					if h.cfg.debug {
						log.Printf("claude refresh %s: success", a.ID)
					}
				}
			}
			// Fetch Claude usage if stale
			if retrievedAt.IsZero() || now.Sub(retrievedAt) >= h.cfg.usageRefresh {
				if err := h.fetchClaudeUsage(now, a); err != nil && h.cfg.debug {
					log.Printf("claude usage fetch %s failed: %v", a.ID, err)
				}
			}
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
	// Proactively refresh expired tokens before making the request.
	// This ensures tokens stay fresh even if access tokens outlive ID token expiry.
	if !h.cfg.disableRefresh && h.needsRefresh(a) {
		if err := h.refreshAccount(context.Background(), a); err != nil {
			errStr := err.Error()
			if h.cfg.debug {
				log.Printf("proactive refresh for %s failed: %v", a.ID, errStr)
			}
			if isRateLimitError(err) {
				h.applyRateLimit(a, nil, defaultRateLimitBackoff)
				return nil
			}
			// If refresh token is permanently invalid, mark account as dead
			if strings.Contains(errStr, "invalid_grant") || strings.Contains(errStr, "refresh_token_reused") {
				a.mu.Lock()
				a.Dead = true
				a.Penalty += 100.0
				a.mu.Unlock()
				log.Printf("marking account %s as dead: refresh token revoked/invalid", a.ID)
				if err := saveAccount(a); err != nil {
					log.Printf("warning: failed to save dead account %s: %v", a.ID, err)
				}
				return fmt.Errorf("refresh token invalid: %w", err)
			}
			// If refresh was rate limited, skip this usage fetch cycle entirely.
			if strings.Contains(errStr, "rate limited") {
				return nil // Not an error - just skip this cycle
			}
		} else {
			// Refresh succeeded - resurrect the account if it was dead
			a.mu.Lock()
			if a.Dead {
				log.Printf("resurrecting account %s after successful refresh", a.ID)
				a.Dead = false
				a.Penalty = 0
			}
			a.mu.Unlock()
		}
	}

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

	if resp.StatusCode == http.StatusTooManyRequests {
		h.applyRateLimit(a, resp.Header, defaultRateLimitBackoff)
		return nil
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Got 401/403 - force a refresh attempt to recover (bypass needsRefresh check)
		a.mu.Lock()
		hasRefreshToken := a.RefreshToken != ""
		a.mu.Unlock()

		if !h.cfg.disableRefresh && hasRefreshToken {
			if err := h.refreshAccount(context.Background(), a); err == nil {
				// Refresh succeeded - retry the usage fetch
				resp.Body.Close()
				resp, err = doReq()
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusTooManyRequests {
					h.applyRateLimit(a, resp.Header, defaultRateLimitBackoff)
					return nil
				}
				// If still 401/403 after successful refresh, add penalty but don't mark dead
				// Account is only dead if refresh itself fails
				if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
					a.mu.Lock()
					a.Penalty += 5.0
					a.mu.Unlock()
					log.Printf("account %s usage 401/403 after successful refresh, adding penalty (not marking dead)", a.ID)
					return fmt.Errorf("usage unauthorized after refresh: %s", resp.Status)
				}
			} else {
				// Refresh failed - check if it's a permanent failure
				errStr := err.Error()
				if isRateLimitError(err) {
					h.applyRateLimit(a, nil, defaultRateLimitBackoff)
					return nil
				}
				if strings.Contains(errStr, "invalid_grant") || strings.Contains(errStr, "refresh_token_reused") {
					a.mu.Lock()
					a.Dead = true
					a.Penalty += 100.0
					a.mu.Unlock()
					log.Printf("marking account %s as dead: refresh token revoked", a.ID)
					if err := saveAccount(a); err != nil {
						log.Printf("warning: failed to save dead account %s: %v", a.ID, err)
					}
					return fmt.Errorf("refresh token invalid: %w", err)
				}
				// Rate limited or other transient error - add penalty and skip
				a.mu.Lock()
				a.Penalty += 1.0
				a.mu.Unlock()
				return fmt.Errorf("usage unauthorized, refresh failed: %w", err)
			}
		} else {
			// No refresh token - mark as dead
			a.mu.Lock()
			a.Dead = true
			a.Penalty += 100.0
			a.mu.Unlock()
			log.Printf("marking account %s as dead: no refresh token and usage 401/403", a.ID)
			if err := saveAccount(a); err != nil {
				log.Printf("warning: failed to save dead account %s: %v", a.ID, err)
			}
			return fmt.Errorf("usage unauthorized, no refresh token: %s", resp.Status)
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("usage bad status: %s", resp.Status)
	}

	var payload struct {
		RateLimit struct {
			PrimaryWindow struct {
				UsedPercent float64 `json:"used_percent"`
				ResetAt     int64   `json:"reset_at"`
			} `json:"primary_window"`
			SecondaryWindow struct {
				UsedPercent float64 `json:"used_percent"`
				ResetAt     int64   `json:"reset_at"`
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
	if payload.RateLimit.PrimaryWindow.ResetAt > 0 {
		whamSnap.PrimaryResetAt = time.Unix(payload.RateLimit.PrimaryWindow.ResetAt, 0)
	}
	if payload.RateLimit.SecondaryWindow.ResetAt > 0 {
		whamSnap.SecondaryResetAt = time.Unix(payload.RateLimit.SecondaryWindow.ResetAt, 0)
	}
	log.Printf("usage fetch %s: primary=%.1f%% secondary=%.1f%%", a.ID, payload.RateLimit.PrimaryWindow.UsedPercent, payload.RateLimit.SecondaryWindow.UsedPercent)
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

func parseClaudeResetAt(value any) (time.Time, bool) {
	switch v := value.(type) {
	case string:
		v = strings.TrimSpace(v)
		if v == "" {
			return time.Time{}, false
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, false
		}
		return t, true
	case float64:
		if v <= 0 {
			return time.Time{}, false
		}
		return time.Unix(int64(v), 0), true
	case int64:
		if v <= 0 {
			return time.Time{}, false
		}
		return time.Unix(v, 0), true
	case int:
		if v <= 0 {
			return time.Time{}, false
		}
		return time.Unix(int64(v), 0), true
	case json.Number:
		if n, err := v.Int64(); err == nil && n > 0 {
			return time.Unix(n, 0), true
		}
	}
	return time.Time{}, false
}

// fetchClaudeUsage fetches usage data from Claude's /api/oauth/usage endpoint.
func (h *proxyHandler) fetchClaudeUsage(now time.Time, a *Account) error {
	// Only OAuth tokens can use the usage endpoint
	a.mu.Lock()
	access := a.AccessToken
	prevPrimaryResetAt := a.Usage.PrimaryResetAt
	prevSecondaryResetAt := a.Usage.SecondaryResetAt
	a.mu.Unlock()

	if !strings.HasPrefix(access, "sk-ant-oat") {
		// API keys don't have a usage endpoint
		return nil
	}

	usageURL := h.cfg.claudeBase.String() + "/api/oauth/usage"
	req, _ := http.NewRequest(http.MethodGet, usageURL, nil)

	// Set all the Claude Code headers
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-dangerous-direct-browser-access", "true")
	req.Header.Set("anthropic-beta", "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27")
	req.Header.Set("User-Agent", "claude-cli/2.0.76 (external, cli)")
	req.Header.Set("X-App", "cli")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-stainless-lang", "js")
	req.Header.Set("x-stainless-package-version", "0.70.0")
	req.Header.Set("x-stainless-os", "MacOS")
	req.Header.Set("x-stainless-arch", "arm64")
	req.Header.Set("x-stainless-runtime", "node")
	req.Header.Set("x-stainless-runtime-version", "v24.3.0")

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		h.applyRateLimit(a, resp.Header, defaultRateLimitBackoff)
		return nil
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Try refresh once
		refreshAttempted := false
		refreshSucceeded := false
		hasRefreshToken := false
		if !h.cfg.disableRefresh {
			a.mu.Lock()
			hasRefreshToken = a.RefreshToken != ""
			a.mu.Unlock()
		}
		if !h.cfg.disableRefresh && hasRefreshToken {
			refreshAttempted = true
			if err := h.refreshAccount(context.Background(), a); err == nil {
				refreshSucceeded = true
				resp.Body.Close()
				// Update token after refresh
				a.mu.Lock()
				access = a.AccessToken
				a.mu.Unlock()
				req.Header.Set("Authorization", "Bearer "+access)
				resp, err = h.transport.RoundTrip(req)
				if err != nil {
					return err
				}
				defer resp.Body.Close()
			} else if isRateLimitError(err) {
				h.applyRateLimit(a, nil, defaultRateLimitBackoff)
				return nil
			}
		}

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.mu.Lock()
			a.Penalty += 0.3
			a.mu.Unlock()
			if h.cfg.debug {
				if refreshAttempted && refreshSucceeded {
					log.Printf("claude usage fetch %s got 401/403 even after refresh; keeping account alive and adding penalty", a.ID)
				} else {
					log.Printf("claude usage fetch %s got 401/403, refresh not attempted or rate limited, adding penalty", a.ID)
				}
			}
			return fmt.Errorf("claude usage unauthorized (not marking dead): %s", resp.Status)
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("claude usage bad status: %s", resp.Status)
	}

	// Parse the Claude usage response
	var payload struct {
		FiveHour *struct {
			Utilization *float64 `json:"utilization"`
			ResetsAt    any      `json:"resets_at"`
		} `json:"five_hour"`
		SevenDay *struct {
			Utilization *float64 `json:"utilization"`
			ResetsAt    any      `json:"resets_at"`
		} `json:"seven_day"`
		SevenDaySonnet *struct {
			Utilization *float64 `json:"utilization"`
			ResetsAt    any      `json:"resets_at"`
		} `json:"seven_day_sonnet"`
		SevenDayOpus *struct {
			Utilization *float64 `json:"utilization"`
			ResetsAt    any      `json:"resets_at"`
		} `json:"seven_day_opus"`
		ExtraUsage *struct {
			IsEnabled   bool     `json:"is_enabled"`
			Utilization *float64 `json:"utilization"`
		} `json:"extra_usage"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}

	snap := UsageSnapshot{
		RetrievedAt: now,
		Source:      "claude-api",
	}

	// Map five_hour to primary, seven_day to secondary
	if payload.FiveHour != nil {
		if payload.FiveHour.Utilization != nil {
			snap.PrimaryUsed = *payload.FiveHour.Utilization / 100.0
			snap.PrimaryUsedPercent = *payload.FiveHour.Utilization / 100.0
		}
		if t, ok := parseClaudeResetAt(payload.FiveHour.ResetsAt); ok {
			snap.PrimaryResetAt = t
		} else if !prevPrimaryResetAt.IsZero() {
			// Some accounts return resets_at=null when utilization=0; infer the next reset from
			// the last known reset so the dashboard doesn't show "-".
			elapsed := now.Sub(prevPrimaryResetAt)
			if elapsed < 0 {
				snap.PrimaryResetAt = prevPrimaryResetAt
			} else {
				cycles := int64(elapsed / (5 * time.Hour))
				snap.PrimaryResetAt = prevPrimaryResetAt.Add(time.Duration(cycles+1) * (5 * time.Hour))
			}
		}
	}

	if payload.SevenDay != nil {
		if payload.SevenDay.Utilization != nil {
			snap.SecondaryUsed = *payload.SevenDay.Utilization / 100.0
			snap.SecondaryUsedPercent = *payload.SevenDay.Utilization / 100.0
		}
		if t, ok := parseClaudeResetAt(payload.SevenDay.ResetsAt); ok {
			snap.SecondaryResetAt = t
		} else if !prevSecondaryResetAt.IsZero() {
			elapsed := now.Sub(prevSecondaryResetAt)
			if elapsed < 0 {
				snap.SecondaryResetAt = prevSecondaryResetAt
			} else {
				cycles := int64(elapsed / (7 * 24 * time.Hour))
				snap.SecondaryResetAt = prevSecondaryResetAt.Add(time.Duration(cycles+1) * (7 * 24 * time.Hour))
			}
		}
	}

	log.Printf("claude usage fetch %s: 5hr=%.1f%% 7day=%.1f%%",
		a.ID,
		snap.PrimaryUsedPercent*100,
		snap.SecondaryUsedPercent*100)

	a.mu.Lock()
	a.Usage = mergeUsage(a.Usage, snap)
	a.mu.Unlock()

	return nil
}

// DailyBreakdownDay represents one day of usage data.
type DailyBreakdownDay struct {
	Date     string
	Surfaces map[string]float64
}

// fetchDailyBreakdownData fetches the daily token usage breakdown and returns structured data.
func (h *proxyHandler) fetchDailyBreakdownData(a *Account) ([]DailyBreakdownDay, error) {
	base := h.cfg.whamBase
	joined := singleJoin(base.Path, "/wham/usage/daily-token-usage-breakdown")
	u := *base
	u.Path = joined
	u.RawQuery = ""

	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
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

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var payload struct {
		Data []struct {
			Date                      string             `json:"date"`
			ProductSurfaceUsageValues map[string]float64 `json:"product_surface_usage_values"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	var result []DailyBreakdownDay
	for _, d := range payload.Data {
		result = append(result, DailyBreakdownDay{
			Date:     d.Date,
			Surfaces: d.ProductSurfaceUsageValues,
		})
	}
	return result, nil
}

// replaceUsageHeaders replaces individual account usage headers with pool aggregate values.
// This shows the client the overall pool capacity rather than a single account's usage.
// Supports both Codex (X-Codex-*) and Claude (anthropic-ratelimit-unified-*) headers.
func (h *proxyHandler) replaceUsageHeaders(hdr http.Header) {
	snap := h.pool.averageUsage()
	if snap.RetrievedAt.IsZero() {
		return // No usage data available
	}

	// Codex headers: Replace usage percentages with pool averages (convert back to 0-100 scale)
	if snap.PrimaryUsedPercent > 0 {
		hdr.Set("X-Codex-Primary-Used-Percent", fmt.Sprintf("%.1f", snap.PrimaryUsedPercent*100))
	}
	if snap.SecondaryUsedPercent > 0 {
		hdr.Set("X-Codex-Secondary-Used-Percent", fmt.Sprintf("%.1f", snap.SecondaryUsedPercent*100))
	}

	// Replace window minutes if we have them
	if snap.PrimaryWindowMinutes > 0 {
		hdr.Set("X-Codex-Primary-Window-Minutes", strconv.Itoa(snap.PrimaryWindowMinutes))
	}
	if snap.SecondaryWindowMinutes > 0 {
		hdr.Set("X-Codex-Secondary-Window-Minutes", strconv.Itoa(snap.SecondaryWindowMinutes))
	}

	// Claude unified rate limit headers: Replace with pool averages
	// Only replace if the header exists (indicates this was a Claude request)
	if hdr.Get("anthropic-ratelimit-unified-primary-utilization") != "" ||
		hdr.Get("anthropic-ratelimit-unified-tokens-utilization") != "" {
		// Get Claude-specific average if available
		claudeSnap := h.pool.averageUsageByType(AccountTypeClaude)
		if claudeSnap.RetrievedAt.IsZero() {
			claudeSnap = snap // Fall back to overall average
		}

		// Replace primary/tokens utilization (0-100 scale)
		primaryUtil := fmt.Sprintf("%.1f", claudeSnap.PrimaryUsedPercent*100)
		hdr.Set("anthropic-ratelimit-unified-primary-utilization", primaryUtil)
		hdr.Set("anthropic-ratelimit-unified-tokens-utilization", primaryUtil)

		// Replace secondary/requests utilization
		secondaryUtil := fmt.Sprintf("%.1f", claudeSnap.SecondaryUsedPercent*100)
		hdr.Set("anthropic-ratelimit-unified-secondary-utilization", secondaryUtil)
		hdr.Set("anthropic-ratelimit-unified-requests-utilization", secondaryUtil)

		// Update reset times if we have them
		now := time.Now()
		if !claudeSnap.PrimaryResetAt.IsZero() {
			hdr.Set("anthropic-ratelimit-unified-primary-reset", strconv.FormatInt(claudeSnap.PrimaryResetAt.Unix(), 10))
			hdr.Set("anthropic-ratelimit-unified-tokens-reset", strconv.FormatInt(claudeSnap.PrimaryResetAt.Unix(), 10))
		} else {
			// Default to 5 hours from now if no reset time
			hdr.Set("anthropic-ratelimit-unified-primary-reset", strconv.FormatInt(now.Add(5*time.Hour).Unix(), 10))
			hdr.Set("anthropic-ratelimit-unified-tokens-reset", strconv.FormatInt(now.Add(5*time.Hour).Unix(), 10))
		}
		if !claudeSnap.SecondaryResetAt.IsZero() {
			hdr.Set("anthropic-ratelimit-unified-secondary-reset", strconv.FormatInt(claudeSnap.SecondaryResetAt.Unix(), 10))
			hdr.Set("anthropic-ratelimit-unified-requests-reset", strconv.FormatInt(claudeSnap.SecondaryResetAt.Unix(), 10))
		} else {
			// Default to 7 days from now if no reset time
			hdr.Set("anthropic-ratelimit-unified-secondary-reset", strconv.FormatInt(now.Add(7*24*time.Hour).Unix(), 10))
			hdr.Set("anthropic-ratelimit-unified-requests-reset", strconv.FormatInt(now.Add(7*24*time.Hour).Unix(), 10))
		}

		// Set status based on utilization
		status := "ok"
		if claudeSnap.PrimaryUsedPercent > 0.8 || claudeSnap.SecondaryUsedPercent > 0.8 {
			status = "warning"
		}
		if claudeSnap.PrimaryUsedPercent > 0.95 || claudeSnap.SecondaryUsedPercent > 0.95 {
			status = "exceeded"
		}
		hdr.Set("anthropic-ratelimit-unified-status", status)
	}
}
