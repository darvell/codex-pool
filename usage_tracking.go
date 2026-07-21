package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const resetCreditAutoRedeemWindow = 15 * time.Minute
const resetCreditPollInterval = 5 * time.Minute

func (h *proxyHandler) startUsagePoller() {
	if h == nil || h.cfg.usageRefresh <= 0 {
		return
	}
	// Fetch usage immediately on startup
	go h.pollUpstreamUsage()

	pollInterval := h.cfg.usageRefresh
	if pollInterval > resetCreditPollInterval {
		pollInterval = resetCreditPollInterval
	}
	ticker := time.NewTicker(pollInterval)
	go func() {
		for range ticker.C {
			h.pollUpstreamUsage()
		}
	}()
}

func (h *proxyHandler) pollUpstreamUsage() {
	if !h.usagePollMu.TryLock() {
		return
	}
	defer h.usagePollMu.Unlock()

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
		resetCreditsRetrievedAt := a.ResetCreditsRetrievedAt
		a.mu.Unlock()

		if !hasToken || (dead && !accountUsesStaticAPIKey(accType)) {
			continue
		}
		if accType == AccountTypeCodex {
			resetCreditsFresh := !resetCreditsRetrievedAt.IsZero() && now.Sub(resetCreditsRetrievedAt) < resetCreditPollInterval
			resetCreditsReady := resetCreditsFresh
			if !resetCreditsFresh {
				if err := h.fetchCodexResetCredits(a); err != nil {
					if h.cfg.debug.Load() {
						log.Printf("reset credit fetch %s failed: %v", a.ID, err)
					}
				} else {
					resetCreditsReady = true
				}
			}
			if resetCreditsReady {
				if err := h.autoRedeemExpiringCodexResetCredit(now, a); err != nil {
					log.Printf("reset credit auto-redeem %s failed: %v", a.ID, err)
				}
			}
		}
		if !rateLimitUntil.IsZero() && rateLimitUntil.After(now) {
			continue
		}

		// Gemini accounts don't have WHAM usage endpoint, but still need refresh
		if accType == AccountTypeGemini || accType == AccountTypeAntigravity {
			if !h.cfg.disableRefresh && h.needsRefresh(a) {
				if err := h.refreshAccount(context.Background(), a); err != nil {
					if isRateLimitError(err) {
						h.applyRateLimit(a, nil)
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
					log.Printf("google refresh %s: success", a.ID)
				}
			}
			continue
		}

		// MiniMax doesn't have a dedicated usage endpoint; usage is captured from response headers
		if accType == AccountTypeMinimax {
			// A dead static key must be revalidated; successful provider traffic is
			// authoritative and clears stale retirement state.
			if dead || retrievedAt.IsZero() {
				if err := h.seedMinimaxUsage(now, a); err != nil && h.cfg.debug.Load() {
					log.Printf("minimax usage seed %s failed: %v", a.ID, err)
				}
			}
			continue
		}

		if accType == AccountTypeZAI {
			if dead || retrievedAt.IsZero() {
				if err := h.seedZAIUsage(now, a); err != nil && h.cfg.debug.Load() {
					log.Printf("zai usage seed %s failed: %v", a.ID, err)
				}
			}
			continue
		}

		// Kimi has a dedicated usage endpoint
		if accType == AccountTypeKimi {
			if dead || retrievedAt.IsZero() || now.Sub(retrievedAt) >= h.cfg.usageRefresh {
				if err := h.fetchKimiUsage(now, a); err != nil && h.cfg.debug.Load() {
					log.Printf("kimi usage fetch %s failed: %v", a.ID, err)
				}
			}
			continue
		}

		// Xiaomi doesn't document a proactive usage endpoint; request usage is parsed from responses.
		if accType == AccountTypeXiaomi {
			continue
		}

		if accType == AccountTypeGrok {
			if !h.cfg.disableRefresh && h.needsRefresh(a) {
				if err := h.refreshAccount(context.Background(), a); err != nil {
					if isRateLimitError(err) {
						h.applyRateLimit(a, nil)
					}
					if h.cfg.debug.Load() {
						log.Printf("grok refresh %s failed: %v", a.ID, err)
					}
					continue
				}
			}
			if retrievedAt.IsZero() || now.Sub(retrievedAt) >= h.cfg.usageRefresh {
				if err := h.fetchGrokUsage(now, a); err != nil && h.cfg.debug.Load() {
					log.Printf("grok usage fetch %s failed: %v", a.ID, err)
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
						h.applyRateLimit(a, nil)
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
					if h.cfg.debug.Load() {
						log.Printf("claude refresh %s: success", a.ID)
					}
				}
			}
			// Fetch Claude usage if stale
			if retrievedAt.IsZero() || now.Sub(retrievedAt) >= h.cfg.usageRefresh {
				if err := h.fetchClaudeUsage(now, a); err != nil && h.cfg.debug.Load() {
					log.Printf("claude usage fetch %s failed: %v", a.ID, err)
				}
			}
			continue
		}

		if !retrievedAt.IsZero() && now.Sub(retrievedAt) < h.cfg.usageRefresh {
			continue
		}
		if err := h.fetchUsage(now, a); err != nil && h.cfg.debug.Load() {
			log.Printf("usage fetch %s failed: %v", a.ID, err)
		}
	}
}

func (h *proxyHandler) fetchGrokUsage(now time.Time, a *Account) error {
	if h == nil || a == nil || h.cfg.grokBase == nil {
		return fmt.Errorf("grok billing is not configured")
	}

	monthly, monthlyErr := h.fetchGrokBillingPart(a, false)
	weekly, weeklyErr := h.fetchGrokBillingPart(a, true)
	if monthlyErr != nil && weeklyErr != nil {
		return fmt.Errorf("grok billing failed: monthly: %v; weekly: %v", monthlyErr, weeklyErr)
	}

	snap, ok := parseGrokBillingUsage(monthly, weekly, now)
	if !ok {
		return fmt.Errorf("grok billing response did not include quota utilization")
	}
	a.mu.Lock()
	a.Usage = mergeUsage(a.Usage, snap)
	a.mu.Unlock()
	restoreValidatedAccount(a, "Grok billing API")
	return nil
}

func (h *proxyHandler) fetchGrokBillingPart(a *Account, weekly bool) ([]byte, error) {
	base := *h.cfg.grokBase
	base.Path = singleJoin(base.Path, "/billing")
	if weekly {
		query := base.Query()
		query.Set("format", "credits")
		base.RawQuery = query.Encode()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	NewGrokProvider(h.cfg.grokBase).SetAuthHeaders(req, a)
	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		h.applyRateLimit(a, resp.Header)
		return nil, fmt.Errorf("billing rate limited: %s", resp.Status)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("billing bad status: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func (h *proxyHandler) fetchUsage(now time.Time, a *Account) error {
	// Proactively refresh expired tokens before making the request.
	// This ensures tokens stay fresh even if access tokens outlive ID token expiry.
	if !h.cfg.disableRefresh && h.needsRefresh(a) {
		if err := h.refreshAccount(context.Background(), a); err != nil {
			errStr := err.Error()
			if h.cfg.debug.Load() {
				log.Printf("proactive refresh for %s failed: %v", a.ID, errStr)
			}
			if isRateLimitError(err) {
				h.applyRateLimit(a, nil)
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
		h.applyRateLimit(a, resp.Header)
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
					h.applyRateLimit(a, resp.Header)
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
					h.applyRateLimit(a, nil)
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

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	rateLimit, _ := payload["rate_limit"].(map[string]any)
	whamSnap, ok := parseCodexRateLimitMap(rateLimit, now, "wham")
	if !ok {
		return fmt.Errorf("usage response missing rate limit windows")
	}
	if credits, ok := payload["credits"].(map[string]any); ok {
		whamSnap.creditsSet = true
		whamSnap.HasCredits, _ = readBoolFromMap(credits, "has_credits")
		whamSnap.CreditsUnlimited, _ = readBoolFromMap(credits, "unlimited")
		whamSnap.CreditsBalance, _ = readFloatFromMap(credits, "balance")
	}
	if planType, ok := payload["plan_type"].(string); ok && planType != "" {
		a.mu.Lock()
		a.PlanType = planType
		a.mu.Unlock()
	}
	log.Printf("usage fetch %s: 5hr=%.1f%% weekly=%.1f%%", a.ID, usagePrimaryUsed(whamSnap)*100, usageSecondaryUsed(whamSnap)*100)
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

func buildWhamResetCreditsURL(base *url.URL) string {
	joined := singleJoin(base.Path, "/wham/rate-limit-reset-credits")
	copy := *base
	copy.Path = joined
	copy.RawQuery = ""
	return copy.String()
}

func buildWhamConsumeResetCreditURL(base *url.URL) string {
	joined := singleJoin(base.Path, "/wham/rate-limit-reset-credits/consume")
	copy := *base
	copy.Path = joined
	copy.RawQuery = ""
	return copy.String()
}

func (h *proxyHandler) fetchCodexResetCredits(a *Account) error {
	req, err := http.NewRequest(http.MethodGet, buildWhamResetCreditsURL(h.cfg.whamBase), nil)
	if err != nil {
		return err
	}

	a.mu.Lock()
	access := a.AccessToken
	accountID := a.AccountID
	if accountID == "" {
		accountID = a.IDTokenChatGPTAccountID
	}
	a.mu.Unlock()

	req.Header.Set("Authorization", "Bearer "+access)
	if accountID != "" {
		req.Header.Set("ChatGPT-Account-ID", accountID)
	}

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("reset credits bad status: %s", resp.Status)
	}

	var payload struct {
		AvailableCount int `json:"available_count"`
		Credits        []struct {
			ID        string  `json:"id"`
			Status    string  `json:"status"`
			ExpiresAt *string `json:"expires_at"`
		} `json:"credits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}

	credits := make([]RateLimitResetCredit, 0, len(payload.Credits))
	for _, credit := range payload.Credits {
		if credit.Status != "available" || credit.ExpiresAt == nil {
			continue
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, *credit.ExpiresAt)
		if err != nil {
			continue
		}
		credits = append(credits, RateLimitResetCredit{
			ID:        credit.ID,
			ExpiresAt: expiresAt,
		})
	}
	sort.Slice(credits, func(i, j int) bool {
		return credits[i].ExpiresAt.Before(credits[j].ExpiresAt)
	})

	a.mu.Lock()
	a.ResetCreditsAvailable = payload.AvailableCount
	a.RateLimitResetCredits = credits
	a.ResetCreditsRetrievedAt = time.Now()
	a.mu.Unlock()
	return nil
}

func (h *proxyHandler) autoRedeemExpiringCodexResetCredit(now time.Time, a *Account) error {
	a.mu.Lock()
	if a.ResetCreditRedeeming {
		a.mu.Unlock()
		return nil
	}
	var due *RateLimitResetCredit
	for _, credit := range a.RateLimitResetCredits {
		untilExpiry := credit.ExpiresAt.Sub(now)
		if credit.ID != "" && untilExpiry > 0 && untilExpiry <= resetCreditAutoRedeemWindow {
			copy := credit
			due = &copy
			break
		}
	}
	if due != nil {
		a.ResetCreditRedeeming = true
	}
	a.mu.Unlock()
	if due == nil {
		return nil
	}
	defer func() {
		a.mu.Lock()
		a.ResetCreditRedeeming = false
		a.mu.Unlock()
	}()

	code, windowsReset, err := h.consumeCodexResetCredit(a, *due)
	if err != nil {
		return err
	}
	log.Printf(
		"reset credit auto-redeem %s: credit=%s expires_in=%s code=%s windows_reset=%d",
		a.ID,
		due.ID,
		formatDuration(due.ExpiresAt.Sub(now)),
		code,
		windowsReset,
	)

	creditsErr := h.fetchCodexResetCredits(a)
	usageErr := h.fetchUsage(time.Now(), a)
	switch {
	case creditsErr != nil && usageErr != nil:
		return fmt.Errorf("refresh reset credits: %v; refresh usage: %v", creditsErr, usageErr)
	case creditsErr != nil:
		return fmt.Errorf("refresh reset credits: %w", creditsErr)
	case usageErr != nil:
		return fmt.Errorf("refresh usage: %w", usageErr)
	default:
		return nil
	}
}

func (h *proxyHandler) consumeCodexResetCredit(a *Account, credit RateLimitResetCredit) (string, int, error) {
	body, err := json.Marshal(map[string]string{
		"redeem_request_id": "codex-pool:" + credit.ID,
		"credit_id":         credit.ID,
	})
	if err != nil {
		return "", 0, err
	}

	req, err := http.NewRequest(http.MethodPost, buildWhamConsumeResetCreditURL(h.cfg.whamBase), bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}

	a.mu.Lock()
	access := a.AccessToken
	accountID := a.AccountID
	if accountID == "" {
		accountID = a.IDTokenChatGPTAccountID
	}
	a.mu.Unlock()

	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	if accountID != "" {
		req.Header.Set("ChatGPT-Account-ID", accountID)
	}

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("consume reset credit bad status: %s", resp.Status)
	}

	var payload struct {
		Code         string `json:"code"`
		WindowsReset int    `json:"windows_reset"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", 0, err
	}
	return payload.Code, payload.WindowsReset, nil
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
	req.Header.Set("anthropic-version", ccAnthropicVersion)
	req.Header.Set("anthropic-dangerous-direct-browser-access", "true")
	req.Header.Set("anthropic-beta", ccMinimalBetaHeader())
	req.Header.Set("User-Agent", ccClaudeCodeUserAgent())
	req.Header.Set("X-Claude-Code-Session-Id", ccAccountSessionID(a.ID))
	req.Header.Set("X-App", "cli")
	req.Header.Set("Accept", "application/json")
	ccStainlessHeaders(req.Header.Set)

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		h.applyRateLimit(a, resp.Header)
		return nil
	}

	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		inspected := bodyForInspection(nil, errBody)
		if isClaudeOrganizationDisabled(inspected) {
			h.disableAccountPermanently(a, "", safeText(inspected))
			return fmt.Errorf("claude organization disabled")
		}
		resp.Body = io.NopCloser(bytes.NewReader(errBody))
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
				h.applyRateLimit(a, nil)
				return nil
			}
		}

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.mu.Lock()
			a.Penalty += 0.3
			a.mu.Unlock()
			if h.cfg.debug.Load() {
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
		} else {
			// Some accounts return resets_at=null when utilization=0. Keep the prior cadence
			// when we have one, otherwise synthesize a reasonable next reset so the 5h
			// window still shows up in the dashboard.
			snap.PrimaryResetAt = inferClaudeWindowReset(now, prevPrimaryResetAt, 5*time.Hour)
		}
	}

	if payload.SevenDay != nil {
		if payload.SevenDay.Utilization != nil {
			snap.SecondaryUsed = *payload.SevenDay.Utilization / 100.0
			snap.SecondaryUsedPercent = *payload.SevenDay.Utilization / 100.0
		}
		if t, ok := parseClaudeResetAt(payload.SevenDay.ResetsAt); ok {
			snap.SecondaryResetAt = t
		} else {
			snap.SecondaryResetAt = inferClaudeWindowReset(now, prevSecondaryResetAt, 7*24*time.Hour)
		}
	}

	// Fall back to model-specific buckets when top-level seven_day is empty.
	// Pro/Team plans report per-model usage (seven_day_sonnet, seven_day_opus)
	// instead of aggregate seven_day.
	if snap.SecondaryUsedPercent == 0 && snap.SecondaryResetAt.IsZero() {
		type bucket struct {
			Utilization *float64
			ResetsAt    any
		}
		var candidates []bucket
		if payload.SevenDaySonnet != nil {
			candidates = append(candidates, bucket{payload.SevenDaySonnet.Utilization, payload.SevenDaySonnet.ResetsAt})
		}
		if payload.SevenDayOpus != nil {
			candidates = append(candidates, bucket{payload.SevenDayOpus.Utilization, payload.SevenDayOpus.ResetsAt})
		}
		for _, c := range candidates {
			if c.Utilization != nil && *c.Utilization/100.0 > snap.SecondaryUsedPercent {
				snap.SecondaryUsed = *c.Utilization / 100.0
				snap.SecondaryUsedPercent = *c.Utilization / 100.0
				if t, ok := parseClaudeResetAt(c.ResetsAt); ok {
					snap.SecondaryResetAt = t
				}
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
	syncUsageCooldown(a)

	return nil
}

func inferClaudeWindowReset(now, prev time.Time, window time.Duration) time.Time {
	if prev.IsZero() {
		return now.Add(window)
	}
	elapsed := now.Sub(prev)
	if elapsed < 0 {
		return prev
	}
	cycles := int64(elapsed / window)
	return prev.Add(time.Duration(cycles+1) * window)
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

func hasCodexUsageHeaders(hdr http.Header) bool {
	for _, key := range []string{
		"X-Codex-Primary-Used-Percent",
		"X-Codex-Secondary-Used-Percent",
		"X-Codex-Primary-Window-Minutes",
		"X-Codex-Secondary-Window-Minutes",
	} {
		if hdr.Get(key) != "" {
			return true
		}
	}
	return false
}

func clearCodexUsageHeaders(hdr http.Header) {
	for _, slot := range []string{"Primary", "Secondary"} {
		for _, suffix := range []string{"Used-Percent", "Window-Minutes", "Reset-At", "Reset-After-Seconds"} {
			hdr.Del("X-Codex-" + slot + "-" + suffix)
		}
	}
}

func setCodexUsageSlotHeaders(hdr http.Header, slot string, window *codexUsageWindow) {
	if window == nil {
		return
	}
	prefix := "X-Codex-" + slot + "-"
	hdr.Set(prefix+"Used-Percent", fmt.Sprintf("%.1f", window.UsedPercent*100))
	hdr.Set(prefix+"Window-Minutes", strconv.Itoa(window.WindowMinutes))
	if !window.ResetAt.IsZero() {
		hdr.Set(prefix+"Reset-At", strconv.FormatInt(window.ResetAt.Unix(), 10))
		resetAfter := int64(time.Until(window.ResetAt).Seconds())
		if resetAfter < 0 {
			resetAfter = 0
		}
		hdr.Set(prefix+"Reset-After-Seconds", strconv.FormatInt(resetAfter, 10))
	}
}

// replaceUsageHeaders replaces individual account usage headers with pool aggregate values.
// This shows the client the overall pool capacity rather than a single account's usage.
// Supports Codex (X-Codex-*), Claude (anthropic-ratelimit-unified-*), and
// Kimi/OpenAI-style (x-ratelimit-*) headers.
func (h *proxyHandler) replaceUsageHeaders(hdr http.Header) {
	// Use time-weighted usage for more accurate pool utilization reporting.
	// This discounts accounts that are about to reset (their high usage doesn't matter).
	snap := h.pool.timeWeightedUsage()
	if snap.RetrievedAt.IsZero() {
		return // No usage data available
	}

	// Codex clients consume positional primary/secondary slots, while the pool stores
	// semantic five-hour/weekly windows. Re-encode the available windows in duration
	// order so a weekly-only limit is emitted as upstream primary, matching OpenAI.
	if hasCodexUsageHeaders(hdr) {
		codexSnap := h.pool.timeWeightedUsageByType(AccountTypeCodex)
		if !codexSnap.RetrievedAt.IsZero() {
			slots := codexUsageSlotsFromSnapshot(codexSnap)
			if slots.Primary != nil {
				clearCodexUsageHeaders(hdr)
				setCodexUsageSlotHeaders(hdr, "Primary", slots.Primary)
				setCodexUsageSlotHeaders(hdr, "Secondary", slots.Secondary)
			}
		}
	}

	// Claude unified rate limit headers: Replace with time-weighted pool values.
	// Only replace if the header exists (indicates this was a Claude request).
	if hdr.Get("anthropic-ratelimit-unified-primary-utilization") != "" ||
		hdr.Get("anthropic-ratelimit-unified-tokens-utilization") != "" ||
		hdr.Get("anthropic-ratelimit-unified-requests-utilization") != "" ||
		hdr.Get("anthropic-ratelimit-unified-5h-utilization") != "" ||
		hdr.Get("anthropic-ratelimit-unified-7d-utilization") != "" ||
		hdr.Get("anthropic-ratelimit-unified-primary-reset") != "" ||
		hdr.Get("anthropic-ratelimit-unified-secondary-reset") != "" ||
		hdr.Get("anthropic-ratelimit-unified-5h-reset") != "" ||
		hdr.Get("anthropic-ratelimit-unified-7d-reset") != "" ||
		hdr.Get("anthropic-ratelimit-unified-reset") != "" ||
		hdr.Get("anthropic-ratelimit-unified-status") != "" ||
		hdr.Get("anthropic-ratelimit-unified-5h-status") != "" ||
		hdr.Get("anthropic-ratelimit-unified-7d-status") != "" {
		claudeSnap := h.pool.timeWeightedUsageByType(AccountTypeClaude)
		if claudeSnap.RetrievedAt.IsZero() {
			claudeSnap = snap // Fall back to overall time-weighted average
		}

		// Replace primary/tokens utilization (0-100 scale)
		primaryUtil := fmt.Sprintf("%.1f", claudeSnap.PrimaryUsedPercent*100)
		hdr.Set("anthropic-ratelimit-unified-primary-utilization", primaryUtil)
		hdr.Set("anthropic-ratelimit-unified-tokens-utilization", primaryUtil)
		hdr.Set("anthropic-ratelimit-unified-5h-utilization", primaryUtil)

		// Replace secondary/requests utilization
		secondaryUtil := fmt.Sprintf("%.1f", claudeSnap.SecondaryUsedPercent*100)
		hdr.Set("anthropic-ratelimit-unified-secondary-utilization", secondaryUtil)
		hdr.Set("anthropic-ratelimit-unified-requests-utilization", secondaryUtil)
		hdr.Set("anthropic-ratelimit-unified-7d-utilization", secondaryUtil)

		// Use earliest reset time (soonest capacity refill) instead of latest
		now := time.Now()
		if !claudeSnap.PrimaryResetAt.IsZero() {
			hdr.Set("anthropic-ratelimit-unified-primary-reset", strconv.FormatInt(claudeSnap.PrimaryResetAt.Unix(), 10))
			hdr.Set("anthropic-ratelimit-unified-tokens-reset", strconv.FormatInt(claudeSnap.PrimaryResetAt.Unix(), 10))
			hdr.Set("anthropic-ratelimit-unified-5h-reset", strconv.FormatInt(claudeSnap.PrimaryResetAt.Unix(), 10))
			hdr.Set("anthropic-ratelimit-unified-reset", strconv.FormatInt(claudeSnap.PrimaryResetAt.Unix(), 10))
		} else {
			hdr.Set("anthropic-ratelimit-unified-primary-reset", strconv.FormatInt(now.Add(5*time.Hour).Unix(), 10))
			hdr.Set("anthropic-ratelimit-unified-tokens-reset", strconv.FormatInt(now.Add(5*time.Hour).Unix(), 10))
			hdr.Set("anthropic-ratelimit-unified-5h-reset", strconv.FormatInt(now.Add(5*time.Hour).Unix(), 10))
			hdr.Set("anthropic-ratelimit-unified-reset", strconv.FormatInt(now.Add(5*time.Hour).Unix(), 10))
		}
		if !claudeSnap.SecondaryResetAt.IsZero() {
			hdr.Set("anthropic-ratelimit-unified-secondary-reset", strconv.FormatInt(claudeSnap.SecondaryResetAt.Unix(), 10))
			hdr.Set("anthropic-ratelimit-unified-requests-reset", strconv.FormatInt(claudeSnap.SecondaryResetAt.Unix(), 10))
			hdr.Set("anthropic-ratelimit-unified-7d-reset", strconv.FormatInt(claudeSnap.SecondaryResetAt.Unix(), 10))
		} else {
			hdr.Set("anthropic-ratelimit-unified-secondary-reset", strconv.FormatInt(now.Add(7*24*time.Hour).Unix(), 10))
			hdr.Set("anthropic-ratelimit-unified-requests-reset", strconv.FormatInt(now.Add(7*24*time.Hour).Unix(), 10))
			hdr.Set("anthropic-ratelimit-unified-7d-reset", strconv.FormatInt(now.Add(7*24*time.Hour).Unix(), 10))
		}

		// Set status based on time-weighted utilization
		status := "ok"
		if claudeSnap.PrimaryUsedPercent > 0.8 || claudeSnap.SecondaryUsedPercent > 0.8 {
			status = "warning"
		}
		if claudeSnap.PrimaryUsedPercent > 0.95 || claudeSnap.SecondaryUsedPercent > 0.95 {
			status = "exceeded"
		}
		hdr.Set("anthropic-ratelimit-unified-status", status)
		hdr.Set("anthropic-ratelimit-unified-5h-status", status)
		hdr.Set("anthropic-ratelimit-unified-7d-status", status)
		hdr.Set("anthropic-ratelimit-unified-primary-status", status)
	}

	hasKimiRateLimit := false
	for key := range hdr {
		if strings.Contains(strings.ToLower(key), "x-ratelimit") {
			hasKimiRateLimit = true
			break
		}
	}
	if hasKimiRateLimit {
		kimiSnap := h.pool.timeWeightedUsageByType(AccountTypeKimi)
		if kimiSnap.RetrievedAt.IsZero() {
			kimiSnap = h.pool.timeWeightedUsage()
		}

		reqUsed := clampRateLimitPercent(kimiSnap.PrimaryUsedPercent)
		tokenUsed := clampRateLimitPercent(kimiSnap.SecondaryUsedPercent)

		// Requests window
		if reqLimit, ok := parseRateLimitFloat(hdr.Get("x-ratelimit-limit-requests")); ok && reqLimit > 0 {
			reqRemaining := int64(math.Round(reqLimit * (1.0 - reqUsed)))
			hdr.Set("x-ratelimit-remaining-requests", strconv.FormatInt(reqRemaining, 10))
			if !kimiSnap.PrimaryResetAt.IsZero() {
				hdr.Set("x-ratelimit-reset-requests", strconv.FormatInt(kimiSnap.PrimaryResetAt.Unix(), 10))
			}
		} else if reqLimit, ok := parseRateLimitFloat(hdr.Get("x-ratelimit-requests-limit")); ok && reqLimit > 0 {
			reqRemaining := int64(math.Round(reqLimit * (1.0 - reqUsed)))
			hdr.Set("x-ratelimit-requests-remaining", strconv.FormatInt(reqRemaining, 10))
			if !kimiSnap.PrimaryResetAt.IsZero() {
				hdr.Set("x-ratelimit-requests-reset", strconv.FormatInt(kimiSnap.PrimaryResetAt.Unix(), 10))
			}
		}

		// Token window
		if tokenLimit, ok := parseRateLimitFloat(hdr.Get("x-ratelimit-limit-tokens")); ok && tokenLimit > 0 {
			tokenRemaining := int64(math.Round(tokenLimit * (1.0 - tokenUsed)))
			hdr.Set("x-ratelimit-remaining-tokens", strconv.FormatInt(tokenRemaining, 10))
			if !kimiSnap.SecondaryResetAt.IsZero() {
				hdr.Set("x-ratelimit-reset-tokens", strconv.FormatInt(kimiSnap.SecondaryResetAt.Unix(), 10))
			}
		} else if tokenLimit, ok := parseRateLimitFloat(hdr.Get("x-ratelimit-tokens-limit")); ok && tokenLimit > 0 {
			tokenRemaining := int64(math.Round(tokenLimit * (1.0 - tokenUsed)))
			hdr.Set("x-ratelimit-tokens-remaining", strconv.FormatInt(tokenRemaining, 10))
			if !kimiSnap.SecondaryResetAt.IsZero() {
				hdr.Set("x-ratelimit-tokens-reset", strconv.FormatInt(kimiSnap.SecondaryResetAt.Unix(), 10))
			}
		}
	}
}

// fetchKimiUsage fetches usage data from Kimi's /v1/usages endpoint.
func (h *proxyHandler) fetchKimiUsage(now time.Time, a *Account) error {
	a.mu.Lock()
	access := a.AccessToken
	a.mu.Unlock()

	usageURL := h.cfg.kimiBase.String() + "/v1/usages"
	req, _ := http.NewRequest(http.MethodGet, usageURL, nil)
	req.Header.Set("Authorization", "Bearer "+access)

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		a.mu.Lock()
		a.Dead = true
		a.Penalty += 100.0
		a.mu.Unlock()
		log.Printf("marking kimi account %s as dead: usage returned %d", a.ID, resp.StatusCode)
		if err := saveAccount(a); err != nil {
			log.Printf("warning: failed to save dead kimi account %s: %v", a.ID, err)
		}
		return fmt.Errorf("kimi usage unauthorized: %s", resp.Status)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("kimi usage bad status: %s", resp.Status)
	}

	var payload struct {
		Usage struct {
			Used      any    `json:"used"`
			Limit     any    `json:"limit"`
			Remaining any    `json:"remaining"`
			ResetAt   string `json:"reset_at"`
		} `json:"usage"`
		Limits []struct {
			Detail map[string]any `json:"detail"`
			Window struct {
				Duration int    `json:"duration"`
				TimeUnit string `json:"timeUnit"`
			} `json:"window"`
		} `json:"limits"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}

	snap := UsageSnapshot{
		RetrievedAt: now,
		Source:      "kimi-api",
	}

	// Primary usage: overall used/limit
	if limit, ok := readFloat(payload.Usage.Limit); ok && limit > 0 {
		if used, ok := readFloat(payload.Usage.Used); ok {
			snap.PrimaryUsedPercent = used / limit
		} else if remaining, ok := readFloat(payload.Usage.Remaining); ok {
			snap.PrimaryUsedPercent = clampRateLimitPercent((limit - remaining) / limit)
		}
		snap.PrimaryUsed = snap.PrimaryUsedPercent
		snap.PrimaryUsedPercent = clampRateLimitPercent(snap.PrimaryUsedPercent)
		snap.PrimaryUsed = clampRateLimitPercent(snap.PrimaryUsed)
	}

	// Parse reset time
	if payload.Usage.ResetAt != "" {
		if t, err := time.Parse(time.RFC3339, payload.Usage.ResetAt); err == nil {
			snap.PrimaryResetAt = t
		}
	}

	// Find DAY-window limit for secondary usage
	for _, lim := range payload.Limits {
		if strings.EqualFold(lim.Window.TimeUnit, "DAY") {
			if detail := lim.Detail; detail != nil {
				if used, ok := readFloatFromMap(detail, "used"); ok {
					if limit, ok := readFloatFromMap(detail, "limit"); ok && limit > 0 {
						snap.SecondaryUsedPercent = used / limit
						snap.SecondaryUsed = snap.SecondaryUsedPercent
					}
				}
			}
			break
		}
	}

	log.Printf("kimi usage fetch %s: primary=%.1f%% secondary=%.1f%%",
		a.ID,
		snap.PrimaryUsedPercent*100,
		snap.SecondaryUsedPercent*100)

	a.mu.Lock()
	a.Usage = mergeUsage(a.Usage, snap)
	a.mu.Unlock()
	restoreValidatedAccount(a, "Kimi usage API")
	return nil
}

// seedMinimaxUsage sends a minimal request to capture initial rate limit headers.
func (h *proxyHandler) seedMinimaxUsage(now time.Time, a *Account) error {
	a.mu.Lock()
	access := a.AccessToken
	a.mu.Unlock()

	seedURL := h.cfg.minimaxBase.String() + "/v1/messages"
	body := []byte(`{"model":"MiniMax-M3","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`)

	req, _ := http.NewRequest(http.MethodPost, seedURL, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", ccAnthropicVersion)

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		a.mu.Lock()
		a.Dead = true
		a.Penalty += 100.0
		a.mu.Unlock()
		log.Printf("marking minimax account %s as dead: seed returned %d", a.ID, resp.StatusCode)
		if err := saveAccount(a); err != nil {
			log.Printf("warning: failed to save dead minimax account %s: %v", a.ID, err)
		}
		return fmt.Errorf("minimax seed unauthorized: %s", resp.Status)
	}

	// A successful model request proves the static credential is live, even when
	// an older request-scoped 401 left a persisted dead flag behind.
	applyMinimaxRateLimits(a, resp.Header, now)
	restoreValidatedAccount(a, "MiniMax model")

	return nil
}

func (h *proxyHandler) seedZAIUsage(now time.Time, a *Account) error {
	a.mu.Lock()
	access := a.AccessToken
	a.mu.Unlock()

	seedURL := h.cfg.zaiBase.String() + "/v1/messages"
	body := []byte(`{"model":"glm-5.2","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`)

	req, _ := http.NewRequest(http.MethodPost, seedURL, bytes.NewReader(body))
	req.Header.Set("X-Api-Key", access)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", ccAnthropicVersion)

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		a.mu.Lock()
		a.Dead = true
		a.Penalty += 100.0
		a.mu.Unlock()
		log.Printf("marking zai account %s as dead: seed returned %d", a.ID, resp.StatusCode)
		if err := saveAccount(a); err != nil {
			log.Printf("warning: failed to save dead zai account %s: %v", a.ID, err)
		}
		return fmt.Errorf("zai seed unauthorized: %s", resp.Status)
	}

	a.mu.Lock()
	a.Usage = mergeUsage(a.Usage, UsageSnapshot{
		RetrievedAt: now,
		Source:      "seed",
	})
	a.mu.Unlock()
	restoreValidatedAccount(a, "Z.ai model")
	return nil
}

// applyMinimaxRateLimits extracts rate limit data from MiniMax response headers and updates the account.
func applyMinimaxRateLimits(a *Account, headers http.Header, now time.Time) {
	remaining := headers.Get("x-ratelimit-remaining")
	limit := headers.Get("x-ratelimit-limit")
	if remaining == "" && limit == "" {
		// Try anthropic-style headers
		remaining = headers.Get("anthropic-ratelimit-requests-remaining")
		limit = headers.Get("anthropic-ratelimit-requests-limit")
	}

	if remaining == "" || limit == "" {
		return
	}

	remainingVal, err1 := strconv.ParseFloat(remaining, 64)
	limitVal, err2 := strconv.ParseFloat(limit, 64)
	if err1 != nil || err2 != nil || limitVal <= 0 {
		return
	}

	usedPercent := (limitVal - remainingVal) / limitVal

	// Try token-based limits too
	tokenRemaining := headers.Get("anthropic-ratelimit-tokens-remaining")
	tokenLimit := headers.Get("anthropic-ratelimit-tokens-limit")
	var tokenUsedPercent float64
	if tokenRemaining != "" && tokenLimit != "" {
		tRemain, err1 := strconv.ParseFloat(tokenRemaining, 64)
		tLimit, err2 := strconv.ParseFloat(tokenLimit, 64)
		if err1 == nil && err2 == nil && tLimit > 0 {
			tokenUsedPercent = (tLimit - tRemain) / tLimit
		}
	}

	snap := UsageSnapshot{
		PrimaryUsedPercent:   usedPercent,
		PrimaryUsed:          usedPercent,
		SecondaryUsedPercent: tokenUsedPercent,
		SecondaryUsed:        tokenUsedPercent,
		RetrievedAt:          now,
		Source:               "headers",
	}

	// Parse reset time
	resetStr := headers.Get("anthropic-ratelimit-requests-reset")
	if resetStr == "" {
		resetStr = headers.Get("x-ratelimit-reset")
	}
	if resetStr != "" {
		if t, err := time.Parse(time.RFC3339, resetStr); err == nil {
			snap.PrimaryResetAt = t
		}
	}

	a.mu.Lock()
	a.Usage = mergeUsage(a.Usage, snap)
	a.mu.Unlock()
}

// readFloat reads a float64 from a map with a string key.
func readFloatFromMap(m map[string]any, key string) (float64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	return readFloat(v)
}

func readBoolFromMap(m map[string]any, key string) (bool, bool) {
	v, ok := m[key]
	if !ok {
		return false, false
	}
	switch value := v.(type) {
	case bool:
		return value, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(value))
		return parsed, err == nil
	default:
		return false, false
	}
}

func readFloat(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case int64:
		return float64(val), true
	case int:
		return float64(val), true
	case int32:
		return float64(val), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
		return f, err == nil
	case json.Number:
		f, err := val.Float64()
		return f, err == nil
	}
	return 0, false
}
