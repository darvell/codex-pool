package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
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

	for _, a := range accs {
		if a == nil {
			continue
		}
		a.mu.Lock()
		dead := a.Dead
		hasToken := a.AccessToken != ""
		retrievedAt := a.Usage.RetrievedAt
		accType := a.Type
		a.mu.Unlock()

		if dead || !hasToken {
			continue
		}

		// Gemini accounts don't have WHAM usage endpoint, but still need refresh
		if accType == AccountTypeGemini {
			if !h.cfg.disableRefresh && h.needsRefresh(a) {
				if err := h.refreshAccount(context.Background(), a); err != nil {
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
			if h.cfg.debug {
				log.Printf("proactive refresh for %s failed: %v", a.ID, err)
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

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Try refresh once (unless disabled).
		if !h.cfg.disableRefresh && h.needsRefresh(a) {
			if err := h.refreshAccount(context.Background(), a); err == nil {
				resp.Body.Close()
				resp, err = doReq()
				if err != nil {
					return err
				}
				defer resp.Body.Close()
			}
		}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		a.mu.Lock()
		a.Dead = true
		a.Penalty += 1.0
		a.mu.Unlock()
		log.Printf("marking account %s as dead: usage fetch 401/403 after refresh attempt", a.ID)
		return fmt.Errorf("usage unauthorized: %s", resp.Status)
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

// replaceUsageHeaders replaces individual account X-Codex-* headers with pool aggregate values.
// This shows the client the overall pool capacity rather than a single account's usage.
func (h *proxyHandler) replaceUsageHeaders(hdr http.Header) {
	snap := h.pool.averageUsage()
	if snap.RetrievedAt.IsZero() {
		return // No usage data available
	}

	// Replace usage percentages with pool averages (convert back to 0-100 scale)
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
}
