package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Antigravity enforces quota per model group rather than per model: every
// Gemini model shares one 5-hour and one weekly bucket, and Claude/GPT-OSS
// share another pair. fetchAvailableModels only mirrors the 5-hour bucket, so
// the weekly limit is visible only through retrieveUserQuotaSummary.
const (
	antigravityQuotaFamilyGemini     = "gemini"
	antigravityQuotaFamilyThirdParty = "3p"
	antigravityQuotaWindowFiveHour   = "5h"
	antigravityQuotaWindowWeekly     = "weekly"
)

type AntigravityQuotaBucket struct {
	ID                string    `json:"id"`
	Window            string    `json:"window"`
	RemainingFraction float64   `json:"remaining_fraction"`
	ResetTime         time.Time `json:"reset_time,omitempty"`
}

type AntigravityQuotaGroup struct {
	Family  string                   `json:"family"`
	Name    string                   `json:"name"`
	Buckets []AntigravityQuotaBucket `json:"buckets"`
}

type AntigravityQuotaSummary struct {
	FetchedAt time.Time               `json:"fetched_at"`
	Groups    []AntigravityQuotaGroup `json:"groups"`
}

type antigravityForbiddenError struct {
	body []byte
}

func (e *antigravityForbiddenError) Error() string {
	return "forbidden: " + safeText(e.body)
}

func parseAntigravityQuotaSummary(body []byte, fetchedAt time.Time) (AntigravityQuotaSummary, error) {
	var payload struct {
		Groups []struct {
			DisplayName string `json:"displayName"`
			Buckets     []struct {
				BucketID string `json:"bucketId"`
				Window   string `json:"window"`
				// proto3 JSON omits zero values, so an absent fraction is an
				// exhausted bucket, not an unknown one.
				RemainingFraction float64 `json:"remainingFraction"`
				ResetTime         string  `json:"resetTime"`
			} `json:"buckets"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return AntigravityQuotaSummary{}, err
	}
	summary := AntigravityQuotaSummary{FetchedAt: fetchedAt.UTC()}
	for _, rawGroup := range payload.Groups {
		group := AntigravityQuotaGroup{Name: rawGroup.DisplayName}
		for _, rawBucket := range rawGroup.Buckets {
			resetTime, _ := time.Parse(time.RFC3339Nano, rawBucket.ResetTime)
			group.Buckets = append(group.Buckets, AntigravityQuotaBucket{
				ID:                rawBucket.BucketID,
				Window:            rawBucket.Window,
				RemainingFraction: rawBucket.RemainingFraction,
				ResetTime:         resetTime,
			})
			if family, _, ok := strings.Cut(rawBucket.BucketID, "-"); ok && group.Family == "" {
				group.Family = family
			}
		}
		if len(group.Buckets) > 0 {
			summary.Groups = append(summary.Groups, group)
		}
	}
	if len(summary.Groups) == 0 {
		return AntigravityQuotaSummary{}, errors.New("retrieveUserQuotaSummary returned no quota groups")
	}
	return summary, nil
}

// fetchAntigravityQuota asks the daily host first because that is the host
// generation uses. Only its 403 describes the account: the production host
// can demand verification for an account the daily host still serves.
func fetchAntigravityQuota(ctx context.Context, transport http.RoundTripper, account *Account, daily, production *url.URL) (AntigravityQuotaSummary, error) {
	account.mu.Lock()
	body, _ := json.Marshal(map[string]string{"project": account.ProjectID})
	account.mu.Unlock()

	var lastErr error
	for index, base := range []*url.URL{daily, production} {
		if base == nil {
			continue
		}
		status, responseBody, err := postAntigravityInternal(ctx, transport, account, base, "retrieveUserQuotaSummary", body)
		if err != nil {
			lastErr = err
			continue
		}
		if status == http.StatusForbidden && index == 0 {
			return AntigravityQuotaSummary{}, &antigravityForbiddenError{body: responseBody}
		}
		if status < 200 || status >= 300 {
			lastErr = fmt.Errorf("retrieveUserQuotaSummary failed: %d: %s", status, safeText(responseBody))
			continue
		}
		return parseAntigravityQuotaSummary(responseBody, time.Now())
	}
	if lastErr == nil {
		lastErr = errors.New("retrieveUserQuotaSummary has no configured upstream")
	}
	return AntigravityQuotaSummary{}, lastErr
}

func antigravityQuotaFamily(model string) string {
	lower := strings.ToLower(model)
	switch {
	case strings.HasPrefix(lower, "claude"), strings.HasPrefix(lower, "gpt"):
		return antigravityQuotaFamilyThirdParty
	case strings.HasPrefix(lower, "gemini") && !strings.Contains(lower, "image"):
		return antigravityQuotaFamilyGemini
	default:
		return ""
	}
}

func (s *AntigravityQuotaSummary) group(family string) *AntigravityQuotaGroup {
	if s == nil || family == "" {
		return nil
	}
	for i := range s.Groups {
		if s.Groups[i].Family == family {
			return &s.Groups[i]
		}
	}
	return nil
}

func (g *AntigravityQuotaGroup) bucket(window string) *AntigravityQuotaBucket {
	if g == nil {
		return nil
	}
	for i := range g.Buckets {
		if g.Buckets[i].Window == window {
			return &g.Buckets[i]
		}
	}
	return nil
}

// exhaustedUntil returns the latest reset among the model group's empty
// buckets; a model is usable only once every bucket it draws from refills.
func (s *AntigravityQuotaSummary) exhaustedUntil(model string, now time.Time) time.Time {
	group := s.group(antigravityQuotaFamily(model))
	if group == nil {
		return time.Time{}
	}
	var until time.Time
	for _, bucket := range group.Buckets {
		if bucket.RemainingFraction <= 0 && bucket.ResetTime.After(now) && bucket.ResetTime.After(until) {
			until = bucket.ResetTime
		}
	}
	return until
}

// AccountQuotaWindow is one provider-reported quota bucket as shown on the
// status page.
type AccountQuotaWindow struct {
	Label         string  `json:"label"`
	UsedPct       float64 `json:"used_pct"`
	ResetMinutes  int     `json:"reset_minutes"`
	WindowMinutes int     `json:"window_minutes"`
}

var antigravityQuotaFamilyLabels = map[string]string{
	antigravityQuotaFamilyGemini:     "Gemini",
	antigravityQuotaFamilyThirdParty: "Claude/GPT",
}

var antigravityQuotaWindowSpecs = []struct {
	window  string
	label   string
	minutes int
}{
	{antigravityQuotaWindowFiveHour, "5h", 5 * 60},
	{antigravityQuotaWindowWeekly, "weekly", 7 * 24 * 60},
}

func antigravityQuotaWindows(accountID string, now time.Time) []AccountQuotaWindow {
	snapshot, ok := antigravityModels.AccountSnapshot(accountID)
	if !ok || snapshot.Quota == nil {
		return nil
	}
	var windows []AccountQuotaWindow
	for _, family := range []string{antigravityQuotaFamilyGemini, antigravityQuotaFamilyThirdParty} {
		group := snapshot.Quota.group(family)
		for _, spec := range antigravityQuotaWindowSpecs {
			bucket := group.bucket(spec.window)
			if bucket == nil {
				continue
			}
			resetMinutes := 0
			if bucket.ResetTime.After(now) {
				resetMinutes = int(bucket.ResetTime.Sub(now).Minutes())
			}
			windows = append(windows, AccountQuotaWindow{
				Label:         antigravityQuotaFamilyLabels[family] + " " + spec.label,
				UsedPct:       (1 - bucket.RemainingFraction) * 100,
				ResetMinutes:  resetMinutes,
				WindowMinutes: spec.minutes,
			})
		}
	}
	return windows
}

func recordAntigravityForbidden(account *Account, body []byte) {
	applyAntigravityForbidden(account, body)
	_ = saveAccount(account)
}

func applyAntigravityForbidden(account *Account, body []byte) {
	needsVerification, banned, verificationURL := classifyAntigravityForbidden(body)
	account.mu.Lock()
	defer account.mu.Unlock()
	account.NeedsVerification = needsVerification
	account.VerificationURL = verificationURL
	account.HealthError = strings.TrimSpace(string(body))
	if banned {
		account.Dead = true
	}
	if !needsVerification && !banned {
		account.RateLimitUntil = time.Now().Add(30 * time.Minute)
	}
}

func clearAntigravityHealth(account *Account) {
	account.mu.Lock()
	hadHealthError := account.NeedsVerification || account.VerificationURL != "" || account.HealthError != ""
	account.NeedsVerification, account.VerificationURL, account.HealthError = false, "", ""
	account.mu.Unlock()
	if hadHealthError {
		_ = saveAccount(account)
	}
}
