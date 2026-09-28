package main

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const antigravityQuotaSummaryFixture = `{"groups":[
 {"displayName":"Gemini Models","buckets":[
  {"bucketId":"gemini-weekly","window":"weekly","resetTime":"2026-10-01T10:40:06Z"},
  {"bucketId":"gemini-5h","window":"5h","resetTime":"2026-09-28T23:02:27Z","remainingFraction":0.9998}]},
 {"displayName":"Claude and GPT models","buckets":[
  {"bucketId":"3p-weekly","window":"weekly","resetTime":"2026-10-05T18:02:13Z","remainingFraction":0.75},
  {"bucketId":"3p-5h","window":"5h","resetTime":"2026-09-28T23:02:13Z","remainingFraction":0.5}]}]}`

const antigravityVerifyFixture = `{"error":{"code":403,"status":"PERMISSION_DENIED","message":"Verify your account to continue.","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"VALIDATION_REQUIRED","metadata":{"validation_url":"https://accounts.google.com/verify"}}]}}`

func antigravityTestResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestAntigravityWeeklyQuotaBlocksWholeModelGroup(t *testing.T) {
	now := time.Date(2026, 9, 28, 18, 0, 0, 0, time.UTC)
	summary, err := parseAntigravityQuotaSummary([]byte(antigravityQuotaSummaryFixture), now)
	if err != nil {
		t.Fatal(err)
	}
	weeklyReset := time.Date(2026, 10, 1, 10, 40, 6, 0, time.UTC)
	if got := summary.exhaustedUntil("gemini-3.8-flash-high", now); !got.Equal(weeklyReset) {
		t.Fatalf("gemini exhausted until %s, want weekly reset %s", got, weeklyReset)
	}
	if got := summary.exhaustedUntil("claude-opus-4-6-thinking", now); !got.IsZero() {
		t.Fatalf("claude should be available, exhausted until %s", got)
	}

	antigravityModels.Reset()
	t.Cleanup(antigravityModels.Reset)
	one := 1.0
	account := &Account{Type: AccountTypeAntigravity, ID: "ag", ModelRateLimits: map[string]time.Time{}}
	antigravityModels.ReplaceAccount(account.ID, AntigravityAccountSnapshot{
		FetchedAt: now,
		Models: map[string]AntigravityModelInfo{
			"gemini-3.8-flash-high":    {ID: "gemini-3.8-flash-high", Quota: AntigravityQuotaInfo{RemainingFraction: &one}},
			"claude-opus-4-6-thinking": {ID: "claude-opus-4-6-thinking", Quota: AntigravityQuotaInfo{RemainingFraction: &one}},
		},
		Quota: &summary,
	})
	available, reset := antigravityModels.DiscoveryAvailability(account.ID, "gemini-3.8-flash-high", now)
	if available || !reset.Equal(weeklyReset) {
		t.Fatalf("gemini availability = %v until %s despite per-model fraction 1", available, reset)
	}
	if available, _ := antigravityModels.DiscoveryAvailability(account.ID, "claude-opus-4-6-thinking", now); !available {
		t.Fatal("claude group still has quota")
	}

	windows := antigravityQuotaWindows(account.ID, now)
	labels := make([]string, 0, len(windows))
	for _, window := range windows {
		labels = append(labels, window.Label)
	}
	if strings.Join(labels, ",") != "Gemini 5h,Gemini weekly,Claude/GPT 5h,Claude/GPT weekly" {
		t.Fatalf("window labels = %v", labels)
	}
	if windows[1].UsedPct != 100 || windows[3].UsedPct != 25 {
		t.Fatalf("used percentages = %v / %v", windows[1].UsedPct, windows[3].UsedPct)
	}
}

func TestAntigravitySyncTrustsDailyHostForVerification(t *testing.T) {
	antigravityModels.Reset()
	t.Cleanup(antigravityModels.Reset)
	daily, _ := url.Parse("https://daily.example.test")
	production, _ := url.Parse("https://prod.example.test")
	file := filepath.Join(t.TempDir(), "ag.json")
	account := &Account{Type: AccountTypeAntigravity, ID: "ag", File: file, AccessToken: "token", ProjectID: "project", ModelRateLimits: map[string]time.Time{},
		NeedsVerification: true, VerificationURL: "https://accounts.google.com/verify", HealthError: antigravityVerifyFixture}

	dailyQuotaStatus := http.StatusOK
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(req.URL.Path, ":fetchAvailableModels"):
			return antigravityTestResponse(http.StatusOK, `{"models":{"gemini-live":{"displayName":"Gemini Live"}}}`), nil
		case req.URL.Host == production.Host:
			return antigravityTestResponse(http.StatusForbidden, antigravityVerifyFixture), nil
		case dailyQuotaStatus == http.StatusOK:
			return antigravityTestResponse(http.StatusOK, antigravityQuotaSummaryFixture), nil
		default:
			return antigravityTestResponse(dailyQuotaStatus, antigravityVerifyFixture), nil
		}
	})

	if err := syncAntigravityModels(context.Background(), transport, account, daily, production); err != nil {
		t.Fatal(err)
	}
	if account.NeedsVerification || account.HealthError != "" {
		t.Fatalf("daily quota success must clear verification: %v %q", account.NeedsVerification, account.HealthError)
	}
	snapshot, _ := antigravityModels.AccountSnapshot(account.ID)
	if snapshot.Quota == nil || len(snapshot.Quota.Groups) != 2 {
		t.Fatalf("quota summary not stored: %#v", snapshot.Quota)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("account was not persisted: %v", err)
	}

	dailyQuotaStatus = http.StatusForbidden
	if err := syncAntigravityModels(context.Background(), transport, account, daily, production); err == nil {
		t.Fatal("daily verification demand must be reported")
	}
	if !account.NeedsVerification || account.VerificationURL != "https://accounts.google.com/verify" {
		t.Fatalf("daily 403 must flag verification: %v %q", account.NeedsVerification, account.VerificationURL)
	}
	snapshot, _ = antigravityModels.AccountSnapshot(account.ID)
	if snapshot.Quota == nil {
		t.Fatal("previous quota summary must survive a failed quota poll")
	}
}

func TestAntigravityProductionForbiddenDoesNotReplaceDailyAnswer(t *testing.T) {
	daily, _ := url.Parse("https://daily.example.test")
	production, _ := url.Parse("https://prod.example.test")
	provider := NewAntigravityProvider(daily, production)
	handler := &proxyHandler{transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == production.Host {
			return antigravityTestResponse(http.StatusForbidden, antigravityVerifyFixture), nil
		}
		return antigravityTestResponse(http.StatusTooManyRequests, `{"error":{"status":"RESOURCE_EXHAUSTED"}}`), nil
	})}

	response, err := handler.doAntigravityRequest(context.Background(), nil, &Account{AccessToken: "token"}, provider, antigravityPreparedRequest{Body: []byte(`{}`), Operation: "generateContent"})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(body), "RESOURCE_EXHAUSTED") {
		t.Fatalf("got %d %s, want the daily 429", response.StatusCode, body)
	}
}
