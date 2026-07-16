package main

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestSignalAnalyticsLinksWeeklyOriginDrainAndCurrentAccountEconomics(t *testing.T) {
	usage, err := newUsageStore(filepath.Join(t.TempDir(), "usage.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	defer usage.Close()

	now := time.Now().UTC()
	if err := usage.record(RequestUsage{
		Timestamp:         now,
		AccountID:         "current",
		AccountType:       AccountTypeCodex,
		OriginID:          "origin-hash",
		InputTokens:       100,
		CachedInputTokens: 60,
		OutputTokens:      20,
		ReasoningTokens:   5,
		BillableTokens:    65,
	}); err != nil {
		t.Fatal(err)
	}

	analytics, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer analytics.Close()
	firstDate := now.AddDate(0, 0, -10).Format("2006-01-02")
	for _, row := range []struct {
		account string
		cost    float64
	}{
		{account: "current", cost: 100},
		{account: "removed", cost: 900},
	} {
		if _, err := analytics.db.Exec(`
			INSERT INTO daily_costs (date, account_id, account_type, model, request_count, cost_usd)
			VALUES (?, ?, ?, ?, ?, ?)`, firstDate, row.account, string(AccountTypeCodex), "gpt-5.6-sol", 1, row.cost); err != nil {
			t.Fatal(err)
		}
	}

	h := &proxyHandler{
		pool:           newPoolState([]*Account{{ID: "current", Type: AccountTypeCodex, PlanType: "pro"}}, false),
		store:          usage,
		analyticsStore: analytics,
	}
	recorder := httptest.NewRecorder()
	h.handleSignalAnalytics(recorder, httptest.NewRequest("GET", "/api/pool/signal?weeks=2", nil))

	var response SignalAnalyticsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.OriginWeekly) != 1 {
		t.Fatalf("origin weekly rows = %d, want 1", len(response.OriginWeekly))
	}
	origin := response.OriginWeekly[0]
	if origin.OriginID != "origin-hash" || origin.AccountID != hashAccountID("current") || origin.BillableTokens != 65 {
		t.Fatalf("origin weekly row = %+v", origin)
	}
	if len(response.Economics) == 0 {
		t.Fatal("economics timeline is empty")
	}
	latest := response.Economics[len(response.Economics)-1]
	if latest.CumulativeAPIValue != 100 {
		t.Fatalf("cumulative API value = %v, want current-account value 100", latest.CumulativeAPIValue)
	}
	if latest.CumulativeSubscriptionSpend != 200 {
		t.Fatalf("cumulative subscription spend = %v, want 200", latest.CumulativeSubscriptionSpend)
	}
}
