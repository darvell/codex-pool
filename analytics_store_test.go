package main

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestAllTimeAccountCostStatsIncludesMeasurementStart(t *testing.T) {
	store, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()

	firstDate := time.Now().UTC().AddDate(0, 0, -45).Format("2006-01-02")
	if _, err := store.db.Exec(`
		INSERT INTO daily_costs (date, account_id, account_type, model, request_count, cost_usd)
		VALUES (?, ?, ?, ?, ?, ?)`, firstDate, "account", string(AccountTypeCodex), "gpt-5.6-sol", 1, 10.0); err != nil {
		t.Fatal(err)
	}
	if err := store.recordRequest(RequestUsage{
		Timestamp:   time.Now().UTC(),
		AccountID:   "account",
		AccountType: AccountTypeCodex,
		Model:       "gpt-5.6-sol",
	}, 2.5); err != nil {
		t.Fatal(err)
	}

	stats, err := store.getAllTimeAccountCostStats()
	if err != nil {
		t.Fatal(err)
	}
	got := stats["account"]
	if got.CostUSD != 12.5 {
		t.Fatalf("cost = %v, want 12.5", got.CostUSD)
	}
	if got.FirstSeen.Format("2006-01-02") != firstDate {
		t.Fatalf("first seen = %v, want %s", got.FirstSeen, firstDate)
	}
}

func TestPoolStatsROIUsesCumulativeSubscriptionSpendForCurrentAccounts(t *testing.T) {
	store, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()

	firstDate := time.Now().UTC().AddDate(0, 0, -45).Format("2006-01-02")
	for _, row := range []struct {
		accountID string
		cost      float64
	}{
		{accountID: "current", cost: 1000},
		{accountID: "removed", cost: 9000},
	} {
		if _, err := store.db.Exec(`
			INSERT INTO daily_costs (date, account_id, account_type, model, request_count, cost_usd)
			VALUES (?, ?, ?, ?, ?, ?)`, firstDate, row.accountID, string(AccountTypeCodex), "gpt-5.6-sol", 1, row.cost); err != nil {
			t.Fatal(err)
		}
	}

	h := &proxyHandler{
		cfg:            &config{},
		pool:           newPoolState([]*Account{{ID: "current", Type: AccountTypeCodex, PlanType: "pro"}}, false),
		analyticsStore: store,
	}
	recorder := httptest.NewRecorder()
	h.handlePoolStats(recorder, httptest.NewRequest("GET", "/api/pool/stats", nil))

	var stats PoolStats
	if err := json.Unmarshal(recorder.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if len(stats.Accounts) != 1 {
		t.Fatalf("accounts = %d", len(stats.Accounts))
	}
	account := stats.Accounts[0]
	if account.SubscriptionSpend != 400 || account.SubscriptionBillingCycles != 2 {
		t.Fatalf("subscription spend = %v across %d cycles, want 400 across 2", account.SubscriptionSpend, account.SubscriptionBillingCycles)
	}
	if account.ROI != 2.5 {
		t.Fatalf("account ROI = %v, want 2.5", account.ROI)
	}
	if stats.AggregateUsage.TotalAPICost != 1000 {
		t.Fatalf("total API cost = %v, want current-account cost 1000", stats.AggregateUsage.TotalAPICost)
	}
	if stats.AggregateUsage.TotalSubscriptionCost != 400 || stats.AggregateUsage.TotalSubscriptionMonthly != 200 {
		t.Fatalf("subscription totals = spend %v monthly %v", stats.AggregateUsage.TotalSubscriptionCost, stats.AggregateUsage.TotalSubscriptionMonthly)
	}
	if stats.AggregateUsage.OverallROI != 2.5 {
		t.Fatalf("overall ROI = %v, want 2.5", stats.AggregateUsage.OverallROI)
	}
	provider := stats.AggregateUsage.CostByProvider[string(AccountTypeCodex)]
	if provider.SubscriptionCost != 400 || provider.MonthlySubscriptionCost != 200 || provider.ROI != 2.5 {
		t.Fatalf("provider cost summary = %+v", provider)
	}
}

func TestQuotaPaceRatioSignalsEarlyExhaustion(t *testing.T) {
	if got := quotaPaceRatio(1, 10050, 10080); got != 0 {
		t.Fatalf("fresh quantized sample pace = %v, want acquiring (0)", got)
	}
	if got := quotaPaceRatio(50, 150, 300); got != 1 {
		t.Fatalf("even pace = %v, want 1", got)
	}
	if got := quotaPaceRatio(50, 225, 300); got != 2 {
		t.Fatalf("fast pace = %v, want 2", got)
	}
	if got := quotaPaceRatio(50, 0, 300); got != 0 {
		t.Fatalf("unknown/resetting pace = %v, want 0", got)
	}
}

func TestPoolStatsROIUsesAccountAdmissionDate(t *testing.T) {
	store, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	firstUsage := time.Now().UTC().AddDate(0, 0, -2).Format("2006-01-02")
	if _, err := store.db.Exec(`
		INSERT INTO daily_costs (date, account_id, account_type, model, request_count, cost_usd)
		VALUES (?, ?, ?, ?, ?, ?)`, firstUsage, "current", string(AccountTypeCodex), "gpt-5.6-sol", 1, 1000); err != nil {
		t.Fatal(err)
	}

	h := &proxyHandler{
		cfg:            &config{},
		pool:           newPoolState([]*Account{{ID: "current", Type: AccountTypeCodex, PlanType: "pro", AddedAt: time.Now().UTC().AddDate(0, 0, -45)}}, false),
		analyticsStore: store,
	}
	recorder := httptest.NewRecorder()
	h.handlePoolStats(recorder, httptest.NewRequest("GET", "/api/pool/stats", nil))

	var stats PoolStats
	if err := json.Unmarshal(recorder.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if got := stats.Accounts[0].SubscriptionSpend; got != 400 {
		t.Fatalf("subscription spend = %v, want 400 from 45-day admission period", got)
	}
	if got := stats.Accounts[0].ROI; got != 2.5 {
		t.Fatalf("ROI = %v, want 2.5", got)
	}
}

func TestPoolStatsLast24hUsesProcessedThroughput(t *testing.T) {
	usage, err := newUsageStore(filepath.Join(t.TempDir(), "usage.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	defer usage.Close()

	now := time.Now().UTC()
	for _, request := range []RequestUsage{
		{Timestamp: now, AccountID: "codex", AccountType: AccountTypeCodex, UserID: "friend", InputTokens: 3000000, CachedInputTokens: 1000000, OutputTokens: 250000, BillableTokens: 2250000},
		{Timestamp: now, AccountID: "claude", AccountType: AccountTypeClaude, UserID: "friend", InputTokens: 100, CachedInputTokens: 500, OutputTokens: 10, BillableTokens: 110},
	} {
		if err := usage.record(request); err != nil {
			t.Fatal(err)
		}
	}

	h := &proxyHandler{
		cfg:   &config{},
		pool:  newPoolState([]*Account{{ID: "codex", Type: AccountTypeCodex}, {ID: "claude", Type: AccountTypeClaude}}, false),
		store: usage,
	}
	recorder := httptest.NewRecorder()
	h.handlePoolStats(recorder, httptest.NewRequest("GET", "/api/pool/stats", nil))

	var stats PoolStats
	if err := json.Unmarshal(recorder.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	const want = int64(3250610)
	if stats.Last24hTokens != want {
		t.Fatalf("last 24h throughput = %d, want %d", stats.Last24hTokens, want)
	}
}

func TestDailyRollupIsIdempotent(t *testing.T) {
	store, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()

	yesterday := time.Now().UTC().AddDate(0, 0, -1)
	if err := store.recordRequest(RequestUsage{
		Timestamp:      yesterday,
		AccountID:      "account",
		AccountType:    AccountTypeCodex,
		Model:          "gpt-5.6-sol",
		InputTokens:    10,
		OutputTokens:   5,
		BillableTokens: 15,
	}, 1.25); err != nil {
		t.Fatal(err)
	}

	store.runDailyRollup()
	store.runDailyRollup()

	var requests int
	var cost float64
	err = store.db.QueryRow(
		`SELECT request_count, cost_usd FROM daily_costs WHERE date = ? AND account_id = ? AND model = ?`,
		yesterday.Format("2006-01-02"),
		"account",
		"gpt-5.6-sol",
	).Scan(&requests, &cost)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 || cost != 1.25 {
		t.Fatalf("rollup duplicated data: requests=%d cost=%f", requests, cost)
	}
}
