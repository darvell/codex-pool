package main

import (
	"math"
	"path/filepath"
	"testing"
	"time"
)

func TestEconomicsRateHistoryPaymentsRemovalAndReconciliation(t *testing.T) {
	store, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	anchor := now.Add(-65 * 24 * time.Hour).Truncate(time.Second)
	a := &Account{ID: "old", Type: AccountTypeCodex, PlanType: "plus", AddedAt: anchor}
	if err := store.syncSubscriptionRates([]*Account{a}, anchor); err != nil {
		t.Fatal(err)
	}
	changed := anchor.Add(31 * 24 * time.Hour)
	a.PlanType = "pro"
	if err := store.syncSubscriptionRates([]*Account{a}, changed); err != nil {
		t.Fatal(err)
	}
	if err := store.syncSubscriptionRates([]*Account{a}, changed.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	rates, err := store.subscriptionRates()
	if err != nil {
		t.Fatal(err)
	}
	if len(rates["account:old"]) != 2 {
		t.Fatalf("rate rows: %d (should only change once)", len(rates["account:old"]))
	}
	if err := store.editEconomics(economicsEdit{Kind: "payment", AccountID: "old", AmountUSD: 15, Note: "invoice"}, anchor); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO daily_costs(date,account_id,account_type,model,cost_usd) VALUES(?,?,?,?,?)`, anchor.Format("2006-01-02"), "old", "codex", "gpt-5.6-sol", 500.0); err != nil {
		t.Fatal(err)
	}
	if err := store.syncSubscriptionRates(nil, now); err != nil {
		t.Fatal(err)
	}
	points, summary, err := store.economics(now)
	if err != nil {
		t.Fatal(err)
	}
	if summary.APIValue != 500 || math.Abs(summary.SubscriptionSpend-235) > 0.001 || summary.RecordedCycles != 1 || summary.EstimatedCycles != 2 || summary.CurrentMonthly != 0 {
		t.Fatalf("summary: %+v", summary)
	}
	last := points[len(points)-1]
	if last.CumulativeAPIValue != summary.APIValue || last.CumulativeSubscriptionSpend != summary.SubscriptionSpend {
		t.Fatalf("chart/headline mismatch: %+v %+v", last, summary)
	}
}

func TestEconomicsUnknownPriceDoesNotBecomeFree(t *testing.T) {
	store, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	if err := store.syncSubscriptionRates([]*Account{{ID: "unknown", Type: AccountTypeGrok, PlanType: "unlisted", AddedAt: now.Add(-32 * 24 * time.Hour)}}, now); err != nil {
		t.Fatal(err)
	}
	_, summary, err := store.economics(now)
	if err != nil {
		t.Fatal(err)
	}
	if summary.UnknownAccounts != 2 || summary.SubscriptionSpend != 0 {
		t.Fatalf("unknown price: %+v", summary)
	}
}

func TestEconomicsPaymentMustMatchBillingCycle(t *testing.T) {
	store, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.syncSubscriptionRates([]*Account{{ID: "a", Type: AccountTypeCodex, PlanType: "plus", AddedAt: now.Add(-50 * 24 * time.Hour)}}, now); err != nil {
		t.Fatal(err)
	}
	if err := store.editEconomics(economicsEdit{Kind: "payment", AccountID: "a", AmountUSD: 10}, now.Add(-25*24*time.Hour)); err == nil {
		t.Fatal("accepted arbitrary payment timestamp")
	}
}

func TestEconomicsReloginsOfOneSeatBillOnce(t *testing.T) {
	store, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Truncate(time.Second)
	seat := func(id string, added time.Time) *Account {
		return &Account{ID: id, Type: AccountTypeCodex, PlanType: "pro", AccountID: "workspace", ChatGPTUserID: "user-1", AddedAt: added}
	}
	other := &Account{ID: "other", Type: AccountTypeCodex, PlanType: "pro", AccountID: "workspace", ChatGPTUserID: "user-2", AddedAt: now.Add(-40 * 24 * time.Hour)}
	accounts := []*Account{seat("neon", now.Add(-40*24*time.Hour)), seat("neon_2", now.Add(-10*24*time.Hour)), seat("neon_3", now.Add(-5*24*time.Hour)), other}
	if err := store.syncSubscriptionRates(accounts, now); err != nil {
		t.Fatal(err)
	}

	_, summary, err := store.economics(now)
	if err != nil {
		t.Fatal(err)
	}
	// Two seats (user-1 via three logins, user-2) over two cycles each.
	if summary.SubscriptionSpend != 800 || summary.EstimatedCycles != 4 || summary.CurrentMonthly != 400 {
		t.Fatalf("summary: %+v", summary)
	}
}

func TestEconomicsHistoryCountsRemovedSubscriptions(t *testing.T) {
	store, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Truncate(time.Second)
	start := now.Add(-100 * 24 * time.Hour)
	for id, day := range map[string]time.Time{"darv": start, "cont_2": start.Add(50 * 24 * time.Hour)} {
		if _, err := store.db.Exec(`INSERT INTO daily_costs(date,account_id,account_type,model,cost_usd) VALUES(?,?,?,?,?)`, day.Format("2006-01-02"), id, "codex", "gpt-5.6", 50.0); err != nil {
			t.Fatal(err)
		}
	}

	history := economicsEdit{Kind: economicsEditHistory, AccountID: "darv", AmountUSD: 200, SubscriptionID: "history:contact"}
	if err := store.recordSubscriptionHistory(history, start, start.Add(45*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// cont_2 logged into the same seat while darv was still active.
	second := economicsEdit{Kind: economicsEditHistory, AccountID: "cont_2", AmountUSD: 200, SubscriptionID: "history:contact"}
	if err := store.recordSubscriptionHistory(second, start.Add(40*24*time.Hour), start.Add(80*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.recordSubscriptionHistory(history, start.Add(time.Hour), start.Add(24*time.Hour)); err == nil {
		t.Fatal("accepted history overlapping the same account")
	}
	if err := store.syncSubscriptionRates(nil, now); err != nil {
		t.Fatal(err)
	}

	_, summary, err := store.economics(now)
	if err != nil {
		t.Fatal(err)
	}
	// One seat from day 0 to day 80: cycles at 0, 30, and 60.
	if summary.SubscriptionSpend != 600 || summary.EstimatedCycles != 3 || summary.UncoveredValue != 0 || summary.CurrentMonthly != 0 {
		t.Fatalf("summary: %+v", summary)
	}

	valid := economicsEdit{Kind: economicsEditHistory, AccountID: "x", SubscriptionID: "s", AmountUSD: 1, EffectiveAt: start.Format(time.RFC3339), EndAt: now.Add(time.Hour).Format(time.RFC3339)}
	if _, _, err := validateEconomicsEdit(valid, now); err == nil {
		t.Fatal("accepted history ending in the future")
	}
}
