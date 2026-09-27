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
	if len(rates["old"]) != 2 {
		t.Fatalf("rate rows: %d (should only change once)", len(rates["old"]))
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
