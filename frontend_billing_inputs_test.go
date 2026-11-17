package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPoolStatsKeepsBillingInputsPrivate(t *testing.T) {
	store, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	addedAt := time.Now().UTC().AddDate(0, 0, -45)
	accounts := []*Account{
		{ID: "private-claude-5x", Type: AccountTypeClaude, PlanType: "max", RateLimitTier: "default_claude_max_5x", AddedAt: addedAt},
		{ID: "private-claude-20x", Type: AccountTypeClaude, PlanType: "max", RateLimitTier: "default_claude_max_20x", AddedAt: addedAt},
		{ID: "private-codex-prolite", Type: AccountTypeCodex, PlanType: "prolite", AddedAt: addedAt},
	}
	for i, account := range accounts {
		if err := store.recordRequest(RequestUsage{Timestamp: time.Now().UTC(), AccountID: account.ID, AccountType: account.Type, Model: "test-model"}, float64(i+1)*11); err != nil {
			t.Fatal(err)
		}
	}

	h := &proxyHandler{cfg: &config{}, pool: newPoolState(accounts, false), analyticsStore: store}
	response := httptest.NewRecorder()
	h.handlePoolStats(response, httptest.NewRequest(http.MethodGet, "/api/pool/stats", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	var stats PoolStats
	if err := json.Unmarshal(response.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if len(stats.Accounts) != len(accounts) {
		t.Fatalf("accounts = %d, want %d", len(stats.Accounts), len(accounts))
	}
	byID := make(map[string]AccountStats)
	for _, account := range stats.Accounts {
		byID[account.ID] = account
	}
	for i, account := range accounts {
		if strings.Contains(response.Body.String(), account.ID) {
			t.Fatalf("response disclosed account ID %q", account.ID)
		}
		got, ok := byID[hashAccountID(account.ID)]
		if !ok {
			t.Fatalf("missing public account for %q", account.ID)
		}
		monthly := []float64{100, 200, 100}[i]
		if got.SubscriptionCostMonthly != monthly || got.SubscriptionBillingCycles != 2 || got.SubscriptionSpend != monthly*2 {
			t.Errorf("billing for %q = monthly %v, cycles %d, spend %v", account.ID, got.SubscriptionCostMonthly, got.SubscriptionBillingCycles, got.SubscriptionSpend)
		}
		if got.APICostEstimate != float64(i+1)*11 {
			t.Errorf("cost for %q = %v, want %v", account.ID, got.APICostEstimate, float64(i+1)*11)
		}
		if got.CostTrackingStartedAt != addedAt.Format(time.RFC3339) {
			t.Errorf("billing start for %q = %s, want %s", account.ID, got.CostTrackingStartedAt, addedAt.Format(time.RFC3339))
		}
	}
}
