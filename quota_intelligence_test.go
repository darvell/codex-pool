package main

import (
	"math"
	"testing"
	"time"
)

func TestInferQuotaIntelligenceAccumulatesRoundedIntervals(t *testing.T) {
	start := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	rows := []RequestUsage{
		{Timestamp: start, AccountID: "acct", AccountType: AccountTypeCodex, PlanType: "pro", Model: "cheap", SecondaryUsedPct: .10, SecondaryResetAt: start.Add(7 * 24 * time.Hour)},
		{Timestamp: start.Add(time.Hour), AccountID: "acct", AccountType: AccountTypeCodex, PlanType: "pro", Model: "cheap", InputTokens: 100, SecondaryUsedPct: .10},
		{Timestamp: start.Add(2 * time.Hour), AccountID: "acct", AccountType: AccountTypeCodex, PlanType: "pro", Model: "rich", InputTokens: 100, SecondaryUsedPct: .12},
		{Timestamp: start.Add(3 * time.Hour), AccountID: "acct", AccountType: AccountTypeCodex, PlanType: "pro", Model: "rich", InputTokens: 100, SecondaryUsedPct: .12},
		{Timestamp: start.Add(4 * time.Hour), AccountID: "acct", AccountType: AccountTypeCodex, PlanType: "pro", Model: "rich", InputTokens: 100, SecondaryUsedPct: .14},
	}
	cost := func(row RequestUsage) float64 {
		if row.Model == "rich" {
			return 4
		}
		return 1
	}
	capacity, models, resets := inferQuotaIntelligence(rows, nil, cost)
	if len(capacity) != 1 {
		t.Fatalf("capacity rows = %d, want 1", len(capacity))
	}
	if capacity[0].EstimatedWeeklyTokens != 10000 || math.Abs(capacity[0].ObservedQuotaPct-4) > 0.001 {
		t.Fatalf("unexpected capacity point: %+v", capacity[0])
	}
	if len(models) != 2 || models[0].Model != "rich" || models[0].RelativeSubsidy <= 1 {
		t.Fatalf("unexpected model efficiency: %+v", models)
	}
	if len(resets) != 0 {
		t.Fatalf("unexpected reset events: %+v", resets)
	}
}

func TestInferQuotaIntelligenceFlagsEarlyObservedReset(t *testing.T) {
	start := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	expected := start.Add(7 * 24 * time.Hour)
	rows := []RequestUsage{
		{Timestamp: start, AccountID: "acct", AccountType: AccountTypeCodex, SecondaryUsedPct: .70, SecondaryResetAt: expected},
		{Timestamp: start.Add(24 * time.Hour), AccountID: "acct", AccountType: AccountTypeCodex, InputTokens: 10, SecondaryUsedPct: .72},
		{Timestamp: start.Add(48 * time.Hour), AccountID: "acct", AccountType: AccountTypeCodex, InputTokens: 10, SecondaryUsedPct: .03},
	}
	_, _, resets := inferQuotaIntelligence(rows, nil, nil)
	if len(resets) != 1 || resets[0].Timing != "early" || resets[0].DeviationMinutes == nil {
		t.Fatalf("unexpected reset event: %+v", resets)
	}
	if *resets[0].DeviationMinutes != -5*24*60 {
		t.Fatalf("deviation = %d, want %d", *resets[0].DeviationMinutes, -5*24*60)
	}
}
