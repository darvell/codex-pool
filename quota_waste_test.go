package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQuotaWasteSnapshotPersistsExplicitZeroAndOpaque(t *testing.T) {
	store, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	accounts := []*Account{
		{ID: "zero", Type: AccountTypeCodex, PlanType: "pro", Usage: UsageSnapshot{PrimaryUsed: 0, RetrievedAt: now, Source: "wham", primarySet: true}},
		{ID: "opaque", Type: AccountTypeMistral, Usage: UsageSnapshot{RetrievedAt: now, Source: "request"}},
	}
	h := &proxyHandler{analyticsStore: store, pool: newPoolState(accounts, false)}
	if err := h.recordQuotaWasteSnapshot(now); err != nil {
		t.Fatal(err)
	}
	rows, err := store.quotaWasteRows(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows=%d, want 2", len(rows))
	}
	byID := make(map[string]quotaWasteObservation, len(rows))
	for _, row := range rows {
		byID[row.AccountID] = row
	}
	zero, ok := byID[hashAccountID("zero")]
	if !ok || zero.Used == nil || *zero.Used != 0 || zero.WindowKey != "primary" || zero.WindowKind != "scheduled" || !zero.Fresh {
		t.Fatalf("explicit zero observation=%+v", zero)
	}
	opaque, ok := byID[hashAccountID("opaque")]
	if !ok || opaque.Used != nil || opaque.WindowKey != "opaque" || opaque.WindowKind != "opaque" || !opaque.Fresh {
		t.Fatalf("opaque observation=%+v", opaque)
	}
}

func TestQuotaWasteDisplayRowsOnlySummarizeConfirmedClosedWindows(t *testing.T) {
	used := 0.60
	reset := "2024-01-02T00:00:00Z"
	nextReset := "2024-01-03T00:00:00Z"
	rows := []quotaWasteObservation{
		{ObservedAt: "2024-01-01T23:55:00Z", SourceObservedAt: "2024-01-01T23:55:00Z", AccountID: "a", SeatID: "s", Provider: "codex", Plan: "pro", WindowKey: "primary", WindowKind: "scheduled", Used: &used, ResetAt: &reset, Source: "provider", Fresh: true, Health: "healthy"},
		{ObservedAt: "2024-01-02T00:05:00Z", SourceObservedAt: "2024-01-02T00:05:00Z", AccountID: "a", SeatID: "s", Provider: "codex", Plan: "pro", WindowKey: "primary", WindowKind: "scheduled", Used: func() *float64 { v := 0.0; return &v }(), ResetAt: &nextReset, Source: "provider", Fresh: true, Health: "healthy"},
	}
	accounts := quotaWasteDisplayRows(rows)
	if len(accounts) != 1 || len(accounts[0].Windows) != 1 {
		t.Fatalf("bounded windows=%+v", accounts)
	}
	window := accounts[0].Windows[0]
	if window.UnusedPercent != nil {
		t.Fatalf("open current window was labelled waste: %+v", window)
	}
	if window.Status != "open" || window.ClosedWindowCount != 1 || window.LastClosedUnusedPercent == nil || *window.LastClosedUnusedPercent != 40 {
		t.Fatalf("closed evidence=%+v", window)
	}
}

func TestQuotaWasteCandidatesRejectStaleEvidence(t *testing.T) {
	used := .50
	accounts := []quotaWasteAccount{
		{ID: "a", SeatID: "seat-a", Provider: "codex", Plan: "pro", Health: "healthy"},
		{ID: "b", SeatID: "seat-b", Provider: "codex", Plan: "pro", Health: "healthy"},
		{ID: "c", SeatID: "seat-c", Provider: "codex", Plan: "pro", Health: "healthy"},
	}
	rows := []quotaWasteObservation{
		{SeatID: "seat-a", Provider: "codex", Plan: "pro", Used: &used, Fresh: false, ObservedAt: "2024-01-01T00:00:00Z"},
		{SeatID: "seat-b", Provider: "codex", Plan: "pro", Used: &used, Fresh: true, ObservedAt: "2024-01-01T00:00:00Z"},
		{SeatID: "seat-c", Provider: "codex", Plan: "pro", Used: &used, Fresh: true, ObservedAt: "2024-01-01T00:00:00Z"},
	}
	candidates := quotaWasteCandidates(rows, accounts)
	if len(candidates) != len(accounts) {
		t.Fatalf("candidates=%+v, want a scenario for each of %d seats", candidates, len(accounts))
	}
	for _, candidate := range candidates {
		if candidate.Eligibility != "insufficient_evidence" || candidate.ProjectedPeakLoad != nil {
			t.Fatalf("stale evidence passed: %+v", candidate)
		}
	}
}

func TestQuotaWasteCandidatesUseReviewBurdenAsSafeTieBreak(t *testing.T) {
	used := .50
	accounts := []quotaWasteAccount{{ID: "healthy", SeatID: "seat-healthy", Provider: "codex", Plan: "pro", Health: "healthy"}, {ID: "review", SeatID: "seat-review", Provider: "codex", Plan: "pro", Health: "degraded"}, {ID: "reserve", SeatID: "seat-reserve", Provider: "codex", Plan: "pro", Health: "healthy"}}
	rows := []quotaWasteObservation{{SeatID: "seat-healthy", Provider: "codex", Plan: "pro", Used: &used, Fresh: true}, {SeatID: "seat-review", Provider: "codex", Plan: "pro", Used: &used, Fresh: true}, {SeatID: "seat-reserve", Provider: "codex", Plan: "pro", Used: &used, Fresh: true}}
	candidates := quotaWasteCandidates(rows, accounts)
	if len(candidates) != 3 || candidates[0].Eligibility != "modelled_safe" {
		t.Fatalf("candidates=%+v", candidates)
	}
	if candidates[0].ReviewBurden <= candidates[1].ReviewBurden || candidates[0].ReviewBurden != 1 {
		t.Fatalf("review burden tie-break=%+v", candidates)
	}
	if !strings.Contains(strings.Join(candidates[0].Rationale, " "), "not a safety pass") {
		t.Fatalf("rationale=%v", candidates[0].Rationale)
	}
}

func TestQuotaWasteCandidatesAllowOneSeatWhenRemainingReserveHolds(t *testing.T) {
	accounts := []quotaWasteAccount{
		{ID: "a", SeatID: "seat-a", Provider: "codex", Plan: "pro", Health: "healthy"},
		{ID: "b", SeatID: "seat-b", Provider: "codex", Plan: "pro", Health: "healthy"},
		{ID: "c", SeatID: "seat-c", Provider: "codex", Plan: "pro", Health: "healthy"},
	}
	used := .50
	rows := make([]quotaWasteObservation, 0, 3)
	for _, seat := range []string{"seat-a", "seat-b", "seat-c"} {
		rows = append(rows, quotaWasteObservation{SeatID: seat, Provider: "codex", Plan: "pro", Used: &used, Fresh: true})
	}
	candidates := quotaWasteCandidates(rows, accounts)
	if len(candidates) != len(accounts) {
		t.Fatalf("candidates=%+v, want a scenario for each of %d seats", candidates, len(accounts))
	}
	expected := map[string]bool{"a": true, "b": true, "c": true}
	for _, c := range candidates {
		if c.Eligibility != "modelled_safe" || c.ProjectedPeakLoad == nil || *c.ProjectedPeakLoad != .75 || !c.Independent || len(c.RemovesAccounts) != 1 {
			t.Fatalf("candidate=%+v", c)
		}
		removed := c.RemovesAccounts[0]
		if !expected[removed] {
			t.Fatalf("duplicate or unexpected removal=%s", removed)
		}
		delete(expected, removed)
	}
	if len(expected) != 0 {
		t.Fatalf("missing scenarios=%v", expected)
	}
}

func TestQuotaWasteObservationUsesManualSubscriptionLinks(t *testing.T) {
	store, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.db.Exec(`INSERT INTO subscription_rates(account_id,start_at,monthly_usd,known,source,subscription_id) VALUES (?, ?, ?, 1, 'manual', ?)`, "login-a", time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano), 100, "shared-seat"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	h := &proxyHandler{analyticsStore: store, pool: newPoolState([]*Account{{
		ID: "login-a", Type: AccountTypeCodex,
		Usage: UsageSnapshot{PrimaryUsed: .2, primarySet: true, RetrievedAt: now},
	}}, false)}
	if err := h.recordQuotaWasteSnapshot(now); err != nil {
		t.Fatal(err)
	}
	rows, err := store.quotaWasteRows(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].AccountID != hashAccountID("login-a") || rows[0].SeatID != hashAccountID("shared-seat") || rows[0].Used == nil || *rows[0].Used != .2 {
		t.Fatalf("manual seat grouping = %+v", rows)
	}
}

func TestQuotaWasteCandidatesRedistributeCompatibleSeats(t *testing.T) {
	accounts := []quotaWasteAccount{
		{ID: "a", SeatID: "seat-a", Provider: "codex", Plan: "pro", Health: "healthy"},
		{ID: "b", SeatID: "seat-b", Provider: "codex", Plan: "pro", Health: "healthy"},
	}
	used := .60
	rows := []quotaWasteObservation{
		{SeatID: "seat-a", Provider: "codex", Plan: "pro", Used: &used},
		{SeatID: "seat-b", Provider: "codex", Plan: "pro", Used: &used},
	}
	candidates := quotaWasteCandidates(rows, accounts)
	if len(candidates) != 2 {
		t.Fatalf("candidates=%d, want independent scenarios for both seats", len(candidates))
	}
	for _, c := range candidates {
		if c.Eligibility != "insufficient_evidence" {
			t.Fatalf("candidate=%+v", c)
		}
		if c.ProjectedPeakLoad == nil || *c.ProjectedPeakLoad != 1.2 {
			t.Fatalf("projected load=%v, want 1.2", c.ProjectedPeakLoad)
		}
	}
}
