package main

import (
	"testing"
	"time"
)

func TestPreserveUsageSnapshotsAcrossAccountReload(t *testing.T) {
	resetAt := time.Date(2026, 7, 21, 20, 40, 0, 0, time.UTC)
	current := &Account{
		Type: AccountTypeCodex,
		ID:   "codex-one",
		Usage: UsageSnapshot{
			SecondaryUsed:        0.18,
			SecondaryUsedPercent: 18,
			SecondaryResetAt:     resetAt,
			RetrievedAt:          time.Now(),
			Source:               "wham",
			secondarySet:         true,
		},
	}
	loaded := &Account{Type: AccountTypeCodex, ID: "codex-one"}

	preserveUsageSnapshots([]*Account{current}, []*Account{loaded})

	if !loaded.Usage.secondarySet || loaded.Usage.SecondaryUsedPercent != 18 {
		t.Fatalf("weekly usage was not preserved: %#v", loaded.Usage)
	}
	if !loaded.Usage.SecondaryResetAt.Equal(resetAt) {
		t.Fatalf("weekly reset = %s, want %s", loaded.Usage.SecondaryResetAt, resetAt)
	}
}

func TestPreserveUsageSnapshotsDoesNotCrossAccountTypes(t *testing.T) {
	current := &Account{Type: AccountTypeCodex, ID: "shared", Usage: UsageSnapshot{SecondaryUsedPercent: 18, secondarySet: true}}
	loaded := &Account{Type: AccountTypeClaude, ID: "shared"}

	preserveUsageSnapshots([]*Account{current}, []*Account{loaded})

	if loaded.Usage.secondarySet {
		t.Fatal("usage crossed provider boundary")
	}
}
