package main

import (
	"sync/atomic"
	"testing"
)

func TestImageFanoutExcludesBusyAccountsWhenIdleCapacityExists(t *testing.T) {
	busy := &Account{ID: "busy", Type: AccountTypeCodex}
	idle := &Account{ID: "idle", Type: AccountTypeCodex}
	atomic.StoreInt64(&busy.Inflight, 1)
	pool := newPoolState([]*Account{busy, idle}, false)

	exclude := map[string]bool{}
	pool.excludeInflightWhenIdleAvailable(AccountTypeCodex, exclude)
	if !exclude["busy"] {
		t.Fatal("busy account was not excluded")
	}
	if exclude["idle"] {
		t.Fatal("idle account was excluded")
	}
}

func TestImageFanoutCandidateRotatesAcrossAccounts(t *testing.T) {
	first := &Account{ID: "a", Type: AccountTypeCodex}
	second := &Account{ID: "b", Type: AccountTypeCodex}
	third := &Account{ID: "c", Type: AccountTypeCodex}
	pool := newPoolState([]*Account{third, first, second}, false)

	for index, want := range []string{"a", "b", "c", "a"} {
		got := pool.imageFanoutCandidate(index, map[string]bool{}, "", "")
		if got == nil || got.ID != want {
			t.Fatalf("index %d candidate = %#v, want %q", index, got, want)
		}
	}
}

func TestImageFanoutAllowsBusyAccountsWhenAllCapacityIsBusy(t *testing.T) {
	first := &Account{ID: "first", Type: AccountTypeCodex}
	second := &Account{ID: "second", Type: AccountTypeCodex}
	atomic.StoreInt64(&first.Inflight, 1)
	atomic.StoreInt64(&second.Inflight, 1)
	pool := newPoolState([]*Account{first, second}, false)

	exclude := map[string]bool{}
	pool.excludeInflightWhenIdleAvailable(AccountTypeCodex, exclude)
	if len(exclude) != 0 {
		t.Fatalf("all-busy pool should remain eligible, got %#v", exclude)
	}
}

func TestImageCapabilityLearnsAfterRepeatedFailures(t *testing.T) {
	account := &Account{ID: "unsupported", Type: AccountTypeCodex}
	recordImageGenerationResult(account, false)
	if got := atomic.LoadInt32(&account.ImageGenerationSupport); got != -1 {
		t.Fatalf("support after one failure = %d", got)
	}

	pool := newPoolState([]*Account{account}, false)
	exclude := map[string]bool{}
	pool.excludeImageIncapable(exclude)
	if !exclude[account.ID] {
		t.Fatal("known incapable account was not excluded")
	}

	recordImageGenerationResult(account, true)
	if got := atomic.LoadInt32(&account.ImageGenerationSupport); got != 1 {
		t.Fatalf("support after success = %d", got)
	}
}
