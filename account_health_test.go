package main

import (
	"testing"
	"time"
)

func TestAccountHealthPenalizesFailuresAndSlowStarts(t *testing.T) {
	now := time.Now()
	healthy := &Account{ID: "healthy"}
	failing := &Account{ID: "failing"}
	slow := &Account{ID: "slow"}
	for i := 0; i < 5; i++ {
		healthy.observeHealth(healthSuccess, 500*time.Millisecond)
		failing.observeHealth(healthFailure, 0)
		slow.observeHealth(healthSuccess, 20*time.Second)
	}

	if got := healthFactorLocked(healthy, now); got != 1 {
		t.Fatalf("healthy factor = %v, want 1", got)
	}
	if got := healthFactorLocked(failing, now); got >= 0.5 {
		t.Fatalf("failing factor = %v, want well below 1", got)
	}
	if got := healthFactorLocked(slow, now); got >= 0.5 {
		t.Fatalf("slow factor = %v, want well below 1", got)
	}
	if healthEscapesStickyLocked(healthy, now) {
		t.Fatal("healthy account shed its pins")
	}
	if !healthEscapesStickyLocked(failing, now) || !healthEscapesStickyLocked(slow, now) {
		t.Fatal("failing or slow account kept its pins")
	}
}

func TestAccountHealthRecoversWhileIdle(t *testing.T) {
	acc := &Account{ID: "idle"}
	for i := 0; i < 5; i++ {
		acc.observeHealth(healthFailure, 0)
	}
	later := time.Now().Add(10 * healthHalfLife)
	if got := healthFactorLocked(acc, later); got < 0.99 {
		t.Fatalf("factor after idling = %v, want near 1", got)
	}
	if healthEscapesStickyLocked(acc, later) {
		t.Fatal("idle account still sheds pins")
	}
}

func TestCandidateMovesPinOffFailingAccount(t *testing.T) {
	bad := &Account{Type: AccountTypeCodex, ID: "a-bad", AccessToken: "x", PlanType: "pro"}
	good := &Account{Type: AccountTypeCodex, ID: "b-good", AccessToken: "y", PlanType: "pro"}
	pool := newPoolState([]*Account{bad, good}, false)
	pool.pin("conv", bad.ID)
	if got := pool.candidate("conv", nil, AccountTypeCodex, "", ""); got != bad {
		t.Fatalf("pinned candidate = %v, want %s", got, bad.ID)
	}
	for i := 0; i < 5; i++ {
		bad.observeHealth(healthFailure, 0)
	}
	if got := pool.candidate("conv", nil, AccountTypeCodex, "", ""); got != good {
		t.Fatalf("candidate = %v, want the healthy account", got)
	}
}
