package main

import "testing"

// A reload must not move a live conversation to a different account.
//
// codex-pool reloads the pool whenever the pool directory or the account list
// changes — adding, removing, disabling or editing an account, and also a
// reload that changes nothing at all, because the directory watcher fires on
// any touch. Before the fix, replace() wiped the whole conversation-pin map on
// every one of those, so an in-flight conversation silently continued on a
// different account.
//
// These tests assert behaviour, not the contents of the map: the pinned
// account is deliberately made the WORSE choice, so a passing test can only
// mean the pin was honoured.

func pinnedTestAccount(id string, primaryUsed float64) *Account {
	return &Account{
		ID:       id,
		Type:     AccountTypeCodex,
		PlanType: "pro",
		Usage:    UsageSnapshot{PrimaryUsedPercent: primaryUsed},
	}
}

func TestReplaceKeepsPinForAccountStillPresent(t *testing.T) {
	// alpha is heavily used but still under the hard-exclude threshold, so it
	// remains a legal pin while never being the account free selection picks.
	alpha := pinnedTestAccount("alpha", 0.90)
	beta := pinnedTestAccount("beta", 0.0)
	p := newPoolState([]*Account{alpha, beta}, false)

	p.pin("conv-1", "alpha")

	if got := p.candidate("conv-1", nil, AccountTypeCodex, "", ""); got != alpha {
		t.Fatalf("precondition: expected the pin to hold before reload, got %v", got)
	}

	// A reload that adds an unrelated account. alpha is still present, so its
	// pin must survive.
	gamma := pinnedTestAccount("gamma", 0.0)
	p.replace([]*Account{alpha, beta, gamma})

	got := p.candidate("conv-1", nil, AccountTypeCodex, "", "")
	if got == nil {
		t.Fatal("after reload the conversation got no account at all")
	}
	if got != alpha {
		t.Fatalf("reload moved conversation conv-1 from alpha to %s; pins must survive a reload that still contains the pinned account", got.ID)
	}
}

func TestReplaceDropsPinForRemovedAccount(t *testing.T) {
	alpha := pinnedTestAccount("alpha", 0.90)
	beta := pinnedTestAccount("beta", 0.0)
	p := newPoolState([]*Account{alpha, beta}, false)

	p.pin("conv-1", "alpha")

	// alpha is removed from the pool. The orphaned pin must not survive, and
	// the conversation must be routed somewhere valid rather than dropped.
	p.replace([]*Account{beta})

	got := p.candidate("conv-1", nil, AccountTypeCodex, "", "")
	if got == nil {
		t.Fatal("removing the pinned account left the conversation with no account")
	}
	if got.ID != "beta" {
		t.Fatalf("expected the conversation to move to beta after alpha was removed, got %s", got.ID)
	}
	// The orphaned pin must be gone rather than left dangling. candidate()
	// does not re-pin — the request handler does that — so the map is simply
	// expected not to name the removed account any more.
	if id, ok := p.convPin["conv-1"]; ok && id == "alpha" {
		t.Fatal("pin still points at the removed account alpha")
	}
}

// A reload that changes nothing must be a no-op for pinning. This is the case
// the file watcher hits most often and the one that was most surprising.
func TestReplaceWithIdenticalSetKeepsPins(t *testing.T) {
	alpha := pinnedTestAccount("alpha", 0.90)
	beta := pinnedTestAccount("beta", 0.0)
	p := newPoolState([]*Account{alpha, beta}, false)

	p.pin("conv-1", "alpha")
	p.replace([]*Account{alpha, beta})

	if got := p.candidate("conv-1", nil, AccountTypeCodex, "", ""); got != alpha {
		t.Fatalf("a no-op reload moved conversation conv-1 off alpha (got %v)", got)
	}
}
