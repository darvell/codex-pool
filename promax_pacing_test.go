package main

import (
	"testing"
	"time"
)

func TestProMaxQuotaDayBoundary(t *testing.T) {
	now := time.Date(2026, time.October, 8, 10, 0, 0, 0, time.UTC)
	max := &Account{Type: AccountTypeCodex, PlanType: "promax",
		Usage: UsageSnapshot{SecondaryUsed: 0.15, SecondaryWindowMinutes: codexWeeklyWindowMinutes,
			SecondaryResetAt: now.Add(6 * 24 * time.Hour)}}
	if !proMaxOverBudgetLocked(max, now.Add(-time.Nanosecond)) {
		t.Fatal("first day's allowance was not enforced before the boundary")
	}
	if proMaxOverBudgetLocked(max, now) {
		t.Fatal("second day's allowance was not released at the boundary")
	}
	max.Usage.SecondaryUsed = 2.0 / 7
	if !proMaxOverBudgetLocked(max, now) {
		t.Fatal("second day's exact allowance was not enforced")
	}
}

func TestProMaxDailyHandoff(t *testing.T) {
	for _, tc := range []struct {
		name      string
		used      float64
		remaining time.Duration
		wantMax   bool
	}{
		{"first day below budget", 0.14, 6*24*time.Hour + time.Hour, true},
		{"first day at budget", 1.0 / 7, 6*24*time.Hour + time.Hour, false},
		{"first day above budget", 0.15, 6*24*time.Hour + time.Hour, false},
		{"production snapshot", 0.48, 8906 * time.Minute, false},
		{"second day below budget", 0.15, 5*24*time.Hour + time.Hour, true},
		{"second day above budget", 0.29, 5*24*time.Hour + time.Hour, false},
		{"last day drain", 0.70, time.Hour, true},
		{"missing reset", 0.15, 0, false},
		{"stale reset", 0.48, -time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, route := range []string{"new", "pinned", "cyber"} {
				t.Run(route, func(t *testing.T) {
					pro := &Account{ID: "pro", Type: AccountTypeCodex, PlanType: "prolite", CyberAccess: true}
					max := &Account{ID: "max", Type: AccountTypeCodex, PlanType: "promax", CyberAccess: true,
						Usage: UsageSnapshot{SecondaryUsedPercent: tc.used, SecondaryWindowMinutes: codexWeeklyWindowMinutes}}
					if tc.remaining != 0 {
						max.Usage.SecondaryResetAt = time.Now().Add(tc.remaining)
					}
					p := newPoolState([]*Account{max, pro}, false)
					var got *Account
					switch route {
					case "pinned":
						p.pin("conversation", max.ID)
						got = p.candidate("conversation", nil, AccountTypeCodex, "pro", "")
					case "cyber":
						got = p.candidateWithCyberAccess(nil, AccountTypeCodex, "pro", "")
					default:
						got = p.candidate("", nil, AccountTypeCodex, "pro", "")
					}
					want := pro
					if tc.wantMax {
						want = max
					}
					if got != want {
						t.Fatalf("selected %p, want %s", got, want.ID)
					}
				})
			}
		})
	}
}

func TestProMaxPacingRecovery(t *testing.T) {
	max := &Account{ID: "max", Type: AccountTypeCodex, PlanType: "promax", CyberAccess: true,
		Usage: UsageSnapshot{SecondaryUsedPercent: 0.15, SecondaryWindowMinutes: codexWeeklyWindowMinutes,
			SecondaryResetAt: time.Now().Add(6*24*time.Hour + time.Hour)}}
	pro := &Account{ID: "pro", Type: AccountTypeCodex, PlanType: "pro"}
	p := newPoolState([]*Account{max, pro}, false)
	p.pin("conversation", max.ID)
	if got := p.candidate("conversation", nil, AccountTypeCodex, "pro", ""); got != pro {
		t.Fatalf("daily handoff selected %p, want ordinary Pro", got)
	}
	pro.RateLimitUntil = time.Now().Add(time.Hour)
	if got := p.candidate("conversation", nil, AccountTypeCodex, "pro", ""); got != max {
		t.Fatalf("only available account selected %p, want pinned Pro Max", got)
	}
	if got := p.candidateWithCyberAccess(nil, AccountTypeCodex, "pro", ""); got != max {
		t.Fatalf("only cyber account selected %p, want Pro Max", got)
	}
	pro.RateLimitUntil = time.Time{}
	max.Usage.SecondaryResetAt = time.Now().Add(5*24*time.Hour + time.Hour)
	if got := p.candidate("", nil, AccountTypeCodex, "pro", ""); got != max {
		t.Fatalf("next quota day selected %p, want Pro Max", got)
	}
	max.Usage.SecondaryUsedPercent = 0
	max.Usage.SecondaryResetAt = time.Now().Add(7 * 24 * time.Hour)
	if got := p.candidate("", nil, AccountTypeCodex, "pro", ""); got != max {
		t.Fatalf("weekly reset selected %p, want Pro Max", got)
	}
}

func TestProMaxPacingEligibility(t *testing.T) {
	model := "fixture-paced-model"
	max := &Account{ID: "max", Type: AccountTypeCodex, PlanType: "promax", CyberAccess: true,
		Models: map[string]DiscoveredModel{model: {ID: model}},
		Usage: UsageSnapshot{SecondaryUsedPercent: 0.48, SecondaryWindowMinutes: codexWeeklyWindowMinutes,
			SecondaryResetAt: time.Now().Add(8906 * time.Minute)}}
	pro := &Account{ID: "pro", Type: AccountTypeCodex, PlanType: "pro", CyberAccess: true}
	p := newPoolState([]*Account{max, pro}, false)
	p.pin("conversation", max.ID)
	if got := p.candidateForModel("conversation", nil, AccountTypeCodex, "pro", "", model); got != max {
		t.Fatalf("unsupported model fallback selected %p, want Pro Max", got)
	}
	if got := p.candidate("conversation", map[string]bool{max.ID: true}, AccountTypeCodex, "pro", ""); got != pro {
		t.Fatalf("retry exclusion selected %p, want ordinary Pro", got)
	}
	if got := p.candidate("conversation", map[string]bool{pro.ID: true}, AccountTypeCodex, "pro", ""); got != max {
		t.Fatalf("excluded alternative selected %p, want Pro Max fallback", got)
	}
	if got := p.candidateWithCyberAccess(map[string]bool{pro.ID: true}, AccountTypeCodex, "pro", ""); got != max {
		t.Fatalf("excluded cyber alternative selected %p, want Pro Max fallback", got)
	}
	pro.AllowedSourceIPs = []string{"192.0.2.2"}
	if got := p.candidate("conversation", nil, AccountTypeCodex, "pro", "192.0.2.1"); got != max {
		t.Fatalf("IP-restricted alternative selected %p, want Pro Max fallback", got)
	}
}

func TestProMaxPacingAcrossAccounts(t *testing.T) {
	deferred := &Account{ID: "deferred", Type: AccountTypeCodex, PlanType: "promax", CyberAccess: true,
		Usage: UsageSnapshot{SecondaryUsedPercent: 0.15, SecondaryResetAt: time.Now().Add(6*24*time.Hour + time.Hour)}}
	preferred := &Account{ID: "preferred", Type: AccountTypeCodex, PlanType: "promax", CyberAccess: true,
		Usage: UsageSnapshot{SecondaryUsedPercent: 0.10, SecondaryResetAt: time.Now().Add(6*24*time.Hour + time.Hour)}}
	pro := &Account{ID: "pro", Type: AccountTypeCodex, PlanType: "pro", CyberAccess: true}
	p := newPoolState([]*Account{deferred, preferred, pro}, false)
	p.pin("conversation", deferred.ID)
	for range 12 {
		if got := p.candidate("conversation", nil, AccountTypeCodex, "pro", ""); got != preferred {
			t.Fatalf("selected %p, want under-budget Pro Max", got)
		}
		if got := p.candidateWithCyberAccess(nil, AccountTypeCodex, "pro", ""); got != preferred {
			t.Fatalf("cyber selected %p, want under-budget Pro Max", got)
		}
	}
}
