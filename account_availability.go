package main

import (
	"log"
	"time"
)

const (
	claudePrimaryCooldownThreshold = 1.0
	primaryHardExcludeThreshold    = 0.95
	secondaryHardExcludeThreshold  = 0.99
)

func accountPrimaryUsageLocked(a *Account) float64 {
	if a == nil {
		return 0
	}
	used := a.Usage.PrimaryUsedPercent
	if used == 0 {
		used = a.Usage.PrimaryUsed
	}
	return used
}

func accountSecondaryUsageLocked(a *Account) float64 {
	if a == nil {
		return 0
	}
	used := a.Usage.SecondaryUsedPercent
	if used == 0 {
		used = a.Usage.SecondaryUsed
	}
	return used
}

func accountCoolingDownLocked(a *Account, now time.Time) bool {
	if a == nil {
		return false
	}
	return !a.RateLimitUntil.IsZero() && a.RateLimitUntil.After(now)
}

func accountUsageExhaustedLocked(a *Account) bool {
	if a == nil {
		return false
	}
	return accountPrimaryUsageLocked(a) >= primaryHardExcludeThreshold ||
		accountSecondaryUsageLocked(a) >= secondaryHardExcludeThreshold
}

func accountAvailableForRoutingLocked(a *Account, now time.Time) bool {
	if a == nil {
		return false
	}
	if a.Dead || a.Disabled {
		return false
	}
	if accountCoolingDownLocked(a, now) {
		return false
	}
	return !accountUsageExhaustedLocked(a)
}

func syncUsageCooldown(a *Account) {
	if a == nil {
		return
	}

	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.Type != AccountTypeClaude {
		return
	}

	primaryUsed := accountPrimaryUsageLocked(a)
	resetAt := a.Usage.PrimaryResetAt
	if primaryUsed < claudePrimaryCooldownThreshold || resetAt.IsZero() || !resetAt.After(now) {
		return
	}

	if !a.RateLimitUntil.Before(resetAt) {
		return
	}

	a.RateLimitUntil = resetAt
	if a.ID != "" {
		log.Printf("cooling down claude account %s until %s (5hr usage %.1f%%)",
			a.ID,
			resetAt.Format(time.RFC3339),
			primaryUsed*100,
		)
	}
}
