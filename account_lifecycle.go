package main

import (
	"fmt"
	"log"
)

// applyProxyAuthFailure updates account state for 401/403 responses that came
// from proxied user requests. Codex requests can fail for request-scoped
// reasons, so they only get a small retry penalty here instead of being treated
// like a bad account.
func applyProxyAuthFailure(a *Account, refreshFailed bool) (markedDead bool, penaltyNow float64) {
	if a == nil {
		return false, 0
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.Type == AccountTypeCodex {
		a.Penalty += 0.2
		return false, a.Penalty
	}
	if refreshFailed {
		a.Dead = true
		a.Penalty += 1.0
		return true, a.Penalty
	}

	a.Penalty += 10.0
	return false, a.Penalty
}

// disableAccountPermanently marks an account as permanently unavailable for
// routing and persists that state to disk.
func (h *proxyHandler) disableAccountPermanently(a *Account, reqID string, reason string) {
	if a == nil {
		return
	}

	a.mu.Lock()
	wasDisabled := a.Disabled
	a.Disabled = true
	a.Dead = true
	a.Penalty += 100.0
	accountID := a.ID
	a.mu.Unlock()

	prefix := ""
	if reqID != "" {
		prefix = fmt.Sprintf("[%s] ", reqID)
	}
	if wasDisabled {
		log.Printf("%saccount %s already disabled: %s", prefix, accountID, reason)
	} else {
		log.Printf("%sdisabling account %s permanently: %s", prefix, accountID, reason)
	}

	if err := saveAccount(a); err != nil {
		log.Printf("%swarning: failed to persist disabled account %s: %v", prefix, accountID, err)
	}
}
