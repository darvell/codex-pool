package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

var (
	errAccountNotFound = errors.New("account not found")
	errNoRefreshToken  = errors.New("account has no refresh token")
)

type accountRoutingState int

const (
	accountEnabled accountRoutingState = iota
	accountDisabled
)

func (p *poolState) accountByID(id string) *Account {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, account := range p.accounts {
		if account.ID == id {
			return account
		}
	}
	return nil
}

func (p *poolState) setDisabled(id string, state accountRoutingState) error {
	target := p.accountByID(id)
	if target == nil {
		return errAccountNotFound
	}
	target.mu.Lock()
	previous := target.Disabled
	target.Disabled = state == accountDisabled
	target.mu.Unlock()
	if err := saveAccount(target); err != nil {
		target.mu.Lock()
		target.Disabled = previous
		target.mu.Unlock()
		return fmt.Errorf("persist account state: %w", err)
	}
	action := "enabled"
	if state == accountDisabled {
		action = "disabled"
	}
	log.Printf("%s account %s", action, id)
	return nil
}

func (p *poolState) reviveAccount(id string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, a := range p.accounts {
		if a.ID != id {
			continue
		}
		a.mu.Lock()
		wasDead := a.Dead
		wasRateLimited := !a.RateLimitUntil.IsZero() && a.RateLimitUntil.After(time.Now())
		a.Dead = false
		a.Penalty = 0
		a.RateLimitUntil = time.Time{}
		a.mu.Unlock()
		log.Printf("resurrected account %s (was_dead=%v, was_rate_limited=%v)", id, wasDead, wasRateLimited)
		return wasDead, nil
	}
	return false, errAccountNotFound
}

func (p *poolState) clearRateLimits() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	cleared := 0
	for _, a := range p.accounts {
		a.mu.Lock()
		if !a.RateLimitUntil.IsZero() && a.RateLimitUntil.After(now) {
			a.RateLimitUntil = time.Time{}
			cleared++
		}
		a.mu.Unlock()
	}
	return cleared
}

func (h *proxyHandler) refreshManagedAccount(ctx context.Context, id string) error {
	target := h.pool.accountByID(id)
	if target == nil {
		return errAccountNotFound
	}
	target.mu.Lock()
	target.RateLimitUntil = time.Time{}
	// LastRefresh must be cleared to bypass the automatic refresh interval.
	target.LastRefresh = time.Time{}
	hasRefreshToken := target.RefreshToken != ""
	target.mu.Unlock()
	if !hasRefreshToken {
		return errNoRefreshToken
	}
	return h.refreshAccountOnce(ctx, target)
}

// Legacy cleanup retains the legacy registration set even when Passport is
// active; changing that authority would change historical cleanup semantics.
func (h *proxyHandler) purgeUnregisteredUsage() (int, int, error) {
	allowed := make(map[string]bool)
	if h.poolUsers != nil {
		for _, user := range h.poolUsers.List() {
			allowed[user.ID] = true
		}
	}
	deleted, err := h.store.purgeNonPoolUsers(allowed)
	return deleted, len(allowed), err
}
