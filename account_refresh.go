package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

func (h *proxyHandler) needsRefresh(a *Account) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.Dead || a.Disabled || a.RefreshToken == "" || a.RefreshBlocked {
		return false
	}
	if !a.refreshAttemptAt.IsZero() && time.Since(a.refreshAttemptAt) < refreshPerAccountInterval {
		return false
	}
	now := time.Now()

	if !a.LastRefresh.IsZero() && now.Sub(a.LastRefresh) < refreshPerAccountInterval {
		return false
	}

	// Antigravity refreshes with the same 3000-second headroom as the native
	// client so a long generation does not cross the token expiry boundary.
	if a.Type == AccountTypeAntigravity && !a.ExpiresAt.IsZero() && a.ExpiresAt.Before(now.Add(50*time.Minute)) {
		return true
	}

	// Codex access JWTs last about ten days. Refresh from the usage poller
	// when that window is nearly closed instead of spending the refresh token
	// on every WHAM/proxy 401.
	if a.Type == AccountTypeCodex && !a.ExpiresAt.IsZero() && a.ExpiresAt.Before(now.Add(codexRefreshHeadroom)) {
		return true
	}

	if !a.ExpiresAt.IsZero() && a.ExpiresAt.Before(now) {
		return true
	}

	if a.ExpiresAt.IsZero() && !a.LastRefresh.IsZero() && now.Sub(a.LastRefresh) > 12*time.Hour {
		return true
	}
	return false
}

const refreshMinInterval = 5 * time.Second

const refreshPerAccountInterval = 15 * time.Minute

// codexRefreshHeadroom is how soon before access-token expiry the poller
// should rotate. Codex access JWTs carry an `exp` claim of about ten days.
const codexRefreshHeadroom = 6 * time.Hour

func (h *proxyHandler) refreshAccount(ctx context.Context, a *Account) error {
	if a == nil {
		return errors.New("nil account")
	}
	if a.Type == AccountTypeAntigravity {
		generation, accounts := h.pool.generationAndAccounts()
		for _, current := range accounts {
			if current == a {
				return h.refreshAntigravityReservation(ctx, &antigravityReservation{Account: a, generation: generation})
			}
		}
		return errStaleAntigravityAccount
	}
	key := fmt.Sprintf("%s:%s", a.Type, a.ID)

	role, err := h.refreshes.run(ctx, key, func() error {
		err := h.refreshAccountOnce(ctx, a)
		if a.Type == AccountTypeCodex {
			return err
		}
		if err == nil {
			a.mu.Lock()
			a.RefreshBlocked = false
			a.mu.Unlock()
		} else if !isPermanentRefreshTokenError(err) && !isRateLimitError(err) {
			// Availability failures leave the current access token usable until
			// an authenticated request establishes otherwise.
			a.mu.Lock()
			a.RefreshBlocked = true
			a.mu.Unlock()
		}
		return err
	})
	if role == refreshJoined && err == nil && a.Type == AccountTypeCodex {
		return syncCodexAuth(a)
	}
	return err
}

func (h *proxyHandler) refreshAccountAfterAuthFailure(ctx context.Context, a *Account) error {
	if a == nil {
		return errors.New("nil account")
	}
	if a.Type == AccountTypeAntigravity {
		return h.refreshAccount(ctx, a)
	}
	if a.Type == AccountTypeCodex {
		// A 401 with a still-valid access JWT is not permission to spend the
		// refresh token. OpenAI treats reuse as "session has ended" and can
		// log out every copy of that login.
		if codexAccessFarFromExpiry(a, time.Now()) {
			return fmt.Errorf("codex access token still live, skipping refresh")
		}
		return h.refreshAccount(ctx, a)
	}
	a.mu.Lock()
	a.LastRefresh = time.Time{}
	a.RefreshBlocked = false
	a.mu.Unlock()
	return h.refreshAccount(ctx, a)
}

func (h *proxyHandler) refreshAccountOnce(ctx context.Context, a *Account) error {
	a.mu.Lock()
	sinceLastRefresh := time.Since(a.LastRefresh)
	if !a.LastRefresh.IsZero() && sinceLastRefresh < refreshPerAccountInterval {
		a.mu.Unlock()
		return fmt.Errorf("account refresh rate limited (%s), wait %v", a.ID, refreshPerAccountInterval-sinceLastRefresh)
	}
	accType := a.Type
	a.mu.Unlock()

	if err := h.waitForRefreshSlot(ctx); err != nil {
		return err
	}

	provider := h.registry.ForType(accType)
	if provider == nil {
		return fmt.Errorf("no provider for account type %s", accType)
	}
	err := provider.RefreshToken(ctx, a, h.refreshTransport)

	if accType == AccountTypeCodex {
		return err
	}
	if err == nil {
		a.mu.Lock()
		a.LastRefresh = time.Now().UTC()
		a.mu.Unlock()
		if saveErr := saveAccount(a); saveErr != nil {
			log.Printf("warning: failed to save account %s after refresh: %v", a.ID, saveErr)
		}
	}

	return err
}

func (h *proxyHandler) waitForRefreshSlot(ctx context.Context) error {
	for {
		h.refreshMu.Lock()
		wait := refreshMinInterval - time.Since(h.lastRefreshTime)
		if h.lastRefreshTime.IsZero() || wait <= 0 {
			h.lastRefreshTime = time.Now()
			h.refreshMu.Unlock()
			return nil
		}
		h.refreshMu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
