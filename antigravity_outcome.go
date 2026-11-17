package main

import (
	"net/http"
	"time"
)

type antigravityOutcomeKind uint8

const (
	antigravitySuccess antigravityOutcomeKind = iota
	antigravityQuotaFailure
	antigravityForbiddenFailure
	antigravityServerFailure
	antigravityRejected
)

type antigravityOutcome struct {
	kind   antigravityOutcomeKind
	status int
	header http.Header
	body   []byte
}

type antigravityCooldown uint8

const (
	antigravityStartCooldown antigravityCooldown = iota
	antigravityKeepCooldown
)

func readAntigravityOutcome(resp *http.Response) antigravityOutcome {
	outcome := antigravityOutcome{status: resp.StatusCode, header: resp.Header}
	switch {
	case resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices:
		return outcome
	case resp.StatusCode == http.StatusTooManyRequests:
		outcome.kind = antigravityQuotaFailure
	case resp.StatusCode == http.StatusForbidden:
		outcome.kind = antigravityForbiddenFailure
	case resp.StatusCode >= http.StatusInternalServerError:
		outcome.kind = antigravityServerFailure
	default:
		outcome.kind = antigravityRejected
	}
	outcome.body, _ = readAndCloseAntigravityError(resp)
	return outcome
}

func (h *proxyHandler) applyAntigravityOutcome(reservation *antigravityReservation, model string, outcome antigravityOutcome, cooldown antigravityCooldown) error {
	return h.pool.withCurrentAntigravityReservation(reservation, func(current *Account) error {
		switch outcome.kind {
		case antigravityQuotaFailure:
			applyAntigravityRateLimit(&h.pool.antigravityModels, current, model, outcome.header, outcome.body, time.Now())
		case antigravityForbiddenFailure:
			recordAntigravityForbidden(current, outcome.body)
		case antigravityServerFailure:
			if cooldown == antigravityKeepCooldown {
				return nil
			}
			current.mu.Lock()
			until := time.Now().Add(backoffDuration(current.BackoffLevel))
			current.BackoffLevel++
			if until.After(current.RateLimitUntil) {
				current.RateLimitUntil = until
			}
			current.mu.Unlock()
			return saveAntigravityAccount(current)
		}
		return nil
	})
}
