package main

import (
	"net/http"
	"strings"
)

// ErrorClass categorises an upstream HTTP response or error so the retry loop
// can decide what to do: retry on another account, back off, give up, etc.
type ErrorClass int

const (
	// ErrorClassNone means no error — the request succeeded.
	ErrorClassNone ErrorClass = iota

	// ErrorClassTransient covers temporary server-side failures (408, 500-504).
	// Action: retry immediately on the next account.
	ErrorClassTransient

	// ErrorClassRateLimit means 429 Too Many Requests.
	// Action: exponential backoff on the account, then try another.
	ErrorClassRateLimit

	// ErrorClassAuth covers 401/403 — token expired or revoked.
	// Action: refresh token, retry same account once; if still failing, rotate.
	ErrorClassAuth

	// ErrorClassPayment means 402 — subscription lapsed, workspace deactivated.
	// Action: mark account dead, rotate.
	ErrorClassPayment

	// ErrorClassNotFound means 404 — model not available on this account.
	// Action: rotate to another account (don't penalise heavily).
	ErrorClassNotFound

	// ErrorClassInvalid means 400 — the request itself is bad.
	// Action: return error to client, do NOT retry.
	ErrorClassInvalid

	// ErrorClassFatal is a catch-all for non-retryable errors we don't have
	// a specific category for. Action: return error to client.
	ErrorClassFatal
)

// classifyStatus maps an HTTP status code to an ErrorClass.
func classifyStatus(statusCode int) ErrorClass {
	switch {
	case statusCode >= 200 && statusCode < 400:
		return ErrorClassNone

	case statusCode == http.StatusBadRequest: // 400
		return ErrorClassInvalid

	case statusCode == http.StatusUnauthorized, // 401
		statusCode == http.StatusForbidden: // 403
		return ErrorClassAuth

	case statusCode == http.StatusPaymentRequired: // 402
		return ErrorClassPayment

	case statusCode == http.StatusNotFound: // 404
		return ErrorClassNotFound

	case statusCode == http.StatusRequestTimeout: // 408
		return ErrorClassTransient

	case statusCode == 524: // Cloudflare timeout — origin didn't respond in time
		return ErrorClassTransient

	case statusCode == http.StatusTooManyRequests: // 429
		return ErrorClassRateLimit

	case statusCode == 529: // Anthropic overloaded — treat as rate limit
		return ErrorClassRateLimit

	case statusCode >= 500 && statusCode <= 599:
		return ErrorClassTransient

	default:
		return ErrorClassFatal
	}
}

// isDeactivatedWorkspace checks the body for signs that the account is
// permanently dead (deactivated workspace, cancelled subscription, etc.).
func isDeactivatedWorkspace(body []byte) bool {
	s := strings.ToLower(string(body))
	return strings.Contains(s, "deactivated_workspace") ||
		strings.Contains(s, "subscription") ||
		strings.Contains(s, "billing") ||
		strings.Contains(s, "payment_required")
}

// isClaudeOrganizationDisabled checks for Anthropic responses that indicate
// the org behind a Claude OAuth token has been disabled permanently.
func isClaudeOrganizationDisabled(body []byte) bool {
	s := strings.ToLower(string(body))
	return strings.Contains(s, "organization has been disabled") ||
		strings.Contains(s, "organization is disabled") ||
		strings.Contains(s, "organization_has_been_disabled") ||
		strings.Contains(s, "organization_disabled") ||
		strings.Contains(s, "oauth authentication is currently not allowed")
}

// isCloudflareChallenge detects Cloudflare bot-mitigation responses that return
// 403 with an HTML challenge page. These are transient (not auth failures) and
// should not penalize accounts.
func isCloudflareChallenge(body []byte, headers http.Header) bool {
	if headers.Get("Cf-Mitigated") == "challenge" {
		return true
	}
	if headers.Get("Server") == "cloudflare" && strings.Contains(string(body), "<html") {
		return true
	}
	return false
}

// Retryable returns true if this class should be retried on another account.
func (c ErrorClass) Retryable() bool {
	switch c {
	case ErrorClassTransient, ErrorClassRateLimit, ErrorClassAuth,
		ErrorClassPayment, ErrorClassNotFound:
		return true
	default:
		return false
	}
}

// String returns a human-readable label.
func (c ErrorClass) String() string {
	switch c {
	case ErrorClassNone:
		return "none"
	case ErrorClassTransient:
		return "transient"
	case ErrorClassRateLimit:
		return "rate_limit"
	case ErrorClassAuth:
		return "auth"
	case ErrorClassPayment:
		return "payment"
	case ErrorClassNotFound:
		return "not_found"
	case ErrorClassInvalid:
		return "invalid"
	case ErrorClassFatal:
		return "fatal"
	default:
		return "unknown"
	}
}
