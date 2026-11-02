package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"go.etcd.io/bbolt"
)

// PoolFailureAttempt is the redacted, durable record of one provider attempt.
// It deliberately contains no response body, request body, or credentials.
type PoolFailureAttempt struct {
	EventID     string    `json:"event_id"`
	RequestID   string    `json:"request_id"`
	AccountID   string    `json:"account_id"`
	Provider    string    `json:"provider"`
	Model       string    `json:"model,omitempty"`
	Attempt     int       `json:"attempt"`
	ObservedAt  time.Time `json:"observed_at"`
	ErrorClass  string    `json:"error_class"`
	ErrorDomain string    `json:"error_domain"`
	ErrorCode   string    `json:"error_code"`
	HTTPStatus  int       `json:"http_status,omitempty"`
	Outcome     string    `json:"outcome"` // attempt_failed, terminal_failure, success
}

// FailureInsight is an aggregate row returned by the pool failure API.
type FailureInsight struct {
	AccountID   string    `json:"account_id"`
	Provider    string    `json:"provider"`
	Model       string    `json:"model,omitempty"`
	ErrorClass  string    `json:"error_class"`
	ErrorDomain string    `json:"error_domain"`
	ErrorCode   string    `json:"error_code"`
	Outcome     string    `json:"outcome"`
	Attempts    int64     `json:"attempts"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

type FailureInsightsResponse struct {
	Since  time.Time        `json:"since"`
	Until  time.Time        `json:"until"`
	Total  int64            `json:"total"`
	Groups []FailureInsight `json:"groups"`
}

func publicFailureAccountID(id string) string {
	if id == "" {
		return "unknown"
	}
	return hashAccountID(id)
}

// classifyFailure normalizes transport and HTTP failures without inspecting or
// retaining bodies. The body is intentionally absent from this API.
func classifyFailure(status int, err error) (class, domain, code string) {
	if status > 0 {
		c := classifyStatus(status)
		return c.String(), "http", strconv.Itoa(status)
	}
	if err == nil {
		return ErrorClassNone.String(), "none", "none"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ErrorClassTransient.String(), "transport", "context_" + errorCode(err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return ErrorClassTransient.String(), "transport", "timeout"
		}
		return ErrorClassTransient.String(), "transport", "network_error"
	}
	return ErrorClassFatal.String(), "transport", "error"
}

func errorCode(err error) string {
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	return "error"
}

func putFailureAttemptOutbox(tx *bbolt.Tx, event PoolFailureAttempt) error {
	b := tx.Bucket([]byte(bucketAnalyticsOutbox))
	if b == nil {
		return fmt.Errorf("analytics outbox bucket missing")
	}
	seq, err := b.NextSequence()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		Type string             `json:"type"`
		Data PoolFailureAttempt `json:"data"`
	}{"pool_failure_attempt", event})
	if err != nil {
		return err
	}
	var key [8]byte
	// The outbox sequence is assigned by Bolt; payload IDs remain stable for
	// DuckDB INSERT OR IGNORE retries.
	binary.BigEndian.PutUint64(key[:], seq)
	return b.Put(key[:], payload)
}

func (s *usageStore) recordPoolFailure(event PoolFailureAttempt) error {
	if s == nil || s.db == nil {
		return nil
	}
	if event.EventID == "" {
		event.EventID = uuid.NewString()
	}
	if event.ObservedAt.IsZero() {
		event.ObservedAt = time.Now().UTC()
	}
	return s.db.Update(func(tx *bbolt.Tx) error { return putFailureAttemptOutbox(tx, event) })
}

func (h *proxyHandler) recordFailureEvent(event PoolFailureAttempt) {
	if h == nil || h.store == nil {
		return
	}
	if err := h.store.recordPoolFailure(event); err != nil {
		log.Printf("analytics: durable failure write failed: %v", err)
		return
	}
	if h.duckAnalytics != nil {
		h.duckAnalytics.Notify()
	}
}

func failureEvent(requestID string, acc *Account, provider, model string, attempt, status int, err error, outcome string) PoolFailureAttempt {
	class, domain, code := classifyFailure(status, err)
	accountID := ""
	if acc != nil {
		accountID = acc.AccountID
		if accountID == "" {
			accountID = acc.ID
		}
	}
	return PoolFailureAttempt{EventID: uuid.NewString(), RequestID: requestID, AccountID: publicFailureAccountID(accountID), Provider: provider, Model: model, Attempt: attempt, ObservedAt: time.Now().UTC(), ErrorClass: class, ErrorDomain: domain, ErrorCode: code, HTTPStatus: status, Outcome: outcome}
}

func (a *DuckAnalytics) FailureInsights(ctx context.Context, since, until time.Time, limit int) ([]FailureInsight, int64, error) {
	if a == nil || a.db == nil {
		return nil, 0, errors.New("analytics unavailable")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := a.db.QueryContext(ctx, `SELECT account_id, provider, COALESCE(model, ''), error_class, error_domain, error_code, outcome, COUNT(*), MAX(observed_at)
		FROM pool_failure_attempts WHERE observed_at >= ? AND observed_at < ? AND outcome <> 'success'
		GROUP BY account_id, provider, model, error_class, error_domain, error_code, outcome
		ORDER BY COUNT(*) DESC, MAX(observed_at) DESC LIMIT ?`, since.UTC(), until.UTC(), limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]FailureInsight, 0)
	var total int64
	for rows.Next() {
		var row FailureInsight
		if err := rows.Scan(&row.AccountID, &row.Provider, &row.Model, &row.ErrorClass, &row.ErrorDomain, &row.ErrorCode, &row.Outcome, &row.Attempts, &row.LastSeenAt); err != nil {
			return nil, 0, err
		}
		out = append(out, row)
		total += row.Attempts
	}
	return out, total, rows.Err()
}

func (h *proxyHandler) handlePoolFailureInsights(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if h.duckAnalytics == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "analytics unavailable")
		return
	}
	hours := 24 * 7
	if v, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && v > 0 && v <= 24*366 {
		hours = v
	}
	limit := 100
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 500 {
		limit = v
	}
	until := time.Now().UTC()
	since := until.Add(-time.Duration(hours) * time.Hour)
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	groups, total, err := h.duckAnalytics.FailureInsights(ctx, since, until, limit)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "failure insights query failed")
		return
	}
	respondJSON(w, FailureInsightsResponse{Since: since, Until: until, Total: total, Groups: groups})
}
