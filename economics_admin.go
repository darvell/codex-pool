package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"
)

type economicsEdit struct {
	Kind           string  `json:"kind"` // rate, payment, history, or link
	AccountID      string  `json:"account_id"`
	EffectiveAt    string  `json:"effective_at"` // RFC3339 UTC; payment: exact cycle start
	EndAt          string  `json:"end_at"`       // history: when the account stopped being used
	AmountUSD      float64 `json:"amount_usd"`
	SubscriptionID string  `json:"subscription_id"` // history, link: logins sharing one paid seat
	Note           string  `json:"note"`
}

const (
	economicsEditRate    = "rate"
	economicsEditPayment = "payment"
	economicsEditHistory = "history"
	economicsEditLink    = "link"
	maxEconomicsIDLength = 256
)

// Explicit operator corrections; billing providers are not polled for prices.
// An operator can correct a backfilled rate, replace a cycle estimate with an
// invoice-backed amount, record the billing history of an account that left
// the pool before the ledger observed it, or link logins that share one paid
// subscription. Authentication is enforced by the router.
func (h *proxyHandler) handleEconomicsAdmin(w http.ResponseWriter, r *http.Request) {
	if h.analyticsStore == nil {
		http.Error(w, "analytics unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var edit economicsEdit
	if err := json.NewDecoder(r.Body).Decode(&edit); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	at, end, err := validateEconomicsEdit(edit, time.Now())
	if err != nil {
		http.Error(w, "invalid economics edit: "+err.Error(), http.StatusBadRequest)
		return
	}
	if edit.Kind == economicsEditHistory {
		err = h.analyticsStore.recordSubscriptionHistory(edit, at, end)
	} else if edit.Kind == economicsEditLink {
		err = h.analyticsStore.linkSubscription(edit.AccountID, edit.SubscriptionID)
	} else {
		err = h.analyticsStore.editEconomics(edit, at)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	respondJSON(w, map[string]bool{"ok": true})
}

func validateEconomicsEdit(edit economicsEdit, now time.Time) (time.Time, time.Time, error) {
	if edit.AccountID == "" || len(edit.AccountID) > maxEconomicsIDLength || len(edit.SubscriptionID) > maxEconomicsIDLength || len(edit.Note) > 512 {
		return time.Time{}, time.Time{}, errors.New("account_id, subscription_id, or note is missing or too long")
	}
	if edit.Kind == economicsEditLink {
		if edit.SubscriptionID == "" {
			return time.Time{}, time.Time{}, errors.New("link requires subscription_id")
		}
		return time.Time{}, time.Time{}, nil
	}
	if edit.Kind != economicsEditRate && edit.Kind != economicsEditPayment && edit.Kind != economicsEditHistory {
		return time.Time{}, time.Time{}, errors.New("unknown kind")
	}
	at, err := time.Parse(time.RFC3339Nano, edit.EffectiveAt)
	if err != nil || at.After(now.Add(time.Hour)) || !isFiniteNonnegative(edit.AmountUSD) {
		return time.Time{}, time.Time{}, errors.New("effective_at or amount_usd is invalid")
	}
	if edit.Kind != economicsEditHistory {
		return at.UTC(), time.Time{}, nil
	}
	// History describes a finished past interval; an open interval belongs to
	// an account the pool still observes.
	end, err := time.Parse(time.RFC3339Nano, edit.EndAt)
	if err != nil || !end.After(at) || end.After(now) || edit.SubscriptionID == "" || edit.AmountUSD <= 0 {
		return time.Time{}, time.Time{}, errors.New("history requires a past end_at after effective_at, a subscription_id, and a positive amount_usd")
	}
	return at.UTC(), end.UTC(), nil
}
func isFiniteNonnegative(x float64) bool { return x >= 0 && !math.IsInf(x, 0) && !math.IsNaN(x) }

func (s *AnalyticsStore) editEconomics(edit economicsEdit, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	atKey := at.Format(time.RFC3339Nano)
	if edit.Kind == "payment" {
		var anchorRaw string
		if err = tx.QueryRow(`SELECT MIN(start_at) FROM subscription_rates WHERE `+subscriptionGroupSQL+` = (SELECT `+subscriptionGroupSQL+` FROM subscription_rates WHERE account_id=? LIMIT 1)`, edit.AccountID).Scan(&anchorRaw); err != nil {
			return err
		}
		anchor, parseErr := time.Parse(time.RFC3339Nano, anchorRaw)
		if parseErr != nil {
			return parseErr
		}
		if at.Before(anchor) || at.Sub(anchor)%billingCycle != 0 {
			return fmt.Errorf("payment timestamp must be an exact 30-day billing cycle start")
		}
		var exists int
		nextKey := at.Add(billingCycle).Format(time.RFC3339Nano)
		err = tx.QueryRow(`SELECT 1 FROM subscription_rates WHERE `+subscriptionGroupSQL+` = (SELECT `+subscriptionGroupSQL+` FROM subscription_rates WHERE account_id=? LIMIT 1) AND start_at<? AND (end_at IS NULL OR end_at>?) LIMIT 1`, edit.AccountID, nextKey, atKey).Scan(&exists)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO subscription_payments(account_id,cycle_at,amount_usd,note) VALUES(?,?,?,?) ON CONFLICT(account_id,cycle_at) DO UPDATE SET amount_usd=excluded.amount_usd,note=excluded.note`, edit.AccountID, atKey, edit.AmountUSD, edit.Note)
	} else {
		var start string
		var end *string
		err = tx.QueryRow(`SELECT start_at,end_at FROM subscription_rates WHERE account_id=? AND start_at<=? AND (end_at IS NULL OR end_at>?) ORDER BY start_at DESC LIMIT 1`, edit.AccountID, atKey, atKey).Scan(&start, &end)
		if err != nil {
			return err
		} // Never invent an account admission date.
		if start == atKey {
			_, err = tx.Exec(`UPDATE subscription_rates SET monthly_usd=?,known=1,source='manual' WHERE account_id=? AND start_at=?`, edit.AmountUSD, edit.AccountID, start)
		} else {
			_, err = tx.Exec(`UPDATE subscription_rates SET end_at=? WHERE account_id=? AND start_at=?`, atKey, edit.AccountID, start)
			if err == nil {
				_, err = tx.Exec(`INSERT INTO subscription_rates(account_id,start_at,end_at,monthly_usd,known,source) VALUES(?,?,?,?,1,'manual')`, edit.AccountID, atKey, end, edit.AmountUSD)
			}
		}
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// recordSubscriptionHistory stores a finished billing interval. Reposting the
// same account and start corrects it. It may not overlap another interval of
// the same account, since that account would then be billed twice.
func (s *AnalyticsStore) recordSubscriptionHistory(edit economicsEdit, start, end time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	startKey, endKey := start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano)
	var overlap int
	err = tx.QueryRow(`SELECT COUNT(*) FROM subscription_rates WHERE account_id=? AND start_at<>? AND start_at<? AND (end_at IS NULL OR end_at>?)`, edit.AccountID, startKey, endKey, startKey).Scan(&overlap)
	if err != nil {
		return err
	}
	if overlap > 0 {
		return fmt.Errorf("history for %s overlaps an existing billing interval", edit.AccountID)
	}
	_, err = tx.Exec(`INSERT INTO subscription_rates(account_id,start_at,end_at,monthly_usd,known,source,subscription_id) VALUES(?,?,?,?,1,'history',?)
		ON CONFLICT(account_id,start_at) DO UPDATE SET end_at=excluded.end_at,monthly_usd=excluded.monthly_usd,known=1,source='history',subscription_id=excluded.subscription_id`,
		edit.AccountID, startKey, endKey, edit.AmountUSD, edit.SubscriptionID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// linkSubscription marks every interval of an account as billed by the named
// subscription, for providers whose credentials do not identify the seat.
func (s *AnalyticsStore) linkSubscription(accountID, subscriptionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`UPDATE subscription_rates SET subscription_id=? WHERE account_id=?`, subscriptionID, accountID)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("no billing history for %s", accountID)
	}
	return nil
}
