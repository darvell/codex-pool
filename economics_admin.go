package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"time"
)

type economicsEdit struct {
	Kind        string  `json:"kind"` // rate or payment
	AccountID   string  `json:"account_id"`
	EffectiveAt string  `json:"effective_at"` // RFC3339 UTC; payment: exact cycle start
	AmountUSD   float64 `json:"amount_usd"`
	Note        string  `json:"note"`
}

// Explicit operator corrections; billing providers are not polled for prices.
// An operator can correct a backfilled rate, or replace a cycle estimate with
// an invoice-backed amount. Authentication is enforced by the router.
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
	at, err := time.Parse(time.RFC3339Nano, edit.EffectiveAt)
	if err != nil || edit.AccountID == "" || len(edit.AccountID) > 256 || len(edit.Note) > 512 || !isFiniteNonnegative(edit.AmountUSD) || (edit.Kind != "rate" && edit.Kind != "payment") || at.After(time.Now().Add(time.Hour)) {
		http.Error(w, "invalid economics edit", http.StatusBadRequest)
		return
	}
	if err := h.analyticsStore.editEconomics(edit, at.UTC()); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	respondJSON(w, map[string]bool{"ok": true})
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
		if err = tx.QueryRow(`SELECT start_at FROM subscription_rates WHERE account_id=? ORDER BY start_at LIMIT 1`, edit.AccountID).Scan(&anchorRaw); err != nil {
			return err
		}
		anchor, parseErr := time.Parse(time.RFC3339Nano, anchorRaw)
		if parseErr != nil {
			return parseErr
		}
		if at.Before(anchor) || at.Sub(anchor)%(30*24*time.Hour) != 0 {
			return fmt.Errorf("payment timestamp must be an exact 30-day billing cycle start")
		}
		var exists int
		err = tx.QueryRow(`SELECT 1 FROM subscription_rates WHERE account_id=? AND start_at<=? AND (end_at IS NULL OR end_at>?) LIMIT 1`, edit.AccountID, atKey, atKey).Scan(&exists)
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
