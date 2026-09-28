package main

import (
	"database/sql"
	"time"
)

// Subscription history is deliberately sparse: one row per account and rate
// change, not one row per day. A payment replaces the estimate for its cycle.
// Neither an OAuth plan claim nor a published list price is proof of payment.
type subscriptionRate struct {
	id         string
	start, end time.Time
	monthly    float64
	known      bool
}
type economicsSummary struct {
	Since                  string  `json:"since"`
	APIValue               float64 `json:"api_value"`
	SubscriptionSpend      float64 `json:"subscription_spend"`
	RecentAPIValue         float64 `json:"recent_api_value"`
	RecentSubscriptionCost float64 `json:"recent_subscription_cost"`
	CurrentMonthly         float64 `json:"current_monthly"`
	EstimatedCycles        int     `json:"estimated_cycles"`
	RecordedCycles         int     `json:"recorded_cycles"`
	UnknownAccounts        int     `json:"unknown_accounts"`
	UncoveredValue         float64 `json:"uncovered_value"`
}

func (s *AnalyticsStore) syncSubscriptionRates(accounts []*Account, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	seen := make(map[string]bool)
	firstUsage, err := s.getAllTimeAccountCostStats()
	if err != nil {
		return err
	}
	for _, a := range accounts {
		a.mu.Lock()
		id, typ, plan, added := a.ID, a.Type, a.PlanType, a.AddedAt
		a.mu.Unlock()
		seen[id] = true
		amount, _ := getSubscriptionCost(typ, accountPlanForSubscription(plan))
		// A zero lookup may mean a free plan, an unknown paid tier, or an
		// API-key account with separate billing. None proves zero spend.
		known := amount > 0
		var start, source string
		var oldAmount float64
		var oldKnown bool
		err := tx.QueryRow(`SELECT start_at, monthly_usd, known, source FROM subscription_rates WHERE account_id = ? AND end_at IS NULL ORDER BY start_at DESC LIMIT 1`, id).Scan(&start, &oldAmount, &oldKnown, &source)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		flag := known
		if err == sql.ErrNoRows {
			if added.IsZero() {
				added = firstUsage[id].FirstSeen
				if added.IsZero() {
					added = now
				}
			}
			if added.After(now) {
				added = now
			}
			_, err = tx.Exec(`INSERT INTO subscription_rates(account_id, start_at, monthly_usd, known, source) VALUES(?, ?, ?, ?, 'plan-estimate')`, id, added.UTC().Format(time.RFC3339Nano), amount, flag)
		} else if source != "manual" && (oldAmount != amount || oldKnown != flag) {
			// Keep the account's original billing anchor: a changed rate applies to
			// the next cycle, not retroactively to already accrued cycles.
			_, err = tx.Exec(`UPDATE subscription_rates SET end_at = ? WHERE account_id = ? AND end_at IS NULL`, now.UTC().Format(time.RFC3339Nano), id)
			if err == nil {
				_, err = tx.Exec(`INSERT INTO subscription_rates(account_id, start_at, monthly_usd, known, source) VALUES(?, ?, ?, ?, 'plan-estimate')`, id, now.UTC().Format(time.RFC3339Nano), amount, flag)
			}
		}
		if err != nil {
			return err
		}
	}
	// A retired account's ledger survives, but it must not keep accruing bills.
	rows, err := tx.Query(`SELECT account_id FROM subscription_rates WHERE end_at IS NULL`)
	if err != nil {
		return err
	}
	var retired []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		if !seen[id] {
			retired = append(retired, id)
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range retired {
		if _, err = tx.Exec(`UPDATE subscription_rates SET end_at = ? WHERE account_id = ? AND end_at IS NULL`, now.UTC().Format(time.RFC3339Nano), id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *AnalyticsStore) subscriptionRates() (map[string][]subscriptionRate, error) {
	rows, err := s.db.Query(`SELECT account_id, start_at, end_at, monthly_usd, known FROM subscription_rates ORDER BY account_id, start_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string][]subscriptionRate)
	for rows.Next() {
		var id, start string
		var end sql.NullString
		var amount float64
		var known bool
		if err := rows.Scan(&id, &start, &end, &amount, &known); err != nil {
			return nil, err
		}
		t, err := time.Parse(time.RFC3339Nano, start)
		if err != nil {
			return nil, err
		}
		r := subscriptionRate{id: id, start: t, monthly: amount, known: known}
		if end.Valid {
			r.end, err = time.Parse(time.RFC3339Nano, end.String)
			if err != nil {
				return nil, err
			}
		}
		result[id] = append(result[id], r)
	}
	return result, rows.Err()
}

func rateAt(rates []subscriptionRate, at time.Time) (subscriptionRate, bool) {
	for i := len(rates) - 1; i >= 0; i-- {
		r := rates[i]
		if !at.Before(r.start) && (r.end.IsZero() || at.Before(r.end)) {
			return r, true
		}
	}
	return subscriptionRate{}, false
}

// A 30-day cycle follows the original account admission date. Rates change
// prospectively at the following billing boundary; payment overrides are keyed
// by account ID and cycle start and are never synthesized by OAuth claims.
func (s *AnalyticsStore) economics(now time.Time) ([]SignalEconomicsPoint, economicsSummary, error) {
	var summary economicsSummary
	rates, err := s.subscriptionRates()
	if err != nil {
		return nil, summary, err
	}
	costs, err := s.getAllAccountDailyCosts()
	if err != nil {
		return nil, summary, err
	}
	payments := map[string]float64{}
	rows, err := s.db.Query(`SELECT account_id, cycle_at, amount_usd FROM subscription_payments`)
	if err != nil {
		return nil, summary, err
	}
	for rows.Next() {
		var id, at string
		var amount float64
		if err = rows.Scan(&id, &at, &amount); err != nil {
			break
		}
		payments[id+"|"+at] = amount
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, summary, err
	}
	now = now.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	recentStart := now.Add(-30 * 24 * time.Hour)
	value := map[string]float64{}
	providers := map[string]map[string]float64{}
	var first time.Time
	for _, row := range costs {
		day, parseErr := time.Parse("2006-01-02", row.Date)
		if parseErr != nil {
			continue
		}
		if first.IsZero() || day.Before(first) {
			first = day
		}
		value[row.Date] += row.CostUSD
		if providers[row.Date] == nil {
			providers[row.Date] = map[string]float64{}
		}
		providers[row.Date][row.AccountType] += row.CostUSD
		if !day.Before(recentStart) {
			summary.RecentAPIValue += row.CostUSD
		}
		if history := rates[row.AccountID]; len(history) == 0 || day.Before(time.Date(history[0].start.Year(), history[0].start.Month(), history[0].start.Day(), 0, 0, 0, 0, time.UTC)) {
			summary.UncoveredValue += row.CostUSD
		}
	}
	spend := map[string]float64{}
	recentSpend := 0.0
	for id, history := range rates {
		anchor := history[0].start
		if first.IsZero() || anchor.Before(first) {
			first = anchor
		}
		for cycle := anchor; !cycle.After(now); cycle = cycle.Add(30 * 24 * time.Hour) {
			if !history[len(history)-1].end.IsZero() && !cycle.Before(history[len(history)-1].end) {
				break
			}
			// Start on a missing-rate cycle still counts as unknown; do not assert $0.
			r, exists := rateAt(history, cycle)
			key := cycle.UTC().Format(time.RFC3339Nano)
			charge, recorded := payments[id+"|"+key]
			if !recorded && (!exists || !r.known) {
				summary.UnknownAccounts++
				continue
			}
			if recorded {
				summary.RecordedCycles++
			} else {
				charge = r.monthly
				summary.EstimatedCycles++
			}
			spend[cycle.Format("2006-01-02")] += charge
			end := cycle.Add(30 * 24 * time.Hour)
			if end.After(now) {
				end = now
			}
			overlapStart := cycle
			if overlapStart.Before(recentStart) {
				overlapStart = recentStart
			}
			if end.After(overlapStart) {
				recentSpend += charge * end.Sub(overlapStart).Hours() / (30 * 24)
			}
		}
		if history[len(history)-1].end.IsZero() && history[len(history)-1].known {
			summary.CurrentMonthly += history[len(history)-1].monthly
		}
	}
	summary.RecentSubscriptionCost = recentSpend
	if first.IsZero() {
		return []SignalEconomicsPoint{}, summary, nil
	}
	first = time.Date(first.Year(), first.Month(), first.Day(), 0, 0, 0, 0, time.UTC)
	summary.Since = first.Format("2006-01-02")
	points := make([]SignalEconomicsPoint, 0)
	for day := first; !day.After(today); day = day.AddDate(0, 0, 1) {
		key := day.Format("2006-01-02")
		summary.APIValue += value[key]
		summary.SubscriptionSpend += spend[key]
		p := providers[key]
		if p == nil {
			p = map[string]float64{}
		}
		points = append(points, SignalEconomicsPoint{Date: key, DailyAPIValue: value[key], CumulativeAPIValue: summary.APIValue, CumulativeSubscriptionSpend: summary.SubscriptionSpend, ProviderAPIValue: p})
	}
	return points, summary, nil
}
