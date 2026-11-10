package main

// Quota-waste insights deliberately consume provider-owned UsageSnapshot values.
// They never make a provider request and are independent from quota intelligence.

import (
	"database/sql"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	quotaWasteObservationInterval = 5 * time.Minute
	quotaWasteRetentionDays       = 180
	quotaWasteSchemaVersion       = 1
	quotaWasteReserve             = 0.20
)

type quotaWasteObservation struct {
	ObservedAt       string
	SourceObservedAt string
	AccountID        string
	SeatID           string
	Provider         string
	Plan             string
	WindowKey        string
	WindowKind       string
	Used             *float64
	ResetAt          *string
	Source           string
	Health           string
	Fresh            bool
}

type quotaWasteWindow struct {
	Key            string   `json:"key"`
	Kind           string   `json:"kind"`
	UsedFraction   *float64 `json:"used_fraction,omitempty"`
	Remaining      *float64 `json:"remaining_fraction,omitempty"`
	ResetAt        *string  `json:"reset_at,omitempty"`
	LastObservedAt string   `json:"last_observed_at"`
	Status         string   `json:"status"`
	// UnusedPercent is only populated for a confirmed, closed window. The
	// current window's remaining quota is deliberately not called waste.
	UnusedPercent           *float64 `json:"unused_percent,omitempty"`
	ClosedWindowCount       int      `json:"closed_window_count,omitempty"`
	LastClosedAt            *string  `json:"last_closed_at,omitempty"`
	LastClosedUnusedPercent *float64 `json:"last_closed_unused_percent,omitempty"`
	Confidence              string   `json:"confidence"`
	Source                  string   `json:"source"`
}

type quotaWasteAccount struct {
	ID       string             `json:"id"`
	SeatID   string             `json:"seat_id,omitempty"`
	Provider string             `json:"provider"`
	Plan     string             `json:"plan,omitempty"`
	Status   string             `json:"status"`
	Health   string             `json:"health"`
	Windows  []quotaWasteWindow `json:"windows"`
}

type quotaWasteCandidate struct {
	SeatID             string   `json:"seat_id"`
	Provider           string   `json:"provider"`
	Plan               string   `json:"plan"`
	RemovesAccounts    []string `json:"removes_accounts"`
	Eligibility        string   `json:"eligibility"`
	Rationale          []string `json:"rationale"`
	Confidence         string   `json:"confidence"`
	ProjectedPeakLoad  *float64 `json:"projected_peak_load,omitempty"`
	MonthlySavingKnown bool     `json:"monthly_saving_known"`
	Independent        bool     `json:"independent_scenario"`
	ReviewBurden       float64  `json:"review_burden"`
}

type quotaWasteResponse struct {
	SchemaVersion int                   `json:"schema_version"`
	GeneratedAt   time.Time             `json:"generated_at"`
	Days          int                   `json:"days"`
	Accounts      []quotaWasteAccount   `json:"accounts"`
	Candidates    []quotaWasteCandidate `json:"candidates"`
	Coverage      map[string]any        `json:"coverage"`
	Gaps          []string              `json:"gaps"`
	Confidence    string                `json:"confidence"`
	Methodology   string                `json:"methodology"`
	Warning       string                `json:"warning"`
}

func createQuotaWasteTables(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS quota_waste_observations (
		observed_at TEXT NOT NULL, account_id TEXT NOT NULL, seat_id TEXT NOT NULL,
		provider TEXT NOT NULL, plan TEXT NOT NULL, window_key TEXT NOT NULL,
		window_kind TEXT NOT NULL, used_fraction REAL, reset_at TEXT, source TEXT NOT NULL,
		source_observed_at TEXT, health TEXT NOT NULL, fresh INTEGER NOT NULL, schema_version INTEGER NOT NULL,
		PRIMARY KEY (observed_at, account_id, window_key)
	);
	CREATE INDEX IF NOT EXISTS idx_quota_waste_observed ON quota_waste_observations(observed_at);
	CREATE INDEX IF NOT EXISTS idx_quota_waste_account ON quota_waste_observations(account_id, observed_at);`)
	if err != nil {
		return err
	}
	return ensureAnalyticsColumn(db, "quota_waste_observations", "source_observed_at", "TEXT")
}

func (s *AnalyticsStore) recordQuotaWasteObservations(rows []quotaWasteObservation) error {
	if s == nil || s.db == nil || len(rows) == 0 {
		return fmt.Errorf("analytics unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, row := range rows {
		_, err = tx.Exec(`INSERT OR IGNORE INTO quota_waste_observations
		(observed_at,account_id,seat_id,provider,plan,window_key,window_kind,used_fraction,reset_at,source,source_observed_at,health,fresh,schema_version)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, row.ObservedAt, row.AccountID, row.SeatID, row.Provider, row.Plan,
			row.WindowKey, row.WindowKind, row.Used, row.ResetAt, row.Source, row.SourceObservedAt, row.Health, boolInt(row.Fresh), quotaWasteSchemaVersion)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if _, err = tx.Exec(`DELETE FROM quota_waste_observations WHERE observed_at < datetime('now', ?)`, fmt.Sprintf("-%d days", quotaWasteRetentionDays)); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// quotaWasteObservationRows includes idle, disabled and dead accounts. A missing
// usage value remains NULL; zero is retained only when the provider explicitly
// supplied that field.
func quotaWasteObservationRows(accounts []*Account, now time.Time) []quotaWasteObservation {
	return quotaWasteObservationRowsWithSeats(accounts, now, nil)
}

func quotaWasteObservationRowsWithSeats(accounts []*Account, now time.Time, linkedSeats map[string]string) []quotaWasteObservation {
	at := now.UTC().Format(time.RFC3339Nano)
	out := make([]quotaWasteObservation, 0, len(accounts)*2)
	for _, a := range accounts {
		if a == nil {
			continue
		}
		a.mu.Lock()
		id, typ, plan := a.ID, a.Type, strings.TrimSpace(a.PlanType)
		seat := subscriptionIdentityLocked(a)
		if linkedSeats != nil {
			if linked, ok := linkedSeats[id]; ok && linked != "" {
				seat = linked
			}
		}
		u := a.Usage
		health := "healthy"
		if a.Disabled {
			health = "disabled"
		} else if a.Dead {
			health = "dead"
		} else if !a.RateLimitUntil.IsZero() && a.RateLimitUntil.After(now) {
			health = "cooldown"
		} else if a.NeedsVerification || a.HealthError != "" {
			health = "degraded"
		}
		if seat == "" {
			seat = "account:" + id
		}
		a.mu.Unlock()
		id = hashAccountID(id)
		seat = hashAccountID(seat)
		add := func(key, kind string, set bool, used float64, reset time.Time) {
			var p *float64
			if set {
				if used < 0 {
					used = 0
				}
				if used > 1 {
					used = 1
				}
				p = &used
			}
			var rp *string
			if !reset.IsZero() {
				v := reset.UTC().Format(time.RFC3339Nano)
				rp = &v
			}
			fresh := !u.RetrievedAt.IsZero() && now.Sub(u.RetrievedAt) <= 2*quotaWasteObservationInterval
			sourceAt := ""
			if !u.RetrievedAt.IsZero() {
				sourceAt = u.RetrievedAt.UTC().Format(time.RFC3339Nano)
			}
			out = append(out, quotaWasteObservation{ObservedAt: at, SourceObservedAt: sourceAt, AccountID: id, SeatID: seat, Provider: string(typ), Plan: plan, WindowKey: key, WindowKind: kind, Used: p, ResetAt: rp, Source: u.Source, Health: health, Fresh: fresh})
		}
		if u.primarySet {
			add("primary", "scheduled", true, u.PrimaryUsed, u.PrimaryResetAt)
		}
		if u.secondarySet {
			add("secondary", "scheduled", true, u.SecondaryUsed, u.SecondaryResetAt)
		}
		if !u.primarySet && !u.secondarySet {
			add("opaque", "opaque", false, 0, time.Time{})
		}
	}
	return out
}

func (h *proxyHandler) recordQuotaWasteSnapshot(now time.Time) {
	if h == nil || h.analyticsStore == nil || h.pool == nil {
		return
	}
	accounts := h.pool.allAccounts()
	linkedSeats, err := h.analyticsStore.quotaWasteSubscriptionSeats(accounts)
	if err != nil {
		return
	}
	if err := h.analyticsStore.recordQuotaWasteObservations(quotaWasteObservationRowsWithSeats(accounts, now, linkedSeats)); err != nil {
		return
	}
}

func (h *proxyHandler) startQuotaWasteObserver() {
	if h == nil || h.analyticsStore == nil {
		return
	}
	go func() {
		h.recordQuotaWasteSnapshot(time.Now())
		t := time.NewTicker(quotaWasteObservationInterval)
		defer t.Stop()
		for now := range t.C {
			h.recordQuotaWasteSnapshot(now)
		}
	}()
}

func (s *AnalyticsStore) quotaWasteSeatHashes() (map[string]string, error) {
	aliases := map[string]string{}
	if s == nil || s.db == nil {
		return aliases, fmt.Errorf("analytics unavailable")
	}
	rows, err := s.db.Query(`SELECT account_id, ` + subscriptionGroupSQL + ` FROM subscription_rates WHERE end_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var accountID, seatID string
		if err := rows.Scan(&accountID, &seatID); err != nil {
			return nil, err
		}
		aliases[hashAccountID(accountID)] = hashAccountID(seatID)
	}
	return aliases, rows.Err()
}

func (s *AnalyticsStore) quotaWasteRows(days int) ([]quotaWasteObservation, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("analytics unavailable")
	}
	if days < 1 {
		days = 1
	}
	if days > 90 {
		days = 90
	}
	const maxRows = 100000
	rows, err := s.db.Query(`SELECT observed_at,account_id,seat_id,provider,plan,window_key,window_kind,used_fraction,reset_at,source,source_observed_at,health,fresh FROM quota_waste_observations WHERE observed_at >= datetime('now', ?) ORDER BY observed_at, account_id, window_key LIMIT ?`, fmt.Sprintf("-%d days", days), maxRows)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []quotaWasteObservation{}
	for rows.Next() {
		var r quotaWasteObservation
		var used sql.NullFloat64
		var reset sql.NullString
		var fresh int
		if err := rows.Scan(&r.ObservedAt, &r.AccountID, &r.SeatID, &r.Provider, &r.Plan, &r.WindowKey, &r.WindowKind, &used, &reset, &r.Source, &r.SourceObservedAt, &r.Health, &fresh); err != nil {
			return nil, err
		}
		if used.Valid {
			v := used.Float64
			r.Used = &v
		}
		if reset.Valid {
			v := reset.String
			r.ResetAt = &v
		}
		r.Fresh = fresh != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func quotaWasteDisplayRows(rows []quotaWasteObservation) []quotaWasteAccount {
	// Raw observations remain durable, but the API returns one latest state per
	// account/window. Closed-window evidence is a bounded summary on that state.
	type windowHistory struct {
		latest           quotaWasteObservation
		prior            *quotaWasteObservation
		closed           int
		lastClosedAt     *string
		lastClosedUnused *float64
	}
	accounts := map[string]*quotaWasteAccount{}
	history := map[string]*windowHistory{}
	for _, r := range rows {
		a := accounts[r.AccountID]
		if a == nil {
			a = &quotaWasteAccount{ID: r.AccountID, SeatID: r.SeatID, Provider: r.Provider, Plan: r.Plan, Health: r.Health, Status: "gathering"}
			accounts[r.AccountID] = a
		}
		if r.Health != "healthy" {
			a.Health = r.Health
		}
		// Rows are ordered oldest-to-newest, so this keeps the account status
		// representative of its latest observed state rather than any old gap.
		if r.Used == nil {
			a.Status = "gathering"
		} else if !r.Fresh {
			a.Status = "stale"
		} else if r.WindowKind == "scheduled" {
			a.Status = "open"
		} else {
			a.Status = "observed"
		}
		windowID := r.AccountID + "\x00" + r.WindowKey
		h := history[windowID]
		if h == nil {
			h = &windowHistory{}
			history[windowID] = h
		}
		if h.latest.ObservedAt != "" {
			prior := h.latest
			h.prior = &prior
		}
		if h.prior != nil && r.WindowKind == "scheduled" && h.prior.ResetAt != nil && r.ResetAt != nil && h.prior.Used != nil && r.Used != nil &&
			h.prior.Fresh && r.Fresh && *h.prior.ResetAt != *r.ResetAt && *h.prior.ResetAt <= r.ObservedAt && *r.ResetAt > r.ObservedAt &&
			h.prior.SourceObservedAt != "" && r.SourceObservedAt != "" {
			priorSource, priorErr := time.Parse(time.RFC3339Nano, h.prior.SourceObservedAt)
			currentSource, currentErr := time.Parse(time.RFC3339Nano, r.SourceObservedAt)
			if priorErr == nil && currentErr == nil && currentSource.After(priorSource) && currentSource.Sub(priorSource) <= 3*quotaWasteObservationInterval {
				bound := (1 - *h.prior.Used) * 100
				closedAt := r.ObservedAt
				h.closed++
				h.lastClosedAt = &closedAt
				h.lastClosedUnused = &bound
			}
		}
		h.latest = r
	}
	for windowID, h := range history {
		parts := strings.SplitN(windowID, "\x00", 2)
		a := accounts[parts[0]]
		if a == nil {
			continue
		}
		r := h.latest
		w := quotaWasteWindow{Key: r.WindowKey, Kind: r.WindowKind, LastObservedAt: r.ObservedAt, Status: "gathering", Confidence: "low", Source: r.Source, ClosedWindowCount: h.closed, LastClosedAt: h.lastClosedAt, LastClosedUnusedPercent: h.lastClosedUnused}
		if r.Used != nil {
			v := *r.Used
			w.UsedFraction = &v
			rem := 1 - v
			w.Remaining = &rem
		}
		if r.ResetAt != nil {
			v := *r.ResetAt
			w.ResetAt = &v
		}
		if r.Used == nil {
			w.Status = "gathering"
		} else if !r.Fresh {
			w.Status = "stale"
		} else if r.WindowKind != "scheduled" {
			w.Status = "gathering"
		} else {
			w.Status = "open"
			w.Confidence = "medium"
		}
		// A reset starts a new open window. Never label its current remaining
		// quota as unused; only the bounded closed summary carries waste.
		a.Windows = append(a.Windows, w)
	}
	out := make([]quotaWasteAccount, 0, len(accounts))
	for _, a := range accounts {
		sort.Slice(a.Windows, func(i, j int) bool { return a.Windows[i].Key < a.Windows[j].Key })
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func quotaWasteCandidates(rows []quotaWasteObservation, accounts []quotaWasteAccount) []quotaWasteCandidate {
	// First collapse repeated logins into paid seats. Redistribution, however, is
	// evaluated across all compatible seats (not within one seat), so two or more
	// accounts at 60% can only be suggested when their combined replay fits.
	type seat struct {
		key, provider, plan string
		ids                 []string
		load                float64
		samples             int
		reviewSamples       int
		unhealthy           bool
	}
	seats := map[string]*seat{}
	for _, a := range accounts {
		key := a.SeatID + "\x00" + a.Provider + "\x00" + a.Plan
		s := seats[key]
		if s == nil {
			s = &seat{key: key, provider: a.Provider, plan: a.Plan}
			seats[key] = s
		}
		s.ids = append(s.ids, a.ID)
		if a.Health != "healthy" {
			s.unhealthy = true
		}
	}
	for _, r := range rows {
		key := r.SeatID + "\x00" + r.Provider + "\x00" + r.Plan
		if s := seats[key]; s != nil {
			if r.Health != "" && r.Health != "healthy" {
				s.unhealthy = true
				s.reviewSamples++
			}
			if r.Used != nil {
				// This is the maximum observed sample, not a replay or a
				// provider peak guarantee. Empty timestamps are retained for
				// deterministic unit fixtures; persisted rows must be fresh.
				if s.samples == 0 || *r.Used > s.load {
					s.load = *r.Used
				}
				s.samples++
			}
		}
	}
	for _, s := range seats {
		if s.unhealthy && s.samples > 0 && s.reviewSamples == 0 {
			s.reviewSamples = s.samples
		}
	}
	// Compatibility pool is provider + plan. Each output remains an independent
	// one-seat scenario and therefore is never combinable with another output.
	pools := map[string][]*seat{}
	for _, s := range seats {
		pools[s.provider+"\x00"+s.plan] = append(pools[s.provider+"\x00"+s.plan], s)
	}
	out := []quotaWasteCandidate{}
	for _, pool := range pools {
		if len(pool) < 2 {
			continue
		}
		total, known := 0.0, true
		for _, s := range pool {
			total += s.load
			known = known && s.samples > 0
			// Database observations always carry freshness. A non-fresh row
			// is startup/stale evidence, never a safety pass.
			for _, r := range rows {
				if r.SeatID == s.key[:strings.IndexByte(s.key, '\x00')] && r.Provider == s.provider && r.Plan == s.plan && r.Used != nil && !r.Fresh && r.ObservedAt != "" {
					known = false
				}
			}
		}
		for _, removed := range pool {
			reviewBurden := 0.0
			if removed.samples > 0 {
				reviewBurden = float64(removed.reviewSamples) / float64(removed.samples)
			}
			c := quotaWasteCandidate{SeatID: hashAccountID(removed.key), Provider: removed.provider, Plan: removed.plan, RemovesAccounts: append([]string(nil), removed.ids...), Independent: true, Eligibility: "insufficient_evidence", Confidence: "low", ReviewBurden: reviewBurden, Rationale: []string{"each scenario removes one paid seat, not one login; scenarios are not additive", "modelled from the maximum observed quota sample with a 20% reserve; this is not a peak-tested replay"}}
			if !known {
				c.Rationale = append(c.Rationale, "complete quota history is unavailable")
				out = append(out, c)
				continue
			}
			remaining := len(pool) - 1
			// Removing a seat does not remove the demand it was serving. The
			// candidate's observed load must be redistributed across the
			// remaining seats, so total demand stays constant.
			peak := total / float64(remaining)
			c.ProjectedPeakLoad = &peak
			if peak > 1-quotaWasteReserve {
				c.Rationale = append(c.Rationale, "observed load would exceed the 20% reserve after redistribution")
				out = append(out, c)
				continue
			}
			c.Eligibility = "modelled_safe"
			c.Confidence = "medium"
			if reviewBurden > 0 {
				c.Rationale = append(c.Rationale, fmt.Sprintf("%d/%d observed samples require review; this health evidence is not a safety pass", removed.reviewSamples, removed.samples))
			} else {
				c.Rationale = append(c.Rationale, "observed samples support a conservative single-seat redistribution within the 20% reserve")
			}
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Eligibility == "modelled_safe" && out[j].Eligibility == "modelled_safe" && out[i].ReviewBurden != out[j].ReviewBurden {
			return out[i].ReviewBurden > out[j].ReviewBurden
		}
		return out[i].SeatID < out[j].SeatID
	})
	return out
}

func (h *proxyHandler) handleQuotaWaste(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.analyticsStore == nil || h.analyticsStore.db == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "quota-waste analytics unavailable")
		return
	}
	days := 30
	if raw := strings.TrimSpace(r.URL.Query().Get("days")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 90 {
			respondJSONError(w, http.StatusBadRequest, "days must be between 1 and 90")
			return
		}
		days = n
	}
	rows, err := h.analyticsStore.quotaWasteRows(days)
	if err != nil {
		respondJSONError(w, http.StatusServiceUnavailable, "quota-waste analytics unavailable")
		return
	}
	seatHashes, err := h.analyticsStore.quotaWasteSeatHashes()
	if err != nil {
		respondJSONError(w, http.StatusServiceUnavailable, "quota-waste analytics unavailable")
		return
	}
	for i := range rows {
		if seat := seatHashes[rows[i].AccountID]; seat != "" {
			rows[i].SeatID = seat
		}
	}
	accounts := quotaWasteDisplayRows(rows)
	candidates := quotaWasteCandidates(rows, accounts)
	fresh := 0
	for _, r := range rows {
		if r.Fresh {
			fresh++
		}
	}
	coverage := map[string]any{"observations": len(rows), "fresh_observations": fresh, "accounts": len(accounts), "days": days}
	gaps := []string{}
	if len(rows) == 0 {
		gaps = append(gaps, "history is still gathering; no observations are available")
	}
	if fresh < len(rows) {
		gaps = append(gaps, "some provider snapshots are stale")
	}
	if len(rows) < 2 {
		gaps = append(gaps, "startup/restart or partial windows are unknown")
	}
	respondJSON(w, quotaWasteResponse{SchemaVersion: quotaWasteSchemaVersion, GeneratedAt: time.Now().UTC(), Days: days, Accounts: accounts, Candidates: candidates, Coverage: coverage, Gaps: gaps, Confidence: func() string {
		if len(gaps) == 0 {
			return "medium"
		}
		return "low"
	}(), Methodology: "Independent five-minute observations of provider-owned snapshots. Expired unused quota is bounded only at a confirmed scheduled reset; sliding, opaque and unmetered limits are not converted to tokens or dollars.", Warning: "Candidate scenarios are independent and not additive. Removing an account does not cure load-induced risk; review and health evidence remain operator decisions."})
}
