package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.etcd.io/bbolt"
	_ "modernc.org/sqlite"
)

// AnalyticsStore persists request cost data in SQLite for analytics queries.
type AnalyticsStore struct {
	db *sql.DB
	mu sync.Mutex // serialize writes
}

// DailyCostEntry represents one day of cost data for a provider.
type DailyCostEntry struct {
	Date         string  `json:"date"`
	AccountType  string  `json:"account_type"`
	CostUSD      float64 `json:"cost_usd"`
	RequestCount int64   `json:"request_count"`
}

// ModelDailyUsageEntry is the public, aggregated model mix used by the signal
// room. It intentionally contains no user or account identifiers.
type ModelDailyUsageEntry struct {
	Date            string  `json:"date"`
	AccountType     string  `json:"account_type"`
	Model           string  `json:"model"`
	InputTokens     int64   `json:"input_tokens"`
	CachedTokens    int64   `json:"cached_tokens"`
	OutputTokens    int64   `json:"output_tokens"`
	ReasoningTokens int64   `json:"reasoning_tokens"`
	RequestCount    int64   `json:"request_count"`
	CostUSD         float64 `json:"cost_usd"`
}

// AccountDailyCostEntry keeps account attribution so cumulative value charts
// can compare the current pool's API-equivalent value with matching spend.
type AccountDailyCostEntry struct {
	Date         string  `json:"date"`
	AccountID    string  `json:"account_id"`
	AccountType  string  `json:"account_type"`
	CostUSD      float64 `json:"cost_usd"`
	RequestCount int64   `json:"request_count"`
}

// AccountCostSummary holds cost totals for a single account.
type AccountCostSummary struct {
	AccountID   string  `json:"account_id"`
	AccountType string  `json:"account_type"`
	CostUSD     float64 `json:"cost_usd"`
}

// AccountCostStats pairs all-time API-equivalent cost with the beginning of
// that measurement period so subscription spend uses the same time horizon.
type AccountCostStats struct {
	CostUSD   float64
	FirstSeen time.Time
}

// ProviderCostSummary holds aggregated cost data for a provider type.
type ProviderCostSummary struct {
	APICost                 float64 `json:"api_cost"`
	SubscriptionCost        float64 `json:"subscription_cost"`
	MonthlySubscriptionCost float64 `json:"monthly_subscription_cost"`
	AccountCount            int     `json:"account_count"`
	ROI                     float64 `json:"roi"`
}

func newAnalyticsStore(dbPath string) (*AnalyticsStore, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create analytics dir: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open analytics db: %w", err)
	}

	// Set connection pool to 1 for writes (SQLite limitation)
	db.SetMaxOpenConns(4)

	if err := createAnalyticsTables(db); err != nil {
		db.Close()
		return nil, err
	}

	return &AnalyticsStore{db: db}, nil
}

func createAnalyticsTables(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS request_costs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		account_id TEXT NOT NULL,
		account_type TEXT NOT NULL,
		user_id TEXT,
		model TEXT,
		input_tokens INTEGER DEFAULT 0,
		cached_tokens INTEGER DEFAULT 0,
		output_tokens INTEGER DEFAULT 0,
		reasoning_tokens INTEGER DEFAULT 0,
		cost_usd REAL DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_request_costs_account_ts ON request_costs(account_id, timestamp);
	CREATE INDEX IF NOT EXISTS idx_request_costs_type_ts ON request_costs(account_type, timestamp);
	CREATE INDEX IF NOT EXISTS idx_request_costs_ts ON request_costs(timestamp);

	CREATE TABLE IF NOT EXISTS daily_costs (
		date TEXT NOT NULL,
		account_id TEXT NOT NULL,
		account_type TEXT NOT NULL,
		model TEXT NOT NULL DEFAULT '',
		input_tokens INTEGER DEFAULT 0,
		cached_tokens INTEGER DEFAULT 0,
		output_tokens INTEGER DEFAULT 0,
		reasoning_tokens INTEGER DEFAULT 0,
		request_count INTEGER DEFAULT 0,
		cost_usd REAL DEFAULT 0,
		PRIMARY KEY (date, account_id, model)
	);
	`
	_, err := db.Exec(schema)
	return err
}

// recordRequest inserts a request cost record.
func (s *AnalyticsStore) recordRequest(ru RequestUsage, costUSD float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO request_costs (timestamp, account_id, account_type, user_id, model,
			input_tokens, cached_tokens, output_tokens, reasoning_tokens, cost_usd)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ru.Timestamp.UTC().Format(time.RFC3339),
		ru.AccountID,
		string(ru.AccountType),
		ru.UserID,
		ru.Model,
		ru.InputTokens,
		ru.CachedInputTokens,
		ru.OutputTokens,
		ru.ReasoningTokens,
		costUSD,
	)
	return err
}

// getCostByAccount returns total cost per account for the last N days.
func (s *AnalyticsStore) getCostByAccount(days int) (map[string]float64, error) {
	since := time.Now().AddDate(0, 0, -days).Format("2006-01-02")
	rows, err := s.db.Query(`
		SELECT account_id, SUM(cost_usd)
		FROM daily_costs
		WHERE date >= ?
		GROUP BY account_id`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]float64)
	for rows.Next() {
		var id string
		var cost float64
		if err := rows.Scan(&id, &cost); err != nil {
			continue
		}
		result[id] = cost
	}

	// Also include today's un-rolled-up request_costs
	todayStart := time.Now().UTC().Format("2006-01-02")
	rows2, err := s.db.Query(`
		SELECT account_id, SUM(cost_usd)
		FROM request_costs
		WHERE timestamp >= ?
		GROUP BY account_id`, todayStart+"T00:00:00Z")
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var id string
			var cost float64
			if err := rows2.Scan(&id, &cost); err != nil {
				continue
			}
			result[id] += cost
		}
	}

	return result, nil
}

// getCostByProvider returns total cost per provider type for the last N days.
func (s *AnalyticsStore) getCostByProvider(days int) (map[string]float64, error) {
	since := time.Now().AddDate(0, 0, -days).Format("2006-01-02")
	rows, err := s.db.Query(`
		SELECT account_type, SUM(cost_usd)
		FROM daily_costs
		WHERE date >= ?
		GROUP BY account_type`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]float64)
	for rows.Next() {
		var accType string
		var cost float64
		if err := rows.Scan(&accType, &cost); err != nil {
			continue
		}
		result[accType] = cost
	}

	// Include today's un-rolled-up data
	todayStart := time.Now().UTC().Format("2006-01-02")
	rows2, err := s.db.Query(`
		SELECT account_type, SUM(cost_usd)
		FROM request_costs
		WHERE timestamp >= ?
		GROUP BY account_type`, todayStart+"T00:00:00Z")
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var accType string
			var cost float64
			if err := rows2.Scan(&accType, &cost); err != nil {
				continue
			}
			result[accType] += cost
		}
	}

	return result, nil
}

// getDailyCosts returns daily cost totals by provider for the last N days (for charting).
func (s *AnalyticsStore) getDailyCosts(days int) ([]DailyCostEntry, error) {
	since := time.Now().AddDate(0, 0, -days).Format("2006-01-02")
	rows, err := s.db.Query(`
		SELECT date, account_type, SUM(cost_usd), SUM(request_count)
		FROM daily_costs
		WHERE date >= ?
		GROUP BY date, account_type
		ORDER BY date`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []DailyCostEntry
	for rows.Next() {
		var e DailyCostEntry
		if err := rows.Scan(&e.Date, &e.AccountType, &e.CostUSD, &e.RequestCount); err != nil {
			continue
		}
		result = append(result, e)
	}
	return result, nil
}

// getModelDailyUsage returns rolled-up historical rows plus today's live
// requests. Keeping the date/model/provider grain makes demand anatomy useful
// without exposing individual accounts or users.
func (s *AnalyticsStore) getModelDailyUsage(days int) ([]ModelDailyUsageEntry, error) {
	if days <= 0 {
		days = 30
	}
	today := time.Now().UTC().Format("2006-01-02")
	since := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
	rows, err := s.db.Query(`
		SELECT date, account_type, COALESCE(model, ''),
			SUM(input_tokens), SUM(cached_tokens), SUM(output_tokens),
			SUM(reasoning_tokens), SUM(request_count), SUM(cost_usd)
		FROM daily_costs
		WHERE date >= ? AND date < ?
		GROUP BY date, account_type, COALESCE(model, '')
		ORDER BY date, account_type, model`, since, today)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ModelDailyUsageEntry, 0)
	for rows.Next() {
		var entry ModelDailyUsageEntry
		if err := rows.Scan(&entry.Date, &entry.AccountType, &entry.Model,
			&entry.InputTokens, &entry.CachedTokens, &entry.OutputTokens,
			&entry.ReasoningTokens, &entry.RequestCount, &entry.CostUSD); err != nil {
			continue
		}
		result = append(result, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	live, err := s.db.Query(`
		SELECT account_type, COALESCE(model, ''),
			SUM(input_tokens), SUM(cached_tokens), SUM(output_tokens),
			SUM(reasoning_tokens), COUNT(*), SUM(cost_usd)
		FROM request_costs
		WHERE timestamp >= ?
		GROUP BY account_type, COALESCE(model, '')
		ORDER BY account_type, model`, today+"T00:00:00Z")
	if err != nil {
		return nil, err
	}
	defer live.Close()
	for live.Next() {
		entry := ModelDailyUsageEntry{Date: today}
		if err := live.Scan(&entry.AccountType, &entry.Model,
			&entry.InputTokens, &entry.CachedTokens, &entry.OutputTokens,
			&entry.ReasoningTokens, &entry.RequestCount, &entry.CostUSD); err == nil {
			result = append(result, entry)
		}
	}
	if err := live.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// getAllAccountDailyCosts returns all rolled-up history plus today's live rows.
// Callers filter to the current account set before calculating pool ROI.
func (s *AnalyticsStore) getAllAccountDailyCosts() ([]AccountDailyCostEntry, error) {
	rows, err := s.db.Query(`
		SELECT date, account_id, account_type, SUM(cost_usd), SUM(request_count)
		FROM daily_costs
		GROUP BY date, account_id, account_type
		ORDER BY date, account_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []AccountDailyCostEntry
	for rows.Next() {
		var entry AccountDailyCostEntry
		if err := rows.Scan(&entry.Date, &entry.AccountID, &entry.AccountType, &entry.CostUSD, &entry.RequestCount); err == nil {
			result = append(result, entry)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	today := time.Now().UTC().Format("2006-01-02")
	liveRows, err := s.db.Query(`
		SELECT account_id, account_type, SUM(cost_usd), COUNT(*)
		FROM request_costs
		WHERE timestamp >= ?
		GROUP BY account_id, account_type`, today+"T00:00:00Z")
	if err != nil {
		return nil, err
	}
	defer liveRows.Close()
	for liveRows.Next() {
		entry := AccountDailyCostEntry{Date: today}
		if err := liveRows.Scan(&entry.AccountID, &entry.AccountType, &entry.CostUSD, &entry.RequestCount); err == nil {
			result = append(result, entry)
		}
	}
	if err := liveRows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// getAllTimeAccountCostStats returns all-time cost and the first date covered
// by that cost for each account.
func (s *AnalyticsStore) getAllTimeAccountCostStats() (map[string]AccountCostStats, error) {
	rows, err := s.db.Query(`
		SELECT account_id, SUM(cost_usd), MIN(date)
		FROM daily_costs
		GROUP BY account_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]AccountCostStats)
	for rows.Next() {
		var id, firstDate string
		var cost float64
		if err := rows.Scan(&id, &cost, &firstDate); err != nil {
			continue
		}
		firstSeen, _ := time.Parse("2006-01-02", firstDate)
		result[id] = AccountCostStats{CostUSD: cost, FirstSeen: firstSeen}
	}

	// Add today's un-rolled-up requests without double-counting older rows that
	// have already been copied into daily_costs.
	todayStart := time.Now().UTC().Format("2006-01-02")
	rows2, err := s.db.Query(`
		SELECT account_id, SUM(cost_usd), MIN(timestamp)
		FROM request_costs
		WHERE timestamp >= ?
		GROUP BY account_id`, todayStart+"T00:00:00Z")
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var id, firstTimestamp string
			var cost float64
			if err := rows2.Scan(&id, &cost, &firstTimestamp); err != nil {
				continue
			}
			stats := result[id]
			stats.CostUSD += cost
			if firstSeen, err := time.Parse(time.RFC3339, firstTimestamp); err == nil &&
				(stats.FirstSeen.IsZero() || firstSeen.Before(stats.FirstSeen)) {
				stats.FirstSeen = firstSeen
			}
			result[id] = stats
		}
	}

	return result, nil
}

// runDailyRollup aggregates yesterday's request_costs into daily_costs and prunes old data.
func (s *AnalyticsStore) runDailyRollup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	yesterday := now.AddDate(0, 0, -1).Format("2006-01-02")

	// Roll up request_costs for yesterday into daily_costs
	_, err := s.db.Exec(`
		INSERT INTO daily_costs (date, account_id, account_type, model,
			input_tokens, cached_tokens, output_tokens, reasoning_tokens, request_count, cost_usd)
		SELECT
			? as date,
			account_id,
			account_type,
			COALESCE(model, '') as model,
			SUM(input_tokens),
			SUM(cached_tokens),
			SUM(output_tokens),
			SUM(reasoning_tokens),
			COUNT(*),
			SUM(cost_usd)
		FROM request_costs
		WHERE timestamp >= ? AND timestamp < ?
		GROUP BY account_id, account_type, COALESCE(model, '')
		ON CONFLICT(date, account_id, model) DO UPDATE SET
			account_type = excluded.account_type,
			input_tokens = excluded.input_tokens,
			cached_tokens = excluded.cached_tokens,
			output_tokens = excluded.output_tokens,
			reasoning_tokens = excluded.reasoning_tokens,
			request_count = excluded.request_count,
			cost_usd = excluded.cost_usd`,
		yesterday, yesterday+"T00:00:00Z", now.Format("2006-01-02")+"T00:00:00Z")
	if err != nil {
		log.Printf("analytics: daily rollup failed: %v", err)
		return
	}

	// Prune old request_costs (keep last 30 days)
	cutoff := now.AddDate(0, 0, -30).Format("2006-01-02") + "T00:00:00Z"
	result, err := s.db.Exec(`DELETE FROM request_costs WHERE timestamp < ?`, cutoff)
	if err != nil {
		log.Printf("analytics: prune failed: %v", err)
		return
	}
	if n, _ := result.RowsAffected(); n > 0 {
		log.Printf("analytics: pruned %d old request_costs rows", n)
	}
}

// startDailyRollup runs the rollup once at startup and then daily at midnight UTC.
func (s *AnalyticsStore) startDailyRollup() {
	// Run once at startup to catch up
	go func() {
		time.Sleep(10 * time.Second) // brief delay to let startup finish
		s.runDailyRollup()
	}()

	go func() {
		for {
			// Sleep until next midnight UTC
			now := time.Now().UTC()
			next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 5, 0, 0, time.UTC)
			time.Sleep(time.Until(next))
			s.runDailyRollup()
		}
	}()
}

// seedFromBoltDB backfills daily_costs from historical BoltDB request data.
// Only runs if daily_costs is empty (first time setup).
func (s *AnalyticsStore) seedFromBoltDB(store *usageStore, pricing *PricingData) {
	if s == nil || store == nil || store.db == nil || pricing == nil {
		return
	}

	// Check if we already have data
	var count int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM daily_costs`).Scan(&count); err != nil || count > 0 {
		return
	}

	log.Printf("analytics: seeding from BoltDB historical data...")

	// Aggregate: date -> accountID -> model -> {tokens, cost}
	type aggKey struct {
		date, accountID, accountType, model string
	}
	type aggVal struct {
		input, cached, output, reasoning, count int64
		cost                                    float64
	}
	agg := make(map[aggKey]*aggVal)
	var totalRequests int64

	err := store.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketUsageRequests))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var ru RequestUsage
			if err := json.Unmarshal(v, &ru); err != nil {
				return nil // skip bad records
			}
			if ru.InputTokens == 0 && ru.OutputTokens == 0 {
				return nil
			}
			totalRequests++

			date := ru.Timestamp.UTC().Format("2006-01-02")
			model := ru.Model
			accType := string(ru.AccountType)

			costUSD := pricing.calculateCost(ru)

			key := aggKey{date, ru.AccountID, accType, model}
			if v, ok := agg[key]; ok {
				v.input += ru.InputTokens
				v.cached += ru.CachedInputTokens
				v.output += ru.OutputTokens
				v.reasoning += ru.ReasoningTokens
				v.count++
				v.cost += costUSD
			} else {
				agg[key] = &aggVal{
					input:     ru.InputTokens,
					cached:    ru.CachedInputTokens,
					output:    ru.OutputTokens,
					reasoning: ru.ReasoningTokens,
					count:     1,
					cost:      costUSD,
				}
			}
			return nil
		})
	})
	if err != nil {
		log.Printf("analytics: seed scan failed: %v", err)
		return
	}

	if len(agg) == 0 {
		log.Printf("analytics: no historical data to seed")
		return
	}

	// Batch insert into daily_costs
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		log.Printf("analytics: seed transaction failed: %v", err)
		return
	}

	stmt, err := tx.Prepare(`
		INSERT INTO daily_costs (date, account_id, account_type, model,
			input_tokens, cached_tokens, output_tokens, reasoning_tokens, request_count, cost_usd)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(date, account_id, model) DO UPDATE SET
			input_tokens = input_tokens + excluded.input_tokens,
			cached_tokens = cached_tokens + excluded.cached_tokens,
			output_tokens = output_tokens + excluded.output_tokens,
			reasoning_tokens = reasoning_tokens + excluded.reasoning_tokens,
			request_count = request_count + excluded.request_count,
			cost_usd = cost_usd + excluded.cost_usd`)
	if err != nil {
		tx.Rollback()
		log.Printf("analytics: seed prepare failed: %v", err)
		return
	}
	defer stmt.Close()

	var totalCost float64
	for key, val := range agg {
		_, err := stmt.Exec(key.date, key.accountID, key.accountType, key.model,
			val.input, val.cached, val.output, val.reasoning, val.count, val.cost)
		if err != nil {
			log.Printf("analytics: seed insert failed for %s/%s: %v", key.date, key.accountID, err)
		}
		totalCost += val.cost
	}

	if err := tx.Commit(); err != nil {
		log.Printf("analytics: seed commit failed: %v", err)
		return
	}

	log.Printf("analytics: seeded %d daily aggregates from %d historical requests, total cost $%.2f", len(agg), totalRequests, totalCost)
}

// Close closes the underlying database connection.
func (s *AnalyticsStore) Close() error {
	return s.db.Close()
}
