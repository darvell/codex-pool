package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"go.etcd.io/bbolt"
)

const analyticsPricingVersion = "2026-08-18-v2"

type analyticsPricingAggKey struct {
	date, accountID, accountType, model string
}

type analyticsPricingAgg struct {
	input, cached, cacheCreation, output, reasoning, count int64
	cost                                                   float64
}

// rebuildPricingFromBoltDB rebuilds both cost tables when pricing semantics
// change. BoltDB retains the complete RequestUsage record, including cache
// creation tokens that older SQLite schemas discarded, so it is the only
// source capable of producing an honest historical reprice.
func (s *AnalyticsStore) rebuildPricingFromBoltDB(store *usageStore, pricing *PricingData) error {
	if s == nil || s.db == nil || store == nil || store.db == nil || pricing == nil {
		return nil
	}

	var version string
	err := s.db.QueryRow(`SELECT value FROM analytics_metadata WHERE key = 'pricing_version'`).Scan(&version)
	if err == nil && version == analyticsPricingVersion {
		return nil
	}

	log.Printf("analytics: rebuilding historical costs for pricing version %s...", analyticsPricingVersion)
	started := time.Now()
	cutoff := time.Now().UTC().AddDate(0, 0, -30)
	agg := make(map[analyticsPricingAggKey]*analyticsPricingAgg)

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM request_costs; DELETE FROM daily_costs`); err != nil {
		return err
	}

	requestStmt, err := tx.Prepare(`INSERT INTO request_costs
		(timestamp, account_id, account_type, user_id, model, input_tokens, cached_tokens,
		 cache_creation_tokens, output_tokens, reasoning_tokens, cost_usd)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer requestStmt.Close()

	var totalRequests, recentRequests int64
	err = store.db.View(func(btx *bbolt.Tx) error {
		bucket := btx.Bucket([]byte(bucketUsageRequests))
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(_, value []byte) error {
			var ru RequestUsage
			if err := json.Unmarshal(value, &ru); err != nil {
				return nil
			}
			if ru.InputTokens == 0 && ru.CachedInputTokens == 0 && ru.CacheCreationTokens == 0 && ru.OutputTokens == 0 {
				return nil
			}
			cost := pricing.calculateCost(ru)
			totalRequests++

			key := analyticsPricingAggKey{
				date:        ru.Timestamp.UTC().Format("2006-01-02"),
				accountID:   ru.AccountID,
				accountType: string(ru.AccountType),
				model:       ru.Model,
			}
			row := agg[key]
			if row == nil {
				row = &analyticsPricingAgg{}
				agg[key] = row
			}
			row.input += ru.InputTokens
			row.cached += ru.CachedInputTokens
			row.cacheCreation += ru.CacheCreationTokens
			row.output += ru.OutputTokens
			row.reasoning += ru.ReasoningTokens
			row.count++
			row.cost += cost

			if !ru.Timestamp.Before(cutoff) {
				_, err := requestStmt.Exec(
					ru.Timestamp.UTC().Format(time.RFC3339), ru.AccountID, string(ru.AccountType),
					ru.UserID, ru.Model, ru.InputTokens, ru.CachedInputTokens,
					ru.CacheCreationTokens, ru.OutputTokens, ru.ReasoningTokens, cost,
				)
				if err != nil {
					return err
				}
				recentRequests++
			}
			return nil
		})
	})
	if err != nil {
		return fmt.Errorf("scan usage history: %w", err)
	}

	dailyStmt, err := tx.Prepare(`INSERT INTO daily_costs
		(date, account_id, account_type, model, input_tokens, cached_tokens,
		 cache_creation_tokens, output_tokens, reasoning_tokens, request_count, cost_usd)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer dailyStmt.Close()
	var totalCost float64
	for key, row := range agg {
		if _, err := dailyStmt.Exec(
			key.date, key.accountID, key.accountType, key.model,
			row.input, row.cached, row.cacheCreation, row.output, row.reasoning, row.count, row.cost,
		); err != nil {
			return err
		}
		totalCost += row.cost
	}
	if _, err := tx.Exec(`INSERT INTO analytics_metadata (key, value) VALUES ('pricing_version', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, analyticsPricingVersion); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	log.Printf("analytics: repriced %d requests ($%.2f total; %d retained as recent rows) in %s",
		totalRequests, totalCost, recentRequests, time.Since(started).Round(time.Millisecond))
	return nil
}
