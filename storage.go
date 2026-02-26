package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

const (
	bucketUsageRequests    = "usage_requests"
	bucketAccountUsage     = "account_usage"
	bucketPlanCapacity     = "plan_capacity"
	bucketCapacitySamples  = "capacity_samples"
	bucketUserUsage        = "user_usage"
	bucketUserDailyUsage   = "user_daily_usage"
	bucketUserHourlyUsage  = "user_hourly_usage"
	bucketGlobalHourlyUsage = "global_hourly_usage"
)

// UserUsage tracks aggregate token usage per user.
type UserUsage struct {
	UserID               string    `json:"user_id"`
	TotalInputTokens     int64     `json:"total_input_tokens"`
	TotalCachedTokens    int64     `json:"total_cached_tokens"`
	TotalOutputTokens    int64     `json:"total_output_tokens"`
	TotalReasoningTokens int64     `json:"total_reasoning_tokens"`
	TotalBillableTokens  int64     `json:"total_billable_tokens"`
	RequestCount         int64     `json:"request_count"`
	FirstSeen            time.Time `json:"first_seen"`
	LastSeen             time.Time `json:"last_seen"`
}

// UserDailyUsage tracks per-day token usage for a user.
type UserDailyUsage struct {
	Date            string `json:"date"` // YYYY-MM-DD
	BillableTokens  int64  `json:"billable_tokens"`
	InputTokens     int64  `json:"input_tokens"`
	OutputTokens    int64  `json:"output_tokens"`
	CachedTokens    int64  `json:"cached_tokens"`
	ReasoningTokens int64  `json:"reasoning_tokens"`
	RequestCount    int64  `json:"request_count"`
	// Per-provider breakdown
	ClaudeTokens int64 `json:"claude_tokens,omitempty"`
	CodexTokens  int64 `json:"codex_tokens,omitempty"`
	GeminiTokens int64 `json:"gemini_tokens,omitempty"`
}

// UserHourlyUsage tracks per-hour per-provider token usage.
type UserHourlyUsage struct {
	Hour            string `json:"hour"`          // "2025-02-05T14" (ISO hour)
	AccountType     string `json:"account_type"`  // "claude", "codex", "gemini"
	InputTokens     int64  `json:"input_tokens"`
	CachedTokens    int64  `json:"cached_tokens"`
	OutputTokens    int64  `json:"output_tokens"`
	ReasoningTokens int64  `json:"reasoning_tokens"`
	BillableTokens  int64  `json:"billable_tokens"`
	RequestCount    int64  `json:"request_count"`
}

type usageStore struct {
	db        *bbolt.DB
	retention time.Duration
	nextPrune time.Time

	// In-memory cache of last known rate limits per account for delta calculation
	lastRateLimits   map[string]rateLimitSnapshot
	lastRateLimitsMu sync.RWMutex
}

type rateLimitSnapshot struct {
	PrimaryPct   float64
	SecondaryPct float64
	Timestamp    time.Time
}

// CapacitySample records a single observation of tokens vs rate limit change.
type CapacitySample struct {
	Timestamp       time.Time `json:"ts"`
	AccountID       string    `json:"account"`
	PlanType        string    `json:"plan"`
	BillableTokens  int64     `json:"tokens"`
	InputTokens     int64     `json:"input"`
	OutputTokens    int64     `json:"output"`
	CachedTokens    int64     `json:"cached"`
	ReasoningTokens int64     `json:"reasoning"`
	PrimaryDelta    float64   `json:"primary_delta"`   // Change in primary %
	SecondaryDelta  float64   `json:"secondary_delta"` // Change in secondary %
}

func newUsageStore(path string, retentionDays int) (*usageStore, error) {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		for _, bucket := range []string{bucketUsageRequests, bucketAccountUsage, bucketPlanCapacity, bucketCapacitySamples, bucketUserUsage, bucketUserDailyUsage, bucketUserHourlyUsage, bucketGlobalHourlyUsage} {
			if _, e := tx.CreateBucketIfNotExists([]byte(bucket)); e != nil {
				return e
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	return &usageStore{
		db:             db,
		retention:      time.Duration(retentionDays) * 24 * time.Hour,
		nextPrune:      time.Now().Add(1 * time.Hour),
		lastRateLimits: make(map[string]rateLimitSnapshot),
	}, nil
}

func (s *usageStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *usageStore) record(u RequestUsage) error {
	if s == nil || s.db == nil {
		return nil
	}

	// Calculate rate limit deltas
	var primaryDelta, secondaryDelta float64
	if u.PrimaryUsedPct > 0 || u.SecondaryUsedPct > 0 {
		s.lastRateLimitsMu.Lock()
		if last, ok := s.lastRateLimits[u.AccountID]; ok {
			// Only count positive deltas (usage increase) and ignore resets
			if u.PrimaryUsedPct >= last.PrimaryPct {
				primaryDelta = u.PrimaryUsedPct - last.PrimaryPct
			}
			if u.SecondaryUsedPct >= last.SecondaryPct {
				secondaryDelta = u.SecondaryUsedPct - last.SecondaryPct
			}
		}
		s.lastRateLimits[u.AccountID] = rateLimitSnapshot{
			PrimaryPct:   u.PrimaryUsedPct,
			SecondaryPct: u.SecondaryUsedPct,
			Timestamp:    u.Timestamp,
		}
		s.lastRateLimitsMu.Unlock()
	}

	key := fmt.Sprintf("%s|%020d", safeID(u.AccountID), u.Timestamp.UnixNano())
	if u.RequestID != "" {
		key = key + "|" + u.RequestID
	}
	val, err := json.Marshal(u)
	if err != nil {
		return err
	}

	err = s.db.Update(func(tx *bbolt.Tx) error {
		// Store raw request
		if err := tx.Bucket([]byte(bucketUsageRequests)).Put([]byte(key), val); err != nil {
			return err
		}

		// Update account aggregates
		b := tx.Bucket([]byte(bucketAccountUsage))
		var agg AccountUsage
		if raw := b.Get([]byte(u.AccountID)); raw != nil {
			_ = json.Unmarshal(raw, &agg)
		}
		agg.TotalInputTokens += u.InputTokens
		agg.TotalCachedTokens += u.CachedInputTokens
		agg.TotalOutputTokens += u.OutputTokens
		agg.TotalReasoningTokens += u.ReasoningTokens
		agg.TotalBillableTokens += u.BillableTokens
		agg.RequestCount++
		agg.LastPrimaryPct = u.PrimaryUsedPct
		agg.LastSecondaryPct = u.SecondaryUsedPct
		agg.LastUpdated = u.Timestamp
		if enc, err := json.Marshal(&agg); err == nil {
			_ = b.Put([]byte(u.AccountID), enc)
		}

		// Update user usage aggregates (if UserID is set)
		if u.UserID != "" {
			userBucket := tx.Bucket([]byte(bucketUserUsage))
			var userAgg UserUsage
			if raw := userBucket.Get([]byte(u.UserID)); raw != nil {
				_ = json.Unmarshal(raw, &userAgg)
			}
			if userAgg.FirstSeen.IsZero() {
				userAgg.FirstSeen = u.Timestamp
			}
			userAgg.UserID = u.UserID
			userAgg.TotalInputTokens += u.InputTokens
			userAgg.TotalCachedTokens += u.CachedInputTokens
			userAgg.TotalOutputTokens += u.OutputTokens
			userAgg.TotalReasoningTokens += u.ReasoningTokens
			userAgg.TotalBillableTokens += u.BillableTokens
			userAgg.RequestCount++
			userAgg.LastSeen = u.Timestamp
			if enc, err := json.Marshal(&userAgg); err == nil {
				_ = userBucket.Put([]byte(u.UserID), enc)
			}

			// Update daily usage
			dateKey := u.Timestamp.Format("2006-01-02")
			dailyBucket := tx.Bucket([]byte(bucketUserDailyUsage))
			dailyKey := fmt.Sprintf("%s|%s", u.UserID, dateKey)
			var daily UserDailyUsage
			if raw := dailyBucket.Get([]byte(dailyKey)); raw != nil {
				_ = json.Unmarshal(raw, &daily)
			}
			daily.Date = dateKey
			daily.BillableTokens += u.BillableTokens
			daily.InputTokens += u.InputTokens
			daily.OutputTokens += u.OutputTokens
			daily.CachedTokens += u.CachedInputTokens
			daily.ReasoningTokens += u.ReasoningTokens
			daily.RequestCount++
			// Per-provider breakdown
			switch u.AccountType {
			case AccountTypeClaude:
				daily.ClaudeTokens += u.BillableTokens
			case AccountTypeCodex:
				daily.CodexTokens += u.BillableTokens
			case AccountTypeGemini:
				daily.GeminiTokens += u.BillableTokens
			}
			if enc, err := json.Marshal(&daily); err == nil {
				_ = dailyBucket.Put([]byte(dailyKey), enc)
			}

			// Update hourly usage (per-user)
			hourKey := u.Timestamp.Format("2006-01-02T15")
			acctType := string(u.AccountType)
			if acctType == "" {
				acctType = "unknown"
			}
			hourlyBucket := tx.Bucket([]byte(bucketUserHourlyUsage))
			hourlyBucketKey := fmt.Sprintf("%s|%s|%s", u.UserID, hourKey, acctType)
			var hourly UserHourlyUsage
			if raw := hourlyBucket.Get([]byte(hourlyBucketKey)); raw != nil {
				_ = json.Unmarshal(raw, &hourly)
			}
			hourly.Hour = hourKey
			hourly.AccountType = acctType
			hourly.InputTokens += u.InputTokens
			hourly.CachedTokens += u.CachedInputTokens
			hourly.OutputTokens += u.OutputTokens
			hourly.ReasoningTokens += u.ReasoningTokens
			hourly.BillableTokens += u.BillableTokens
			hourly.RequestCount++
			if enc, err := json.Marshal(&hourly); err == nil {
				_ = hourlyBucket.Put([]byte(hourlyBucketKey), enc)
			}

			// Update global hourly usage (all users combined)
			globalHourlyBucket := tx.Bucket([]byte(bucketGlobalHourlyUsage))
			globalHourlyKey := fmt.Sprintf("%s|%s", hourKey, acctType)
			var globalHourly UserHourlyUsage
			if raw := globalHourlyBucket.Get([]byte(globalHourlyKey)); raw != nil {
				_ = json.Unmarshal(raw, &globalHourly)
			}
			globalHourly.Hour = hourKey
			globalHourly.AccountType = acctType
			globalHourly.InputTokens += u.InputTokens
			globalHourly.CachedTokens += u.CachedInputTokens
			globalHourly.OutputTokens += u.OutputTokens
			globalHourly.ReasoningTokens += u.ReasoningTokens
			globalHourly.BillableTokens += u.BillableTokens
			globalHourly.RequestCount++
			if enc, err := json.Marshal(&globalHourly); err == nil {
				_ = globalHourlyBucket.Put([]byte(globalHourlyKey), enc)
			}
		}

		// Store capacity sample if we have meaningful deltas
		if u.BillableTokens > 0 && (primaryDelta > 0.001 || secondaryDelta > 0.001) {
			sample := CapacitySample{
				Timestamp:       u.Timestamp,
				AccountID:       u.AccountID,
				PlanType:        u.PlanType,
				BillableTokens:  u.BillableTokens,
				InputTokens:     u.InputTokens,
				OutputTokens:    u.OutputTokens,
				CachedTokens:    u.CachedInputTokens,
				ReasoningTokens: u.ReasoningTokens,
				PrimaryDelta:    primaryDelta,
				SecondaryDelta:  secondaryDelta,
			}
			sampleKey := fmt.Sprintf("%s|%020d", safeID(u.PlanType), u.Timestamp.UnixNano())
			if sampleVal, err := json.Marshal(sample); err == nil {
				_ = tx.Bucket([]byte(bucketCapacitySamples)).Put([]byte(sampleKey), sampleVal)
			}

			// Update plan capacity aggregates with full sample for weighted analysis
			s.updatePlanCapacity(tx, sample)
		}

		return nil
	})
	if err != nil {
		return err
	}
	if time.Now().After(s.nextPrune) {
		s.prune()
	}
	return nil
}

func (s *usageStore) updatePlanCapacity(tx *bbolt.Tx, sample CapacitySample) {
	planType := sample.PlanType
	if planType == "" {
		planType = "unknown"
	}
	b := tx.Bucket([]byte(bucketPlanCapacity))
	var cap TokenCapacity
	if raw := b.Get([]byte(planType)); raw != nil {
		_ = json.Unmarshal(raw, &cap)
	}
	cap.PlanType = planType
	cap.SampleCount++
	cap.TotalTokens += sample.BillableTokens
	cap.TotalPrimaryPctDelta += sample.PrimaryDelta
	cap.TotalSecondaryPctDelta += sample.SecondaryDelta

	// Track individual token types for weighted estimation
	cap.TotalInputTokens += sample.InputTokens
	cap.TotalCachedTokens += sample.CachedTokens
	cap.TotalOutputTokens += sample.OutputTokens
	cap.TotalReasoningTokens += sample.ReasoningTokens

	// Calculate raw tokens per percent (avoid division by zero)
	if cap.TotalPrimaryPctDelta > 0.01 {
		cap.TokensPerPrimaryPct = float64(cap.TotalTokens) / cap.TotalPrimaryPctDelta
	}
	if cap.TotalSecondaryPctDelta > 0.01 {
		cap.TokensPerSecondaryPct = float64(cap.TotalTokens) / cap.TotalSecondaryPctDelta
	}

	// Estimate output multiplier from data if we have enough samples
	// Known: cached costs 0.1x of input, output costs more than input
	// We use the relationship: delta% ≈ (input + cached*0.1 + output*M + reasoning*M) / capacity
	// Start with default multiplier of 4.0 (typical LLM output:input cost ratio)
	outputMult := 4.0
	reasoningMult := 4.0

	// If we have enough samples, try to refine the estimate
	// Using the heuristic that if raw estimate is way off from weighted, adjust multiplier
	if cap.SampleCount >= 10 && cap.TotalInputTokens > 0 && cap.TotalOutputTokens > 0 {
		// Rough estimation: if output tokens are generating more delta than expected,
		// the multiplier should be higher
		inputEquivalent := float64(cap.TotalInputTokens) + float64(cap.TotalCachedTokens)*0.1
		outputEquivalent := float64(cap.TotalOutputTokens) + float64(cap.TotalReasoningTokens)

		if inputEquivalent > 0 && outputEquivalent > 0 {
			// Total effective with current multiplier
			totalDelta := cap.TotalPrimaryPctDelta + cap.TotalSecondaryPctDelta
			if totalDelta > 0.1 {
				// Estimate: what multiplier would make the math work?
				// totalDelta ≈ (inputEquiv + outputEquiv * M) / capacity
				// We don't know capacity, but we can compare ratios
				ratio := outputEquivalent / inputEquivalent
				if ratio > 0.1 && ratio < 10 {
					// Output is significant portion - use data to refine
					// Keep multiplier bounded between 2x and 8x
					estimatedMult := 4.0 * (1.0 + (ratio-1.0)*0.2)
					if estimatedMult < 2.0 {
						estimatedMult = 2.0
					}
					if estimatedMult > 8.0 {
						estimatedMult = 8.0
					}
					outputMult = estimatedMult
					reasoningMult = estimatedMult
				}
			}
		}
	}
	cap.OutputMultiplier = outputMult
	cap.ReasoningMultiplier = reasoningMult

	// Calculate weighted effective tokens per percent
	// Formula: effective = input + (cached * 0.1) + (output * outputMult) + (reasoning * reasoningMult)
	totalEffective := float64(cap.TotalInputTokens) +
		float64(cap.TotalCachedTokens)*0.1 +
		float64(cap.TotalOutputTokens)*outputMult +
		float64(cap.TotalReasoningTokens)*reasoningMult

	// Only update if totalEffective is positive (prevents corrupted data from past negative billable tokens)
	if cap.TotalPrimaryPctDelta > 0.01 && totalEffective > 0 {
		cap.EffectivePerPrimaryPct = totalEffective / cap.TotalPrimaryPctDelta
	}
	if cap.TotalSecondaryPctDelta > 0.01 && totalEffective > 0 {
		cap.EffectivePerSecondaryPct = totalEffective / cap.TotalSecondaryPctDelta
	}

	if enc, err := json.Marshal(&cap); err == nil {
		_ = b.Put([]byte(planType), enc)
	}
}

func (s *usageStore) prune() {
	cutoff := time.Now().Add(-s.retention)
	_ = s.db.Update(func(tx *bbolt.Tx) error {
		c := tx.Bucket([]byte(bucketUsageRequests)).Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			parts := strings.Split(string(k), "|")
			if len(parts) < 2 {
				continue
			}
			ts, err := timeFromKey(parts[1])
			if err != nil {
				continue
			}
			if ts.Before(cutoff) {
				_ = c.Delete()
			} else {
				// keys are ordered; can break once beyond cutoff
				break
			}
		}
		return nil
	})
	s.nextPrune = time.Now().Add(1 * time.Hour)
}

func timeFromKey(tsPart string) (time.Time, error) {
	var n int64
	if _, err := fmt.Sscanf(tsPart, "%d", &n); err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, n), nil
}

func safeID(id string) string {
	if id == "" {
		return "unknown"
	}
	return id
}

// loadAccountUsage fetches aggregates for an account.
func (s *usageStore) loadAccountUsage(accountID string) (AccountUsage, error) {
	var out AccountUsage
	if s == nil || s.db == nil {
		return out, nil
	}
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketAccountUsage))
		if raw := b.Get([]byte(accountID)); raw != nil {
			return json.Unmarshal(raw, &out)
		}
		return nil
	})
	return out, err
}

// loadAllAccountUsage returns usage for all accounts.
func (s *usageStore) loadAllAccountUsage() (map[string]AccountUsage, error) {
	out := make(map[string]AccountUsage)
	if s == nil || s.db == nil {
		return out, nil
	}
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketAccountUsage))
		return b.ForEach(func(k, v []byte) error {
			var agg AccountUsage
			if err := json.Unmarshal(v, &agg); err == nil {
				out[string(k)] = agg
			}
			return nil
		})
	})
	return out, err
}

// loadPlanCapacity returns capacity analysis for a plan type.
func (s *usageStore) loadPlanCapacity(planType string) (TokenCapacity, error) {
	var out TokenCapacity
	if s == nil || s.db == nil {
		return out, nil
	}
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketPlanCapacity))
		if raw := b.Get([]byte(planType)); raw != nil {
			return json.Unmarshal(raw, &out)
		}
		return nil
	})
	return out, err
}

// loadAllPlanCapacity returns capacity analysis for all plan types.
func (s *usageStore) loadAllPlanCapacity() (map[string]TokenCapacity, error) {
	out := make(map[string]TokenCapacity)
	if s == nil || s.db == nil {
		return out, nil
	}
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketPlanCapacity))
		return b.ForEach(func(k, v []byte) error {
			var cap TokenCapacity
			if err := json.Unmarshal(v, &cap); err == nil {
				out[string(k)] = cap
			}
			return nil
		})
	})
	return out, err
}

// CapacityEstimate provides an estimate of remaining capacity for a plan.
type CapacityEstimate struct {
	PlanType                string  `json:"plan_type"`
	SampleCount             int64   `json:"sample_count"`
	ConfidenceLevel         string  `json:"confidence"`                // "low", "medium", "high"
	EstimatedTotalPrimary   int64   `json:"estimated_total_primary"`   // Total effective tokens per 5hr window
	EstimatedTotalSecondary int64   `json:"estimated_total_secondary"` // Total effective tokens per 7d window
	OutputMultiplier        float64 `json:"output_multiplier"`
	ReasoningMultiplier     float64 `json:"reasoning_multiplier"`
	CachedMultiplier        float64 `json:"cached_multiplier"` // Always 0.1
	Notes                   string  `json:"notes,omitempty"`
}

// EstimateCapacity returns capacity estimates for all tracked plan types.
func (s *usageStore) EstimateCapacity() (map[string]CapacityEstimate, error) {
	estimates := make(map[string]CapacityEstimate)
	if s == nil || s.db == nil {
		return estimates, nil
	}

	caps, err := s.loadAllPlanCapacity()
	if err != nil {
		return estimates, err
	}

	for planType, cap := range caps {
		est := CapacityEstimate{
			PlanType:            planType,
			SampleCount:         cap.SampleCount,
			OutputMultiplier:    cap.OutputMultiplier,
			ReasoningMultiplier: cap.ReasoningMultiplier,
			CachedMultiplier:    0.1,
		}

		// Determine confidence based on sample count
		switch {
		case cap.SampleCount < 5:
			est.ConfidenceLevel = "low"
			est.Notes = "Need more samples for accurate estimation"
		case cap.SampleCount < 20:
			est.ConfidenceLevel = "medium"
		default:
			est.ConfidenceLevel = "high"
		}

		// Estimate total capacity (effective tokens for 100% usage)
		// If we know X effective tokens = Y%, then 100% = X * (100/Y)
		if cap.EffectivePerPrimaryPct > 0 {
			est.EstimatedTotalPrimary = int64(cap.EffectivePerPrimaryPct * 100)
		} else if cap.TokensPerPrimaryPct > 0 {
			// Fallback to raw tokens if no weighted estimate
			est.EstimatedTotalPrimary = int64(cap.TokensPerPrimaryPct * 100)
			est.Notes = "Using raw token estimate (no weighted data yet)"
		}

		if cap.EffectivePerSecondaryPct > 0 {
			est.EstimatedTotalSecondary = int64(cap.EffectivePerSecondaryPct * 100)
		} else if cap.TokensPerSecondaryPct > 0 {
			est.EstimatedTotalSecondary = int64(cap.TokensPerSecondaryPct * 100)
		}

		// Set default multipliers if not yet estimated
		if est.OutputMultiplier == 0 {
			est.OutputMultiplier = 4.0
		}
		if est.ReasoningMultiplier == 0 {
			est.ReasoningMultiplier = 4.0
		}

		estimates[planType] = est
	}

	return estimates, nil
}

// getRecentSamples returns the most recent capacity samples.
func (s *usageStore) getRecentSamples(limit int) ([]CapacitySample, error) {
	var samples []CapacitySample
	if s == nil || s.db == nil {
		return samples, nil
	}
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketCapacitySamples))
		c := b.Cursor()
		// Iterate in reverse to get most recent first
		for k, v := c.Last(); k != nil && len(samples) < limit; k, v = c.Prev() {
			var sample CapacitySample
			if err := json.Unmarshal(v, &sample); err == nil {
				samples = append(samples, sample)
			}
		}
		return nil
	})
	return samples, err
}

// getUserUsage returns aggregate usage for a specific user.
func (s *usageStore) getUserUsage(userID string) (*UserUsage, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	var out UserUsage
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketUserUsage))
		if raw := b.Get([]byte(userID)); raw != nil {
			return json.Unmarshal(raw, &out)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out.UserID == "" {
		return nil, nil
	}
	return &out, nil
}

// getAllUserUsage returns usage for all users, sorted by total billable tokens descending.
func (s *usageStore) getAllUserUsage() ([]UserUsage, error) {
	var users []UserUsage
	if s == nil || s.db == nil {
		return users, nil
	}
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketUserUsage))
		return b.ForEach(func(k, v []byte) error {
			var u UserUsage
			if err := json.Unmarshal(v, &u); err == nil {
				users = append(users, u)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	// Sort by total billable tokens descending
	for i := 0; i < len(users); i++ {
		for j := i + 1; j < len(users); j++ {
			if users[j].TotalBillableTokens > users[i].TotalBillableTokens {
				users[i], users[j] = users[j], users[i]
			}
		}
	}
	return users, nil
}

// getUserDailyUsage returns daily usage for a user over the last N days.
func (s *usageStore) getUserDailyUsage(userID string, days int) ([]UserDailyUsage, error) {
	var daily []UserDailyUsage
	if s == nil || s.db == nil {
		return daily, nil
	}
	if days <= 0 {
		days = 30
	}

	// Generate date keys for the last N days
	today := time.Now()
	dateKeys := make(map[string]bool)
	for i := 0; i < days; i++ {
		d := today.AddDate(0, 0, -i)
		dateKeys[d.Format("2006-01-02")] = true
	}

	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketUserDailyUsage))
		prefix := []byte(userID + "|")
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && len(k) > len(prefix) && string(k[:len(prefix)]) == string(prefix); k, v = c.Next() {
			dateStr := string(k[len(prefix):])
			if dateKeys[dateStr] {
				var d UserDailyUsage
				if err := json.Unmarshal(v, &d); err == nil {
					daily = append(daily, d)
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sort by date descending (most recent first)
	for i := 0; i < len(daily); i++ {
		for j := i + 1; j < len(daily); j++ {
			if daily[j].Date > daily[i].Date {
				daily[i], daily[j] = daily[j], daily[i]
			}
		}
	}
	return daily, nil
}

// getUserHourlyUsage returns hourly usage for a user over the last N hours.
func (s *usageStore) getUserHourlyUsage(userID string, hours int) ([]UserHourlyUsage, error) {
	var result []UserHourlyUsage
	if s == nil || s.db == nil {
		return result, nil
	}
	if hours <= 0 {
		hours = 24
	}

	// Generate hour keys for the last N hours
	now := time.Now()
	hourKeys := make(map[string]bool)
	for i := 0; i < hours; i++ {
		h := now.Add(-time.Duration(i) * time.Hour)
		hourKeys[h.Format("2006-01-02T15")] = true
	}

	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketUserHourlyUsage))
		prefix := []byte(userID + "|")
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && len(k) > len(prefix) && string(k[:len(prefix)]) == string(prefix); k, v = c.Next() {
			// Key format: userID|hourKey|accountType
			rest := string(k[len(prefix):])
			parts := strings.SplitN(rest, "|", 2)
			if len(parts) < 1 {
				continue
			}
			hourKey := parts[0]
			if hourKeys[hourKey] {
				var h UserHourlyUsage
				if err := json.Unmarshal(v, &h); err == nil {
					result = append(result, h)
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sort by hour descending
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].Hour > result[i].Hour {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	return result, nil
}

// getGlobalHourlyUsage returns global hourly usage (all users combined) over the last N hours.
func (s *usageStore) getGlobalHourlyUsage(hours int) ([]UserHourlyUsage, error) {
	var result []UserHourlyUsage
	if s == nil || s.db == nil {
		return result, nil
	}
	if hours <= 0 {
		hours = 24
	}

	// Generate hour keys for the last N hours
	now := time.Now()
	hourKeys := make(map[string]bool)
	for i := 0; i < hours; i++ {
		h := now.Add(-time.Duration(i) * time.Hour)
		hourKeys[h.Format("2006-01-02T15")] = true
	}

	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketGlobalHourlyUsage))
		return b.ForEach(func(k, v []byte) error {
			// Key format: hourKey|accountType
			key := string(k)
			parts := strings.SplitN(key, "|", 2)
			if len(parts) < 1 {
				return nil
			}
			hourKey := parts[0]
			if hourKeys[hourKey] {
				var h UserHourlyUsage
				if err := json.Unmarshal(v, &h); err == nil {
					result = append(result, h)
				}
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	// Sort by hour descending
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].Hour > result[i].Hour {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	return result, nil
}
