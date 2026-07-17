package main

import (
	"log"
	"math"
	"sort"
	"strings"
	"time"
)

const quotaIntelligenceRefreshInterval = 15 * time.Minute

type quotaIntelligenceSnapshot struct {
	updatedAt       time.Time
	capacity        []QuotaCapacityPoint
	modelEfficiency []ModelQuotaEfficiency
	resetEvents     []ResetObservation
}

func (h *proxyHandler) startQuotaIntelligenceRefresher() {
	if h == nil || h.store == nil {
		return
	}
	go h.refreshQuotaIntelligence()
	go func() {
		ticker := time.NewTicker(quotaIntelligenceRefreshInterval)
		defer ticker.Stop()
		for range ticker.C {
			h.refreshQuotaIntelligence()
		}
	}()
}

func (h *proxyHandler) quotaIntelligenceSnapshot() quotaIntelligenceSnapshot {
	if h == nil {
		return quotaIntelligenceSnapshot{}
	}
	h.quotaIntelMu.RLock()
	snapshot := h.quotaIntel
	snapshot.capacity = append([]QuotaCapacityPoint(nil), snapshot.capacity...)
	snapshot.modelEfficiency = append([]ModelQuotaEfficiency(nil), snapshot.modelEfficiency...)
	snapshot.resetEvents = append([]ResetObservation(nil), snapshot.resetEvents...)
	h.quotaIntelMu.RUnlock()
	return snapshot
}

func (h *proxyHandler) refreshQuotaIntelligence() {
	if h == nil || h.store == nil {
		return
	}
	h.quotaIntelMu.Lock()
	if h.quotaIntelBusy {
		h.quotaIntelMu.Unlock()
		return
	}
	h.quotaIntelBusy = true
	h.quotaIntelMu.Unlock()
	started := time.Now()
	defer func() {
		h.quotaIntelMu.Lock()
		h.quotaIntelBusy = false
		h.quotaIntelMu.Unlock()
	}()

	requests, err := h.store.getRecentRequestUsage(30)
	if err != nil {
		log.Printf("quota intelligence refresh failed: %v", err)
		return
	}
	metadata := make(map[string]quotaAccountMeta)
	for _, account := range h.pool.allAccounts() {
		account.mu.Lock()
		metadata[account.ID] = quotaAccountMeta{
			accountType:   string(account.Type),
			planType:      account.PlanType,
			windowMinutes: account.Usage.SecondaryWindowMinutes,
		}
		account.mu.Unlock()
	}
	var costFor func(RequestUsage) float64
	if h.pricing != nil {
		costFor = h.pricing.calculateCost
	}
	capacity, modelEfficiency, resetEvents := inferQuotaIntelligence(requests, metadata, costFor)
	h.quotaIntelMu.Lock()
	h.quotaIntel = quotaIntelligenceSnapshot{
		updatedAt:       time.Now().UTC(),
		capacity:        capacity,
		modelEfficiency: modelEfficiency,
		resetEvents:     resetEvents,
	}
	h.quotaIntelMu.Unlock()
	log.Printf("quota intelligence refreshed: requests=%d capacity=%d models=%d resets=%d duration=%s", len(requests), len(capacity), len(modelEfficiency), len(resetEvents), time.Since(started).Round(time.Millisecond))
}

type QuotaCapacityPoint struct {
	WeekStart             string  `json:"week_start"`
	AccountType           string  `json:"account_type"`
	PlanType              string  `json:"plan_type"`
	WindowMinutes         int     `json:"window_minutes"`
	EstimatedWindowTokens int64   `json:"estimated_window_tokens"`
	EstimatedWeeklyTokens int64   `json:"estimated_weekly_tokens"`
	LowEstimateTokens     int64   `json:"low_estimate_tokens"`
	HighEstimateTokens    int64   `json:"high_estimate_tokens"`
	ObservedQuotaPct      float64 `json:"observed_quota_pct"`
	IntervalCount         int     `json:"interval_count"`
	RequestCount          int64   `json:"request_count"`
	Confidence            string  `json:"confidence"`
}

type ModelQuotaEfficiency struct {
	AccountType      string  `json:"account_type"`
	Model            string  `json:"model"`
	Tokens           int64   `json:"tokens"`
	RequestCount     int64   `json:"request_count"`
	APIValue         float64 `json:"api_value"`
	ObservedQuotaPct float64 `json:"observed_quota_pct"`
	APIValuePerQuota float64 `json:"api_value_per_quota_pct"`
	RelativeSubsidy  float64 `json:"relative_subsidy"`
	IntervalCount    int     `json:"interval_count"`
	Confidence       string  `json:"confidence"`
}

type ResetObservation struct {
	AccountID        string     `json:"account_id"`
	AccountType      string     `json:"account_type"`
	ObservedAt       time.Time  `json:"observed_at"`
	ExpectedAt       *time.Time `json:"expected_at,omitempty"`
	DeviationMinutes *int       `json:"deviation_minutes,omitempty"`
	FromUsedPct      float64    `json:"from_used_pct"`
	ToUsedPct        float64    `json:"to_used_pct"`
	Timing           string     `json:"timing"`
}

type quotaAccountMeta struct {
	accountType   string
	planType      string
	windowMinutes int
}

type modelIntervalUsage struct {
	tokens   int64
	requests int64
	apiValue float64
}

type quotaState struct {
	initialized bool
	lastPct     float64
	expectedAt  time.Time
	pending     map[string]*modelIntervalUsage
}

type capacityAggregate struct {
	point     QuotaCapacityPoint
	tokens    int64
	delta     float64
	estimates []float64
}

type modelAggregate struct {
	row ModelQuotaEfficiency
}

func quotaConfidence(intervals int, observedPct float64) string {
	switch {
	case intervals >= 20 && observedPct >= 20:
		return "high"
	case intervals >= 5 && observedPct >= 5:
		return "medium"
	default:
		return "low"
	}
}

func quotaThroughput(row RequestUsage, accountType string) int64 {
	total := row.InputTokens + row.OutputTokens
	if accountType == string(AccountTypeClaude) {
		total += row.CachedInputTokens
	}
	if total < 0 {
		return 0
	}
	return total
}

func quantile(values []float64, fraction float64) float64 {
	if len(values) == 0 {
		return 0
	}
	copyValues := append([]float64(nil), values...)
	sort.Float64s(copyValues)
	index := int(math.Round(float64(len(copyValues)-1) * fraction))
	if index < 0 {
		index = 0
	}
	if index >= len(copyValues) {
		index = len(copyValues) - 1
	}
	return copyValues[index]
}

// inferQuotaIntelligence turns quota ticks into complete token intervals. A
// provider may report the same rounded percentage for many requests, so tokens
// accumulate until the next positive tick instead of being attributed only to
// the request that happened to cross the display boundary.
func inferQuotaIntelligence(rows []RequestUsage, metadata map[string]quotaAccountMeta, costFor func(RequestUsage) float64) ([]QuotaCapacityPoint, []ModelQuotaEfficiency, []ResetObservation) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].AccountID != rows[j].AccountID {
			return rows[i].AccountID < rows[j].AccountID
		}
		return rows[i].Timestamp.Before(rows[j].Timestamp)
	})
	states := make(map[string]*quotaState)
	capacity := make(map[string]*capacityAggregate)
	models := make(map[string]*modelAggregate)
	providerValue := make(map[string]float64)
	providerQuota := make(map[string]float64)
	resets := make([]ResetObservation, 0)

	for _, row := range rows {
		meta := metadata[row.AccountID]
		accountType := string(row.AccountType)
		if accountType == "" {
			accountType = meta.accountType
		}
		planType := strings.TrimSpace(row.PlanType)
		if planType == "" {
			planType = meta.planType
		}
		if planType == "" {
			planType = "unknown"
		}
		windowMinutes := row.SecondaryWindowMinutes
		if windowMinutes <= 0 {
			windowMinutes = meta.windowMinutes
		}
		if windowMinutes <= 0 {
			windowMinutes = 7 * 1440
		}

		state := states[row.AccountID]
		if state == nil {
			state = &quotaState{pending: make(map[string]*modelIntervalUsage)}
			states[row.AccountID] = state
		}
		// Zero is ambiguous in legacy rows (either a real reset or missing
		// telemetry), so the next positive observation confirms the rollover.
		if row.SecondaryUsedPct <= 0 {
			continue
		}
		if !state.initialized {
			state.initialized = true
			state.lastPct = row.SecondaryUsedPct
			state.expectedAt = row.SecondaryResetAt
			continue
		}

		model := strings.TrimSpace(row.Model)
		if model == "" {
			model = "unknown"
		}
		usage := state.pending[model]
		if usage == nil {
			usage = &modelIntervalUsage{}
			state.pending[model] = usage
		}
		usage.tokens += quotaThroughput(row, accountType)
		usage.requests++
		if costFor != nil {
			usage.apiValue += costFor(row)
		}

		if row.SecondaryUsedPct+0.005 < state.lastPct {
			reset := ResetObservation{
				AccountID:   hashAccountID(row.AccountID),
				AccountType: accountType,
				ObservedAt:  row.Timestamp.UTC(),
				FromUsedPct: state.lastPct * 100,
				ToUsedPct:   row.SecondaryUsedPct * 100,
				Timing:      "observed",
			}
			if !state.expectedAt.IsZero() {
				expected := state.expectedAt.UTC()
				deviation := int(row.Timestamp.Sub(expected).Minutes())
				reset.ExpectedAt = &expected
				reset.DeviationMinutes = &deviation
				switch {
				case deviation < -30:
					reset.Timing = "early"
				case deviation > 30:
					reset.Timing = "late"
				default:
					reset.Timing = "on_time"
				}
			}
			resets = append(resets, reset)
			state.pending = make(map[string]*modelIntervalUsage)
			state.lastPct = row.SecondaryUsedPct
			state.expectedAt = row.SecondaryResetAt
			continue
		}

		delta := row.SecondaryUsedPct - state.lastPct
		if delta >= 0.0001 {
			var intervalTokens, intervalRequests int64
			for _, item := range state.pending {
				intervalTokens += item.tokens
				intervalRequests += item.requests
			}
			if intervalTokens > 0 {
				week := startOfUTCWeek(row.Timestamp).Format("2006-01-02")
				key := week + "|" + accountType + "|" + planType
				agg := capacity[key]
				if agg == nil {
					agg = &capacityAggregate{point: QuotaCapacityPoint{WeekStart: week, AccountType: accountType, PlanType: planType, WindowMinutes: windowMinutes}}
					capacity[key] = agg
				}
				agg.tokens += intervalTokens
				agg.delta += delta
				agg.point.IntervalCount++
				agg.point.RequestCount += intervalRequests
				agg.estimates = append(agg.estimates, float64(intervalTokens)/delta)

				for model, item := range state.pending {
					share := float64(item.tokens) / float64(intervalTokens)
					quotaPct := delta * 100 * share
					modelKey := accountType + "|" + model
					modelAgg := models[modelKey]
					if modelAgg == nil {
						modelAgg = &modelAggregate{row: ModelQuotaEfficiency{AccountType: accountType, Model: model}}
						models[modelKey] = modelAgg
					}
					modelAgg.row.Tokens += item.tokens
					modelAgg.row.RequestCount += item.requests
					modelAgg.row.APIValue += item.apiValue
					modelAgg.row.ObservedQuotaPct += quotaPct
					modelAgg.row.IntervalCount++
					providerValue[accountType] += item.apiValue
					providerQuota[accountType] += quotaPct
				}
			}
			state.pending = make(map[string]*modelIntervalUsage)
			state.lastPct = row.SecondaryUsedPct
		}
		if !row.SecondaryResetAt.IsZero() {
			state.expectedAt = row.SecondaryResetAt
		}
	}

	capacityRows := make([]QuotaCapacityPoint, 0, len(capacity))
	for _, agg := range capacity {
		if agg.delta <= 0 {
			continue
		}
		agg.point.EstimatedWindowTokens = int64(math.Round(float64(agg.tokens) / agg.delta))
		agg.point.EstimatedWeeklyTokens = int64(math.Round(float64(agg.point.EstimatedWindowTokens) * float64(7*1440) / float64(agg.point.WindowMinutes)))
		agg.point.LowEstimateTokens = int64(math.Round(quantile(agg.estimates, 0.25)))
		agg.point.HighEstimateTokens = int64(math.Round(quantile(agg.estimates, 0.75)))
		agg.point.ObservedQuotaPct = agg.delta * 100
		agg.point.Confidence = quotaConfidence(agg.point.IntervalCount, agg.point.ObservedQuotaPct)
		capacityRows = append(capacityRows, agg.point)
	}
	sort.Slice(capacityRows, func(i, j int) bool {
		if capacityRows[i].WeekStart != capacityRows[j].WeekStart {
			return capacityRows[i].WeekStart < capacityRows[j].WeekStart
		}
		if capacityRows[i].AccountType != capacityRows[j].AccountType {
			return capacityRows[i].AccountType < capacityRows[j].AccountType
		}
		return capacityRows[i].PlanType < capacityRows[j].PlanType
	})

	modelRows := make([]ModelQuotaEfficiency, 0, len(models))
	for _, agg := range models {
		row := agg.row
		if row.ObservedQuotaPct > 0 {
			row.APIValuePerQuota = row.APIValue / row.ObservedQuotaPct
		}
		providerRate := 0.0
		if providerQuota[row.AccountType] > 0 {
			providerRate = providerValue[row.AccountType] / providerQuota[row.AccountType]
		}
		if providerRate > 0 {
			row.RelativeSubsidy = row.APIValuePerQuota / providerRate
		}
		row.Confidence = quotaConfidence(row.IntervalCount, row.ObservedQuotaPct)
		modelRows = append(modelRows, row)
	}
	sort.Slice(modelRows, func(i, j int) bool {
		if modelRows[i].RelativeSubsidy != modelRows[j].RelativeSubsidy {
			return modelRows[i].RelativeSubsidy > modelRows[j].RelativeSubsidy
		}
		return modelRows[i].APIValue > modelRows[j].APIValue
	})
	sort.Slice(resets, func(i, j int) bool { return resets[i].ObservedAt.After(resets[j].ObservedAt) })
	return capacityRows, modelRows, resets
}
