package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

type SignalEconomicsPoint struct {
	Date                        string             `json:"date"`
	DailyAPIValue               float64            `json:"daily_api_value"`
	CumulativeAPIValue          float64            `json:"cumulative_api_value"`
	CumulativeSubscriptionSpend float64            `json:"cumulative_subscription_spend"`
	ProviderAPIValue            map[string]float64 `json:"provider_api_value"`
}

type SignalAnalyticsResponse struct {
	GeneratedAt       time.Time              `json:"generated_at"`
	OriginDataSince   time.Time              `json:"origin_data_since"`
	Economics         []SignalEconomicsPoint `json:"economics"`
	EconomicsSummary  economicsSummary       `json:"economics_summary"`
	Hourly            []UserHourlyUsage      `json:"hourly"`
	OriginWeekly      []OriginWeeklyUsage    `json:"origin_weekly"`
	ModelDaily        []ModelDailyUsageEntry `json:"model_daily"`
	QuotaCapacity     []QuotaCapacityPoint   `json:"quota_capacity"`
	ModelEfficiency   []ModelQuotaEfficiency `json:"model_efficiency"`
	ResetObservations []ResetObservation     `json:"reset_observations"`
	QuotaGeneratedAt  time.Time              `json:"quota_generated_at,omitempty"`
}

// handleSignalAnalytics returns chart-ready time series that preserve the
// attribution boundaries needed by the signal-room UI. It intentionally keeps
// account identifiers hashed; raw origin metadata remains admin-only.
func (h *proxyHandler) handleSignalAnalytics(w http.ResponseWriter, r *http.Request) {
	weeks := 6
	if raw := r.URL.Query().Get("weeks"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			weeks = min(parsed, 12)
		}
	}

	response := SignalAnalyticsResponse{
		GeneratedAt:       time.Now().UTC(),
		Economics:         []SignalEconomicsPoint{},
		Hourly:            []UserHourlyUsage{},
		OriginWeekly:      []OriginWeeklyUsage{},
		ModelDaily:        []ModelDailyUsageEntry{},
		QuotaCapacity:     []QuotaCapacityPoint{},
		ModelEfficiency:   []ModelQuotaEfficiency{},
		ResetObservations: []ResetObservation{},
	}
	if h.store != nil {
		response.OriginDataSince = response.GeneratedAt.Add(-h.store.retention)
		originWeekly, err := h.store.getOriginWeeklyUsage(weeks)
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, "failed to build origin drain matrix")
			return
		}
		response.OriginWeekly = originWeekly

		hourly, err := h.store.getGlobalHourlyUsage(24 * 14)
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, "failed to load burn velocity")
			return
		}
		response.Hourly = hourly

		quota := h.quotaIntelligenceSnapshot()
		response.QuotaCapacity = quota.capacity
		response.ModelEfficiency = quota.modelEfficiency
		response.ResetObservations = quota.resetEvents
		response.QuotaGeneratedAt = quota.updatedAt
	}

	if h.analyticsStore != nil {
		if err := h.analyticsStore.syncSubscriptionRates(h.pool.allAccounts(), response.GeneratedAt); err != nil {
			respondJSONError(w, http.StatusInternalServerError, "failed to record subscription state")
			return
		}
		economics, summary, err := h.analyticsStore.economics(response.GeneratedAt)
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, "failed to build subscription economics")
			return
		}
		response.Economics = economics
		response.EconomicsSummary = summary
		modelDaily, err := h.analyticsStore.getModelDailyUsage(42)
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, "failed to build model demand mix")
			return
		}
		response.ModelDaily = modelDaily
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
