import { describe, expect, it } from "vitest";
import { capacityForecasts, dailyDemandSeries, demandSummary } from "./insights";
import type { AccountStats, HourlyUsage } from "./types";

function account(overrides: Partial<AccountStats>): AccountStats {
  return {
    id: "account",
    type: "codex",
    plan_type: "pro",
    status: "healthy",
    penalty: 0,
    primary_window_used_pct: 0,
    secondary_window_used_pct: 0,
    primary_window_available: false,
    secondary_window_available: true,
    primary_reset_minutes: 0,
    secondary_reset_minutes: 7830,
    primary_window_minutes: 0,
    secondary_window_minutes: 10080,
    primary_pace_ratio: 0,
    secondary_pace_ratio: 0,
    total_input_tokens: 0,
    total_cached_tokens: 0,
    total_output_tokens: 0,
    total_reasoning_tokens: 0,
    total_billable_tokens: 0,
    cache_hit_rate_pct: 0,
    score: 1,
    is_primary: false,
    subscription_cost_monthly: 0,
    subscription_spend: 0,
    subscription_billing_cycles: 0,
    subscription_label: "",
    api_cost_estimate: 0,
    api_cost_last_30d: 0,
    roi: 0,
    ...overrides,
  };
}

describe("capacityForecasts", () => {
  it("converts weekly quota drain into account-equivalent demand", () => {
    const forecast = capacityForecasts([
      account({ id: "one", secondary_window_used_pct: 45 }),
      account({ id: "two", secondary_window_used_pct: 43 }),
      account({ id: "three", secondary_window_used_pct: 43 }),
    ])[0];
    expect(forecast.loadEquivalents).toBeCloseTo(5.87, 1);
    expect(forecast.baselineAccounts).toBe(6);
    expect(forecast.minimumToAdd).toBe(3);
    expect(forecast.bufferedAccounts).toBe(8);
    expect(forecast.bufferedToAdd).toBe(5);
    expect(forecast.earliestFullMinutes).toBeLessThan(2 * 1440);
  });

  it("uses a seven-day fallback when a provider omits its weekly window length", () => {
    const forecast = capacityForecasts([account({ type: "claude", secondary_window_minutes: 0, secondary_reset_minutes: 3960, secondary_window_used_pct: 8 })])[0];
    expect(forecast.loadEquivalents).toBeCloseTo(0.13, 1);
    expect(forecast.minimumToAdd).toBe(0);
    expect(forecast.earliestFullMinutes).toBeNull();
  });

  it("keeps idle accounts with reported weekly telemetry in the model", () => {
    const forecast = capacityForecasts([account({ secondary_window_used_pct: 0 })])[0];
    expect(forecast.measuredAccounts).toBe(1);
    expect(forecast.loadEquivalents).toBe(0);
    expect(forecast.minimumToAdd).toBe(0);
  });
});

describe("demand trend", () => {
  const hourly = Array.from({ length: 48 }, (_, index): HourlyUsage => ({
    hour: `2026-07-${String(16 + Math.floor(index / 24)).padStart(2, "0")}T${String(index % 24).padStart(2, "0")}:00:00Z`,
    account_type: "codex",
    input_tokens: index < 24 ? 100 : 200,
    cached_tokens: 0,
    output_tokens: 0,
    reasoning_tokens: 0,
    billable_tokens: 0,
    request_count: 1,
  }));

  it("compares the latest complete 24 hours with the prior 24 hours", () => {
    const summary = demandSummary(hourly);
    expect(summary.current24).toBe(4800);
    expect(summary.previous24).toBe(2400);
    expect(summary.deltaPct).toBe(100);
  });

  it("builds daily demand with a rolling trend", () => {
    expect(dailyDemandSeries(hourly)).toEqual([
      { date: "2026-07-16", demand: 2400, trend: 2400 },
      { date: "2026-07-17", demand: 4800, trend: 3600 },
    ]);
  });
});
