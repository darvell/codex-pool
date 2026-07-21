import { describe, expect, it } from "vitest";
import { accountFlow, capacityForecasts, dailyDemandSeries, demandSummary, modelMix, originConcentration, peakHeatmap, weeklyQuotaEstimate } from "./insights";
import type { AccountStats, HourlyUsage, ModelDailyUsage, OriginWeeklyUsage } from "./types";

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
  it("does not extrapolate a new window before one percentage point of budget has elapsed", () => {
    const fresh = account({ secondary_window_used_pct: 1, secondary_reset_minutes: 10050 });
    expect(weeklyQuotaEstimate(fresh)).toBeNull();
    expect(capacityForecasts([fresh])).toEqual([]);
  });

  it("starts forecasting once the quota reading has enough time resolution", () => {
    const established = account({ secondary_window_used_pct: 2, secondary_reset_minutes: 9960 });
    const estimate = weeklyQuotaEstimate(established);
    expect(estimate?.burnPerDay).toBeCloseTo(24);
    expect(estimate?.projectedFinalPct).toBeCloseTo(168);
  });

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

describe("resource dashboards", () => {
  it("omits acquiring windows from account-flow classifications", () => {
    expect(accountFlow([
      account({ id: "fresh", secondary_window_used_pct: 1, secondary_reset_minutes: 10050 }),
    ])).toEqual([]);
  });

  it("identifies accounts that exhaust and accounts with stranded capacity", () => {
    const rows = accountFlow([
      account({ id: "hot", secondary_window_used_pct: 45 }),
      account({ id: "cold", secondary_window_used_pct: 5 }),
    ]);
    expect(rows.find((row) => row.id === "hot")?.state).toBe("exhausts");
    expect(rows.find((row) => row.id === "cold")?.state).toBe("stranded");
  });

  it("builds a complete weekday-hour heatmap including zero-demand slots", () => {
    const cells = peakHeatmap([
      { hour: "2026-07-13T10", account_type: "codex", input_tokens: 100, cached_tokens: 0, output_tokens: 0, reasoning_tokens: 0, billable_tokens: 100, request_count: 1 },
      { hour: "2026-07-20T10", account_type: "codex", input_tokens: 300, cached_tokens: 0, output_tokens: 0, reasoning_tokens: 0, billable_tokens: 300, request_count: 1 },
    ]);
    expect(cells).toHaveLength(168);
    expect(cells.find((cell) => cell.day === 1 && cell.hour === 10)?.averageTokens).toBe(200);
  });

  it("measures current-week origin concentration", () => {
    const rows: OriginWeeklyUsage[] = [70, 20, 10].map((tokens, index) => ({
      week_start: "2026-07-13", origin_id: `origin-${index}`, account_id: "acct", account_type: "codex",
      input_tokens: tokens, cached_tokens: 0, output_tokens: 0, reasoning_tokens: 0, billable_tokens: tokens, request_count: 1,
    }));
    const concentration = originConcentration(rows);
    expect(concentration.topOriginShare).toBe(70);
    expect(concentration.topThreeShare).toBe(100);
  });

  it("ranks model demand across the selected recent days", () => {
    const rows: ModelDailyUsage[] = [
      { date: "2026-07-16", account_type: "codex", model: "large", input_tokens: 200, cached_tokens: 0, output_tokens: 0, reasoning_tokens: 0, request_count: 1, cost_usd: 2 },
      { date: "2026-07-16", account_type: "codex", model: "small", input_tokens: 100, cached_tokens: 0, output_tokens: 0, reasoning_tokens: 0, request_count: 2, cost_usd: 1 },
    ];
    expect(modelMix(rows)[0].model).toBe("large");
    expect(modelMix(rows)[0].share).toBeCloseTo(200 / 3);
  });
});
