import type { AccountStats, HourlyUsage, Provider } from "./types";

export interface CapacityForecast {
  provider: Provider;
  activeAccounts: number;
  measuredAccounts: number;
  loadEquivalents: number;
  baselineAccounts: number;
  bufferedAccounts: number;
  minimumToAdd: number;
  bufferedToAdd: number;
  headroomPct: number;
  sampleAccountDays: number;
  earliestFullMinutes: number | null;
}

export interface DemandSummary {
  current24: number;
  previous24: number;
  deltaPct: number;
  averageDay7d: number;
  peakHour7d: number;
  p95Hour7d: number;
  peakFactor: number;
}

export interface DailyDemandPoint {
  date: string;
  demand: number;
  trend: number;
}

function throughput(row: Pick<HourlyUsage, "account_type" | "input_tokens" | "cached_tokens" | "output_tokens">) {
  return row.input_tokens + row.output_tokens + (row.account_type === "claude" ? row.cached_tokens : 0);
}

export function capacityForecasts(accounts: AccountStats[], bufferRatio = 0.2): CapacityForecast[] {
  const providers = [...new Set(accounts.map((account) => account.type))];
  return providers.flatMap((provider) => {
    const rows = accounts.filter((account) => account.type === provider);
    const activeAccounts = rows.filter((account) => account.status === "healthy" || account.status === "degraded").length;
    const measured = rows.flatMap((account) => {
      if (account.status === "dead" || !account.secondary_window_available || account.secondary_window_used_pct < 0) return [];
      const windowMinutes = account.secondary_window_minutes > 0 ? account.secondary_window_minutes : 7 * 1440;
      const elapsedMinutes = windowMinutes - account.secondary_reset_minutes;
      if (elapsedMinutes <= 0) return [];
      const loadEquivalents = (account.secondary_window_used_pct / 100) * (windowMinutes / elapsedMinutes);
      const burnPerMinute = account.secondary_window_used_pct / elapsedMinutes;
      const fullInMinutes = burnPerMinute > 0 ? (100 - account.secondary_window_used_pct) / burnPerMinute : Number.POSITIVE_INFINITY;
      return [{ loadEquivalents, elapsedMinutes, fullInMinutes, resetMinutes: account.secondary_reset_minutes }];
    });
    if (measured.length === 0) return [];
    const loadEquivalents = measured.reduce((sum, row) => sum + row.loadEquivalents, 0);
    const baselineAccounts = Math.ceil(loadEquivalents);
    const bufferedAccounts = Math.max(baselineAccounts, Math.ceil(loadEquivalents * (1 + bufferRatio)));
    const earlyFullTimes = measured.filter((row) => row.fullInMinutes < row.resetMinutes).map((row) => row.fullInMinutes);
    return [{
      provider,
      activeAccounts,
      measuredAccounts: measured.length,
      loadEquivalents,
      baselineAccounts,
      bufferedAccounts,
      minimumToAdd: Math.max(0, baselineAccounts - activeAccounts),
      bufferedToAdd: Math.max(0, bufferedAccounts - activeAccounts),
      headroomPct: activeAccounts > 0 ? ((activeAccounts - loadEquivalents) / activeAccounts) * 100 : -100,
      sampleAccountDays: measured.reduce((sum, row) => sum + row.elapsedMinutes / 1440, 0),
      earliestFullMinutes: earlyFullTimes.length ? Math.min(...earlyFullTimes) : null,
    }];
  }).sort((a, b) => b.bufferedToAdd - a.bufferedToAdd || b.loadEquivalents - a.loadEquivalents);
}

function hourlyTotals(hourly: HourlyUsage[]) {
  const totals = new Map<string, number>();
  for (const row of hourly) totals.set(row.hour, (totals.get(row.hour) ?? 0) + throughput(row));
  return [...totals.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([hour, total]) => ({ hour, total }));
}

export function demandSummary(hourly: HourlyUsage[]): DemandSummary {
  const totals = hourlyTotals(hourly).map((row) => row.total);
  const current24 = totals.slice(-24).reduce((sum, value) => sum + value, 0);
  const previous24 = totals.slice(-48, -24).reduce((sum, value) => sum + value, 0);
  const last7d = totals.slice(-168);
  const sorted7d = [...last7d].sort((a, b) => a - b);
  const p95Hour7d = sorted7d.length ? sorted7d[Math.min(sorted7d.length - 1, Math.floor(sorted7d.length * 0.95))] : 0;
  const averageHour7d = last7d.length ? last7d.reduce((sum, value) => sum + value, 0) / last7d.length : 0;
  return {
    current24,
    previous24,
    deltaPct: previous24 ? ((current24 - previous24) / previous24) * 100 : 0,
    averageDay7d: averageHour7d * 24,
    peakHour7d: sorted7d.at(-1) ?? 0,
    p95Hour7d,
    peakFactor: averageHour7d ? p95Hour7d / averageHour7d : 0,
  };
}

export function dailyDemandSeries(hourly: HourlyUsage[]): DailyDemandPoint[] {
  const days = new Map<string, { demand: number; hours: number }>();
  for (const row of hourlyTotals(hourly)) {
    const date = row.hour.slice(0, 10);
    const day = days.get(date) ?? { demand: 0, hours: 0 };
    day.demand += row.total;
    day.hours++;
    days.set(date, day);
  }
  const completeDays = [...days.entries()].filter(([, day]) => day.hours >= 20).sort(([a], [b]) => a.localeCompare(b));
  return completeDays.map(([date, day], index) => {
    const demand = day.demand;
    const window = completeDays.slice(Math.max(0, index - 2), index + 1);
    return { date, demand, trend: window.reduce((sum, row) => sum + row[1].demand, 0) / window.length };
  });
}
