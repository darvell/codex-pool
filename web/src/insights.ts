import type { AccountStats, HourlyUsage, ModelDailyUsage, OriginWeeklyUsage, Provider } from "./types";

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

export interface AccountFlow {
  id: string;
  provider: Provider;
  usedPct: number;
  projectedFinalPct: number;
  strandedPct: number;
  resetMinutes: number;
  state: "exhausts" | "tight" | "balanced" | "stranded";
}

export interface WeeklyQuotaEstimate {
  elapsedMinutes: number;
  burnPerDay: number;
  loadEquivalent: number;
  projectedFinalPct: number;
  fullInMinutes: number;
}

// The provider reports quota usage in percentage-point increments. Until at
// least one percentage point of the window's even-burn budget has elapsed, a
// non-zero reading is mostly quantization noise: 1% after 23 minutes in a
// seven-day window naively becomes 62.6%/day. Acquire a longer baseline before
// extrapolating it into routing-capacity advice.
export function weeklyQuotaEstimate(account: Pick<AccountStats,
  "secondary_window_used_pct" | "secondary_reset_minutes" | "secondary_window_minutes"
>): WeeklyQuotaEstimate | null {
  const windowMinutes = account.secondary_window_minutes > 0 ? account.secondary_window_minutes : 7 * 1440;
  const elapsedMinutes = windowMinutes - account.secondary_reset_minutes;
  const minimumElapsedMinutes = windowMinutes / 100;
  if (elapsedMinutes < minimumElapsedMinutes || elapsedMinutes > windowMinutes || account.secondary_window_used_pct < 0) return null;

  const burnPerMinute = account.secondary_window_used_pct / elapsedMinutes;
  const loadEquivalent = (account.secondary_window_used_pct / 100) * (windowMinutes / elapsedMinutes);
  return {
    elapsedMinutes,
    burnPerDay: burnPerMinute * 1440,
    loadEquivalent,
    projectedFinalPct: loadEquivalent * 100,
    fullInMinutes: burnPerMinute > 0 ? (100 - account.secondary_window_used_pct) / burnPerMinute : Number.POSITIVE_INFINITY,
  };
}

export interface PeakCell {
  day: number;
  hour: number;
  averageTokens: number;
  averageRequests: number;
}

export interface OriginConcentration {
  week: string;
  origins: number;
  topOriginShare: number;
  topThreeShare: number;
  gini: number;
}

export interface ModelMixRow {
  model: string;
  provider: Provider | "unknown";
  tokens: number;
  requests: number;
  apiValue: number;
  share: number;
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
      const estimate = weeklyQuotaEstimate(account);
      if (!estimate) return [];
      return [{ loadEquivalents: estimate.loadEquivalent, elapsedMinutes: estimate.elapsedMinutes, fullInMinutes: estimate.fullInMinutes, resetMinutes: account.secondary_reset_minutes }];
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

export function accountFlow(accounts: AccountStats[]): AccountFlow[] {
  return accounts.flatMap((account) => {
    if (account.status === "dead" || !account.secondary_window_available) return [];
    const estimate = weeklyQuotaEstimate(account);
    if (!estimate) return [];
    const projectedFinalPct = estimate.projectedFinalPct;
    const strandedPct = Math.max(0, 100 - projectedFinalPct);
    const state: AccountFlow["state"] = projectedFinalPct >= 100 ? "exhausts"
      : projectedFinalPct >= 85 ? "tight"
        : projectedFinalPct < 55 ? "stranded"
          : "balanced";
    return [{
      id: account.id,
      provider: account.type,
      usedPct: account.secondary_window_used_pct,
      projectedFinalPct,
      strandedPct,
      resetMinutes: account.secondary_reset_minutes,
      state,
    }];
  }).sort((a, b) => b.projectedFinalPct - a.projectedFinalPct);
}

export function peakHeatmap(hourly: HourlyUsage[]): PeakCell[] {
  const totals = hourlyTotals(hourly);
  if (totals.length === 0) return [];
  const tokenByHour = new Map(totals.map((row) => [row.hour, row.total]));
  const requestsByHour = new Map<string, number>();
  for (const row of hourly) requestsByHour.set(row.hour, (requestsByHour.get(row.hour) ?? 0) + row.request_count);
  const first = new Date(`${totals[0].hour}:00:00Z`);
  const last = new Date(`${totals.at(-1)!.hour}:00:00Z`);
  const buckets = new Map<string, { tokens: number; requests: number; samples: number }>();
  for (let cursor = first.valueOf(); cursor <= last.valueOf(); cursor += 60 * 60 * 1000) {
    const date = new Date(cursor);
    const key = `${date.getUTCDay()}|${date.getUTCHours()}`;
    const hour = date.toISOString().slice(0, 13);
    const bucket = buckets.get(key) ?? { tokens: 0, requests: 0, samples: 0 };
    bucket.tokens += tokenByHour.get(hour) ?? 0;
    bucket.requests += requestsByHour.get(hour) ?? 0;
    bucket.samples++;
    buckets.set(key, bucket);
  }
  const cells: PeakCell[] = [];
  for (let day = 0; day < 7; day++) {
    for (let hour = 0; hour < 24; hour++) {
      const bucket = buckets.get(`${day}|${hour}`) ?? { tokens: 0, requests: 0, samples: 1 };
      cells.push({ day, hour, averageTokens: bucket.tokens / bucket.samples, averageRequests: bucket.requests / bucket.samples });
    }
  }
  return cells;
}

export function originConcentration(rows: OriginWeeklyUsage[]): OriginConcentration {
  const week = rows.reduce((latest, row) => row.week_start > latest ? row.week_start : latest, "");
  const totals = new Map<string, number>();
  for (const row of rows.filter((item) => item.week_start === week)) {
    totals.set(row.origin_id, (totals.get(row.origin_id) ?? 0) + throughput(row));
  }
  const values = [...totals.values()].sort((a, b) => b - a);
  const total = values.reduce((sum, value) => sum + value, 0);
  const ascending = [...values].sort((a, b) => a - b);
  const weighted = ascending.reduce((sum, value, index) => sum + (index + 1) * value, 0);
  const gini = total && ascending.length > 1
    ? (2 * weighted) / (ascending.length * total) - (ascending.length + 1) / ascending.length
    : 0;
  return {
    week,
    origins: values.length,
    topOriginShare: total ? (values[0] ?? 0) / total * 100 : 0,
    topThreeShare: total ? values.slice(0, 3).reduce((sum, value) => sum + value, 0) / total * 100 : 0,
    gini,
  };
}

export function modelMix(rows: ModelDailyUsage[], days = 14): ModelMixRow[] {
  const dates = [...new Set(rows.map((row) => row.date))].sort();
  const included = new Set(dates.slice(-days));
  const models = new Map<string, Omit<ModelMixRow, "share">>();
  for (const row of rows.filter((item) => included.has(item.date))) {
    const model = row.model || "unknown";
    const key = `${row.account_type}|${model}`;
    const aggregate = models.get(key) ?? { model, provider: row.account_type, tokens: 0, requests: 0, apiValue: 0 };
    aggregate.tokens += throughput(row);
    aggregate.requests += row.request_count;
    aggregate.apiValue += row.cost_usd;
    models.set(key, aggregate);
  }
  const total = [...models.values()].reduce((sum, row) => sum + row.tokens, 0);
  return [...models.values()]
    .map((row) => ({ ...row, share: total ? row.tokens / total * 100 : 0 }))
    .sort((a, b) => b.tokens - a.tokens);
}
