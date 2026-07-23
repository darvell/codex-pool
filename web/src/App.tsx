import { type CSSProperties, type FormEvent, type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Grid,
  Legend,
  Line,
  LineChart,
  Sparkline,
  Tooltip,
  XAxis,
  YAxis,
  type ChartConfig,
  type DitherColor,
} from "./components/dither-kit";
import {
  claim,
	  antigravityOAuthStatus,
  clearFriendSession,
  contributeAPIKey,
  contributeGrok,
  exchangeAccountOAuth,
	  exchangeAntigravityOAuth,
  loadAdminAccounts,
	loadLiveCuteCodeSettings,
	loadLivePiModels,
	loadModelCatalog,
  loadPoolStats,
  loadSignalAnalytics,
  lockOperator,
  mutateAccount,
  reloadAccounts,
  storedAdminToken,
  storedFriendCode,
  storedFriendEmail,
  storedFriendSession,
  startAccountOAuth,
	  startAntigravityOAuth,
  unlockOperator,
} from "./api";
import {
  accountFlow,
  capacityForecasts,
  dailyDemandSeries,
  demandSummary,
  modelMix,
  originConcentration,
  peakHeatmap,
  weeklyQuotaEstimate,
  type AccountFlow,
  type CapacityForecast,
} from "./insights";
import type {
  AccountStats,
  AdminAccount,
  FriendSession,
  HourlyUsage,
	ModelDailyUsage,
	ModelDescriptor,
  ModelQuotaEfficiency,
  OriginWeeklyUsage,
  PoolStats,
  Provider,
  QuotaCapacityPoint,
  ResetObservation,
  SignalAnalytics,
} from "./types";

type View = "pulse" | "insights" | "usage" | "accounts" | "models" | "setup";

const PROVIDERS: Record<Provider, { label: string; color: string; dither: DitherColor; glyph: string }> = {
  codex: { label: "Codex", color: "#39e75f", dither: "green", glyph: "◎" },
  claude: { label: "Claude", color: "#a678ff", dither: "purple", glyph: "◉" },
  gemini: { label: "Gemini", color: "#27d8d1", dither: "cyan", glyph: "✦" },
	  antigravity: { label: "Antigravity", color: "#70d6ff", dither: "cyan", glyph: "✧" },
  kimi: { label: "Kimi", color: "#3f8cff", dither: "blue", glyph: "◈" },
  minimax: { label: "MiniMax", color: "#ffb23f", dither: "orange", glyph: "◇" },
  zai: { label: "Z.ai", color: "#ff5454", dither: "red", glyph: "◆" },
  xiaomi: { label: "Xiaomi", color: "#ff7b2d", dither: "orange", glyph: "◫" },
  grok: { label: "Grok", color: "#86efff", dither: "cyan", glyph: "⌁" },
};

const compact = new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 });
const money = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 });
const preciseMoney = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 2 });

function formatTokens(value: number) {
  return compact.format(value || 0).replace("T", "T");
}

// Burn is account throughput, not API-price-equivalent tokens. Codex-style
// usage includes cache reads inside input_tokens; Anthropic reports them as a
// separate field, so only Claude needs the cached count added explicitly.
function tokenThroughput(row: { account_type: Provider | "unknown"; input_tokens: number; cached_tokens: number; output_tokens: number }) {
  return row.input_tokens + row.output_tokens + (row.account_type === "claude" ? row.cached_tokens : 0);
}

function accountThroughput(account: AccountStats) {
  return account.total_input_tokens + account.total_output_tokens + (account.type === "claude" ? account.total_cached_tokens : 0);
}

function formatReset(minutes: number) {
  if (!minutes) return "now";
  const days = Math.floor(minutes / 1440);
  const hours = Math.floor((minutes % 1440) / 60);
  return days ? `${days}d ${hours}h` : `${hours}h ${minutes % 60}m`;
}

function originHandle(originID: string) {
  return originID.replace(/^ip_/, "").slice(0, 4).toUpperCase();
}

function formatAdmission(value?: string) {
  if (!value) return "UNKNOWN";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "UNKNOWN" : date.toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" });
}

function paceLabel(paceRatio?: number) {
  if (!paceRatio || paceRatio <= 0) return "PACE ACQUIRING";
  return paceRatio >= 1.1 ? `${paceRatio.toFixed(1)}× FAST` : `${paceRatio.toFixed(1)}× SAFE`;
}

function WeeklyPace({ account }: { account: AccountStats }) {
  if (!account.secondary_window_available) {
    return <span className="quota-limit unavailable">N/A</span>;
  }
  const windowMinutes = account.secondary_window_minutes > 0 ? account.secondary_window_minutes : 7 * 1440;
  const windowDays = windowMinutes / 1440;
  const budgetPerDay = 100 / windowDays;
  const estimate = weeklyQuotaEstimate(account);
  if (!estimate || account.secondary_window_used_pct <= 0) {
    return (
      <span className="quota-limit acquiring" aria-label={`Weekly budget ${budgetPerDay.toFixed(1)} percent per day; not enough history to forecast`}>
        <b>—</b><small>BUDGET {budgetPerDay.toFixed(1)}%/D</small><em>ACQUIRING RATE</em>
      </span>
    );
  }
  const exhaustsEarly = estimate.fullInMinutes < account.secondary_reset_minutes;
  const forecast = exhaustsEarly ? `FULL IN ${formatReset(Math.max(1, Math.floor(estimate.fullInMinutes)))}` : "LASTS TO RESET";
  return (
    <span className={classNames("quota-limit", exhaustsEarly ? "fast" : "safe")} aria-label={`Burning ${estimate.burnPerDay.toFixed(1)} percent per day against a ${budgetPerDay.toFixed(1)} percent daily budget. ${forecast.toLowerCase()}.`}>
      <b>{estimate.burnPerDay.toFixed(1)}%/D</b><small>BUDGET {budgetPerDay.toFixed(1)}</small><em>{forecast}</em>
    </span>
  );
}

function ResetWindow({ label, available, used, resetMinutes, paceRatio, showPace = false, compact = false }: { label: string; available: boolean; used: number; resetMinutes: number; paceRatio?: number; showPace?: boolean; compact?: boolean }) {
  if (!available) return <span className={classNames("reset-window unavailable", compact && "compact")}><b>{label}</b><small>NOT REPORTED</small></span>;
  if (compact) return <span className="reset-window compact" aria-label={`${label} ${used.toFixed(0)}%, resets in ${formatReset(resetMinutes)}`}><b>{label}</b><strong>{used.toFixed(0)}%</strong><small>{formatReset(resetMinutes)}</small></span>;
  return <span className="reset-window"><b>{label} {used.toFixed(0)}%</b><small>RESETS {formatReset(resetMinutes)}{showPace ? ` // ${paceLabel(paceRatio)}` : ""}</small></span>;
}

function formatResetCreditExpiry(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "UNKNOWN EXPIRATION";
  const absolute = new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  }).format(date);
  const remainingMinutes = Math.floor((date.valueOf() - Date.now()) / 60_000);
  if (remainingMinutes <= 0) return `${absolute} // EXPIRED`;
  const days = Math.floor(remainingMinutes / 1440);
  const hours = Math.floor((remainingMinutes % 1440) / 60);
  const minutes = remainingMinutes % 60;
  const relative = days > 0 ? `${days}D ${hours}H` : hours > 0 ? `${hours}H ${minutes}M` : `${minutes}M`;
  return `${absolute} // IN ${relative}`;
}

function ResetCreditExpirations({ account }: { account: AccountStats }) {
  const expirations = account.reset_credit_expirations ?? [];
  const count = account.reset_credits_available ?? expirations.length;
  const missing = Math.max(0, count - expirations.length);
  return (
    <>
      {expirations.map((expiry, index) => <span key={`${expiry}-${index}`}>{formatResetCreditExpiry(expiry)}</span>)}
      {missing > 0 && <span>{missing} EXPIRATION {missing === 1 ? "IS" : "ARE"} NOT REPORTED</span>}
      {count === 0 && <span>NO BANKED RESETS</span>}
    </>
  );
}

function ResetCreditBadge({ account }: { account: AccountStats }) {
  if (account.type !== "codex" || !account.reset_credits_known) return <span className="reset-credit unknown">—</span>;
  const count = account.reset_credits_available ?? 0;
  return (
    <span className="reset-credit" aria-label={`${count} banked usage reset${count === 1 ? "" : "s"}; select account for expiration details`}>
      <b aria-hidden="true">↻</b><strong>{count}</strong>
      <span className="reset-credit-popover" role="tooltip">
        <em>{count} BANKED USAGE RESET{count === 1 ? "" : "S"}</em>
        <ResetCreditExpirations account={account} />
      </span>
    </span>
  );
}

function classNames(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(" ");
}

export function App() {
  const [session, setSession] = useState<FriendSession | null>(storedFriendSession());
  const [booting, setBooting] = useState(Boolean(storedFriendCode() && storedFriendSession()));
  const [view, setView] = useState<View>("pulse");
  const [stats, setStats] = useState<PoolStats | null>(null);
  const [signal, setSignal] = useState<SignalAnalytics | null>(null);
	const [models, setModels] = useState<ModelDescriptor[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [operatorToken, setOperatorToken] = useState(storedAdminToken());
  const [adminAccounts, setAdminAccounts] = useState<AdminAccount[]>([]);

  const refresh = useCallback(async () => {
    if (!storedFriendCode()) return;
    setLoading(true);
    try {
	  const [nextStats, nextSignal, nextCatalog] = await Promise.all([loadPoolStats(), loadSignalAnalytics(), loadModelCatalog()]);
      setStats(nextStats);
      setSignal(nextSignal);
	  setModels(nextCatalog.models);
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Signal lost");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const savedCode = storedFriendCode();
    if (!savedCode || !session) {
      setBooting(false);
      return;
    }
    claim(savedCode, storedFriendEmail())
      .then((fresh) => {
        setSession(fresh);
        return refresh();
      })
      .catch(() => {
        clearFriendSession();
        setSession(null);
      })
      .finally(() => setBooting(false));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!session) return;
    refresh();
    const timer = window.setInterval(refresh, 30_000);
    return () => window.clearInterval(timer);
  }, [session, refresh]);

  useEffect(() => {
    if (!operatorToken) return;
    loadAdminAccounts()
      .then(setAdminAccounts)
      .catch(() => {
        lockOperator();
        setOperatorToken("");
        setAdminAccounts([]);
      });
  }, [operatorToken]);

  if (booting) return <BootScreen />;
  if (!session) {
    return <AccessGate onAccess={(next) => { setSession(next); refresh(); }} />;
  }

  const signOut = () => {
    clearFriendSession();
    setSession(null);
    setStats(null);
    setSignal(null);
  };

  return (
    <div className="signal-app">
      <SignalNoise />
      <Header
        stats={stats}
        loading={loading}
        operator={Boolean(operatorToken)}
        onRefresh={refresh}
        onLock={() => { lockOperator(); setOperatorToken(""); setAdminAccounts([]); }}
      />
      <div className="app-grid">
        <Navigation view={view} onChange={setView} onSignOut={signOut} />
        <main className="signal-main" id="main-content">
          {error && <div className="signal-error" role="alert">SIGNAL INTERRUPTED // {error}</div>}
          {view === "pulse" && <Pulse stats={stats} signal={signal} onAccounts={() => setView("accounts")} />}
          {view === "insights" && <Insights stats={stats} signal={signal} onAccounts={() => setView("accounts")} />}
          {view === "usage" && <Usage stats={stats} signal={signal} session={session} />}
          {view === "accounts" && (
            <Accounts
              stats={stats}
              adminAccounts={adminAccounts}
              operatorToken={operatorToken}
              onUnlocked={(token, accounts) => { setOperatorToken(token); setAdminAccounts(accounts); }}
              onAccountsChanged={async () => {
				if (!operatorToken) {
				  await refresh();
				  return;
				}
				const [accounts] = await Promise.all([loadAdminAccounts(), refresh()]);
				setAdminAccounts(accounts);
              }}
            />
          )}
		  {view === "models" && <Models models={models} />}
          {view === "setup" && <Setup session={session} />}
        </main>
      </div>
    </div>
  );
}

function SignalNoise() {
  return <div className="signal-noise" aria-hidden="true" />;
}

function BootScreen() {
  return (
    <div className="boot-screen">
      <div className="heraldic-mark">⌁</div>
      <div className="boot-title">AI POOL</div>
      <div className="boot-status">REACQUIRING SIGNAL</div>
    </div>
  );
}

function AccessGate({ onAccess }: { onAccess: (session: FriendSession) => void }) {
  const [code, setCode] = useState(storedFriendCode());
  const [email, setEmail] = useState(storedFriendEmail());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      onAccess(await claim(code.trim(), email.trim()));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Access denied");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="access-gate">
      <SignalNoise />
      <div className="access-frame">
        <div className="access-calibration" aria-hidden="true">A.00 / PRIVATE FREQUENCY</div>
        <img src="/hero.webp" alt="AI Pool heraldic mark" className="access-mark" />
        <div className="access-name">Friends of PP</div>
        <h1>Full-Spectrum Signal Room</h1>
        <p>For the few who know. The charts are nosy.</p>
        <form onSubmit={submit} className="access-form">
          <label>
            <span>Friend code</span>
            <input value={code} onChange={(event) => setCode(event.target.value)} required autoFocus autoComplete="off" />
          </label>
          <label>
            <span>Email <i>optional</i></span>
            <input value={email} onChange={(event) => setEmail(event.target.value)} type="email" autoComplete="email" />
          </label>
          {error && <div className="access-error" role="alert">{error}</div>}
          <button className="gold-button" disabled={busy}>{busy ? "TUNING…" : "ENTER POOL"}</button>
        </form>
      </div>
    </div>
  );
}

function Header({ stats, loading, operator, onRefresh, onLock }: {
  stats: PoolStats | null;
  loading: boolean;
  operator: boolean;
  onRefresh: () => void;
  onLock: () => void;
}) {
  const generated = stats ? new Date(stats.generated_at) : null;
  return (
    <header className="command-rail">
      <a href="#main-content" className="skip-link">Skip to data</a>
      <div className="command-brand">
        <img src="/hero.webp" alt="" className="command-mark" />
        <div className="command-brand-copy">
          <span>AI POOL</span>
          <em>FULL-SPECTRUM SIGNAL ROOM</em>
        </div>
      </div>
      <div className="rail-readouts">
        <span><i className="lamp live" /> POOL {stats?.active_accounts ?? "–"}/{stats?.total_accounts ?? "–"}</span>
        <span>24H {formatTokens(stats?.last_24h_tokens ?? 0)}</span>
        <span>{generated ? generated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "--:--:--"}</span>
        <button onClick={onRefresh} disabled={loading}>{loading ? "SYNCING" : "SYNC"}</button>
        {operator && <button className="operator-live" onClick={onLock}>OPERATOR LIVE // LOCK</button>}
      </div>
    </header>
  );
}

function Navigation({ view, onChange, onSignOut }: { view: View; onChange: (view: View) => void; onSignOut: () => void }) {
  const items: Array<[View, string, string]> = [
    ["pulse", "PULSE", "⌁"],
    ["insights", "INSIGHTS", "△"],
    ["usage", "USAGE", "╱"],
    ["accounts", "ACCOUNTS", "▦"],
	["models", "MODELS", "◇"],
    ["setup", "SETUP", "⌘"],
  ];
  return (
    <nav className="signal-nav" aria-label="Signal room">
      <div className="nav-index">A.01</div>
      {items.map(([id, label, glyph]) => (
        <button key={id} className={classNames("nav-item", view === id && "active")} onClick={() => onChange(id)}>
          <span>{glyph}</span>{label}
        </button>
      ))}
      <div className="nav-spacer" />
      <button className="nav-item sign-out" onClick={onSignOut}><span>×</span>EXIT</button>
    </nav>
  );
}

function Pulse({ stats, signal, onAccounts }: { stats: PoolStats | null; signal: SignalAnalytics | null; onAccounts: () => void }) {
  if (!stats || !signal) return <SignalSkeleton />;
  const latestEconomics = signal.economics.at(-1);
  const surplus = (latestEconomics?.cumulative_api_value ?? stats.aggregate.total_api_cost) - (latestEconomics?.cumulative_subscription_spend ?? stats.aggregate.total_subscription_cost);
  const burn = burnSummary(signal.hourly);
  const intervention = stats.accounts.filter((account) => account.status !== "healthy" || account.secondary_window_used_pct >= 80);

  return (
    <div className="signal-view pulse-view">
      <section className="inline-instruments" aria-label="Pool extraction summary">
        <Instrument label="API-EQUIV VALUE" value={money.format(stats.aggregate.total_api_cost)} accent />
        <Instrument label="SUBSCRIPTION SPEND" value={money.format(stats.aggregate.total_subscription_cost)} />
        <Instrument label="EXTRACTION" value={`${stats.aggregate.overall_roi.toFixed(2)}×`} accent />
        <Instrument label="SURPLUS" value={`+${money.format(Math.max(0, surplus))}`} />
        <Instrument label="BURN / 24H" value={formatTokens(burn.current24)} />
        <Instrument label="ACCEL" value={`${burn.delta >= 0 ? "+" : ""}${burn.delta.toFixed(1)}%`} danger={burn.delta > 25} />
      </section>

      <section className="primary-signal-grid">
        <SignalPanel code="A.10" title="VALUE GAP // API EQUIVALENT VS SUBSCRIPTION SPEND" className="value-panel">
          <ValueGapChart data={signal.economics} />
          <div className="chart-corner-readout">
            <strong>{stats.aggregate.overall_roi.toFixed(2)}×</strong>
            <span>EXTRACTION</span>
            <small>{money.format(stats.aggregate.total_subscription_monthly)} / MO</small>
          </div>
        </SignalPanel>
        <SignalPanel code="A.11" title="BURN VELOCITY // ALL PROVIDERS" className="burn-panel">
          <BurnChart hourly={signal.hourly} />
          <div className="burn-readout"><span>NOW {formatTokens(burn.latestHour)}/H</span><span>7D AVG {formatTokens(burn.averageHour)}/H</span></div>
        </SignalPanel>
      </section>

      <SignalPanel code="A.20" title="PROVIDER EXTRACTION LANES">
        <ProviderLanes accounts={stats.accounts} />
      </SignalPanel>

      {intervention.length > 0 && (
        <button className="intervention-strip" onClick={onAccounts}>
          <span>INTERVENTION QUEUE</span>
          {intervention.slice(0, 5).map((account) => (
            <b key={account.id} style={{ color: PROVIDERS[account.type].color }}>
              {PROVIDERS[account.type].label.toUpperCase()} {account.status === "dead" ? "COOKED" : account.secondary_window_used_pct >= 80 ? "LEANING HARD" : account.status.toUpperCase()}
            </b>
          ))}
          <i>OPEN ACCOUNTS →</i>
        </button>
      )}

      <section className="lower-signal-grid">
        <SignalPanel code="A.30" title="TOKEN COMPOSITION // 14D">
          <TokenComposition hourly={signal.hourly} />
        </SignalPanel>
        <SignalPanel code="A.31" title="WEEKLY HASHED-IP DRAIN">
          <OriginDrain rows={signal.origin_weekly} />
        </SignalPanel>
      </section>
    </div>
  );
}

function Instrument({ label, value, accent, danger }: { label: string; value: string; accent?: boolean; danger?: boolean }) {
  return <div className={classNames("instrument", accent && "accent", danger && "danger")}><span>{label}</span><strong>{value}</strong></div>;
}

function SignalPanel({ code, title, className, children }: { code: string; title: string; className?: string; children: ReactNode }) {
  return (
    <section className={classNames("signal-panel", className)}>
      <header><span>{code}</span><h2>{title}</h2><i aria-hidden="true" /></header>
      <div className="panel-body">{children}</div>
    </section>
  );
}

function ValueGapChart({ data }: { data: SignalAnalytics["economics"] }) {
  const chartData = data.map((point) => ({ date: point.date, value: point.cumulative_api_value, spend: point.cumulative_subscription_spend }));
  if (chartData.length < 2) return <EmptyChart label="VALUE SERIES WARMING UP" />;
  const config: ChartConfig = {
    value: { label: "API-equivalent value", color: "gold" },
    spend: { label: "Subscription spend", color: "grey" },
  };
  return (
    <div className="chart-stage large">
      <AreaChart data={chartData} config={config} margins={{ left: 54, bottom: 28 }} bloom="low" bloomOnHover>
        <Grid horizontal />
        <Area dataKey="value" variant="hatched" isClickable />
        <Area dataKey="spend" variant="solid" strokeVariant="dashed" isClickable />
        <XAxis dataKey="date" tickFormatter={(value) => String(value).slice(5)} maxTicks={7} />
        <YAxis tickFormatter={(value) => `$${compact.format(value)}`} />
        <Legend isClickable />
        <Tooltip labelKey="date" valueFormatter={(value) => preciseMoney.format(value)} />
      </AreaChart>
    </div>
  );
}

function aggregateHourly(hourly: HourlyUsage[]) {
  const rows = new Map<string, Record<string, string | number>>();
  for (const item of hourly) {
    const row = rows.get(item.hour) ?? { hour: item.hour };
    row[item.account_type] = Number(row[item.account_type] ?? 0) + tokenThroughput(item);
    row.input = Number(row.input ?? 0) + item.input_tokens;
    row.cached = Number(row.cached ?? 0) + item.cached_tokens;
    row.output = Number(row.output ?? 0) + item.output_tokens;
    row.reasoning = Number(row.reasoning ?? 0) + item.reasoning_tokens;
    rows.set(item.hour, row);
  }
  return [...rows.values()].sort((a, b) => String(a.hour).localeCompare(String(b.hour)));
}

function BurnChart({ hourly }: { hourly: HourlyUsage[] }) {
  const data = aggregateHourly(hourly);
  const providers = Object.keys(PROVIDERS).filter((provider) => data.some((row) => Number(row[provider]) > 0)) as Provider[];
  if (data.length < 2 || providers.length === 0) return <EmptyChart label="BURN TRACE ACQUIRING" />;
  const config = Object.fromEntries(providers.map((provider) => [provider, { label: PROVIDERS[provider].label, color: PROVIDERS[provider].dither }])) as ChartConfig;
  return (
    <div className="chart-stage large">
      <LineChart data={data} config={config} margins={{ left: 48, bottom: 28 }} bloom="low" bloomOnHover>
        <Grid horizontal />
        {providers.map((provider) => <Line key={provider} dataKey={provider} isClickable />)}
        <XAxis dataKey="hour" tickFormatter={(value) => String(value).slice(5).replace("T", " ")} maxTicks={6} />
        <YAxis tickFormatter={formatTokens} />
        <Legend isClickable />
        <Tooltip labelKey="hour" valueFormatter={(value) => `${formatTokens(value)} tok`} />
      </LineChart>
    </div>
  );
}

function burnSummary(hourly: HourlyUsage[]) {
  const data = aggregateHourly(hourly);
  const totals = data.map((row) => Object.keys(PROVIDERS).reduce((sum, provider) => sum + Number(row[provider] ?? 0), 0));
  const current = totals.slice(-24).reduce((sum, value) => sum + value, 0);
  const previous = totals.slice(-48, -24).reduce((sum, value) => sum + value, 0);
  return {
    current24: current,
    latestHour: totals.at(-1) ?? 0,
    averageHour: totals.length ? totals.reduce((sum, value) => sum + value, 0) / totals.length : 0,
    delta: previous ? ((current - previous) / previous) * 100 : 0,
  };
}

function ProviderLanes({ accounts }: { accounts: AccountStats[] }) {
  const groups = Object.keys(PROVIDERS).map((provider) => {
    const rows = accounts.filter((account) => account.type === provider);
    return { provider: provider as Provider, rows };
  }).filter((group) => group.rows.length);
  return (
    <div className="provider-lanes">
      {groups.map(({ provider, rows }) => {
        const used = rows.filter((row) => row.secondary_window_available).reduce((sum, row) => sum + row.secondary_window_used_pct, 0) / Math.max(1, rows.filter((row) => row.secondary_window_available).length);
        const value = rows.reduce((sum, row) => sum + row.api_cost_estimate, 0);
        const spend = rows.reduce((sum, row) => sum + row.subscription_spend, 0);
        const roi = spend ? value / spend : 0;
        const spark = rows.map(accountThroughput);
        const status = rows.some((row) => row.status === "dead") ? "cooked" : used > 80 ? "leaning hard" : roi > 2 ? "carrying" : roi < 0.5 && spend ? "paid for" : "live";
        return (
          <div className="provider-lane" key={provider} style={{ "--provider": PROVIDERS[provider].color } as CSSProperties}>
            <div className="provider-name"><span>{PROVIDERS[provider].glyph}</span><b>{PROVIDERS[provider].label}</b><small>{rows.length} acct</small></div>
            <div className="quota-field"><i style={{ width: `${Math.min(100, used)}%` }} /><span>{used ? `${used.toFixed(0)}% week` : "window n/a"}</span></div>
            <div className="lane-stat"><span>API VALUE</span><b>{money.format(value)}</b></div>
            <div className="lane-stat"><span>SPEND</span><b>{money.format(spend)}</b></div>
            <div className="lane-stat"><span>ROI</span><b>{roi ? `${roi.toFixed(2)}×` : "—"}</b></div>
            <div className="lane-spark"><Sparkline data={spark.length > 1 ? spark : [0, ...spark]} color={PROVIDERS[provider].dither} /></div>
            <div className="lane-status">{status}</div>
          </div>
        );
      })}
    </div>
  );
}

function TokenComposition({ hourly }: { hourly: HourlyUsage[] }) {
  const data = aggregateHourly(hourly);
  if (data.length < 2) return <EmptyChart label="TOKEN MIX ACQUIRING" />;
  const config: ChartConfig = {
    input: { label: "Input", color: "blue" },
    cached: { label: "Cached", color: "green" },
    output: { label: "Output", color: "orange" },
    reasoning: { label: "Reasoning", color: "purple" },
  };
  return (
    <div className="chart-stage medium">
      <AreaChart data={data} config={config} stackType="stacked" margins={{ left: 46, bottom: 28 }}>
        <Grid horizontal />
        <Area dataKey="input" variant="dotted" isClickable />
        <Area dataKey="cached" variant="hatched" isClickable />
        <Area dataKey="output" variant="dotted" isClickable />
        <Area dataKey="reasoning" variant="hatched" isClickable />
        <XAxis dataKey="hour" tickFormatter={(value) => String(value).slice(5, 10)} maxTicks={5} />
        <YAxis tickFormatter={formatTokens} />
        <Legend isClickable />
        <Tooltip labelKey="hour" valueFormatter={(value) => `${formatTokens(value)} tok`} />
      </AreaChart>
    </div>
  );
}

function OriginDrain({ rows }: { rows: OriginWeeklyUsage[] }) {
  const latestWeek = rows.reduce((latest, row) => row.week_start > latest ? row.week_start : latest, "");
  const originMap = new Map<string, { id: string; total: number; requests: number; providers: Partial<Record<Provider, number>> }>();
  for (const row of rows.filter((item) => item.week_start === latestWeek)) {
    const aggregate = originMap.get(row.origin_id) ?? { id: row.origin_id, total: 0, requests: 0, providers: {} };
    const throughput = tokenThroughput(row);
    aggregate.total += throughput;
    aggregate.requests += row.request_count;
    if (row.account_type in PROVIDERS) {
      const provider = row.account_type as Provider;
      aggregate.providers[provider] = (aggregate.providers[provider] ?? 0) + throughput;
    }
    originMap.set(row.origin_id, aggregate);
  }
  const origins = [...originMap.values()].sort((a, b) => b.total - a.total).slice(0, 10);
  const poolTotal = origins.reduce((sum, origin) => sum + origin.total, 0);
  return (
    <div className="origin-drain">
      <div className="origin-head"><span>HASHED IP</span><span>TOKENS</span><span>SHARE</span><span>ACCOUNT FOOTPRINT</span></div>
      {origins.length === 0 && <div className="empty-signal">NO ORIGIN SERIES YET // THE WIRES ARE QUIET</div>}
      {origins.map((origin, index) => (
        <div className="origin-row" key={origin.id}>
          <span><i>{String(index + 1).padStart(2, "0")}</i>{originHandle(origin.id)}</span>
          <b>{formatTokens(origin.total)}</b>
          <span>{poolTotal ? `${((origin.total / poolTotal) * 100).toFixed(1)}%` : "0%"}</span>
          <div className="footprint" aria-label="Provider footprint">
            {Object.entries(origin.providers).map(([provider, value]) => (
              <i key={provider} title={`${PROVIDERS[provider as Provider].label}: ${formatTokens(value ?? 0)}`} style={{ background: PROVIDERS[provider as Provider].color, flex: value }} />
            ))}
          </div>
        </div>
      ))}
      <footer>WEEK OF {latestWeek || "—"} // HASHED AT INGEST // {origins.length} ACTIVE ORIGINS</footer>
    </div>
  );
}

function ProviderCapitalChart({ accounts }: { accounts: AccountStats[] }) {
  const data = Object.keys(PROVIDERS).map((provider) => {
    const rows = accounts.filter((account) => account.type === provider);
    return {
      provider,
      value: rows.reduce((sum, account) => sum + account.api_cost_estimate, 0),
      spend: rows.reduce((sum, account) => sum + account.subscription_spend, 0),
    };
  }).filter((row) => row.value > 0 || row.spend > 0);
  if (data.length === 0) return <EmptyChart label="CAPITAL TRACE ACQUIRING" />;
  const config: ChartConfig = {
    value: { label: "API-equivalent value", color: "gold" },
    spend: { label: "Matched subscription spend", color: "grey" },
  };
  return (
    <div className="chart-stage medium">
      <BarChart data={data} config={config} margins={{ left: 52, bottom: 30 }} bloom="low" bloomOnHover>
        <Grid horizontal />
        <Bar dataKey="value" variant="hatched" isClickable />
        <Bar dataKey="spend" variant="dotted" isClickable />
        <XAxis dataKey="provider" tickFormatter={(value) => String(value).toUpperCase()} maxTicks={8} />
        <YAxis tickFormatter={(value) => `$${compact.format(value)}`} />
        <Legend isClickable />
        <Tooltip labelKey="provider" valueFormatter={(value) => preciseMoney.format(value)} />
      </BarChart>
    </div>
  );
}

function OriginWeeklyChart({ rows }: { rows: OriginWeeklyUsage[] }) {
  const totals = new Map<string, number>();
  for (const row of rows) totals.set(row.origin_id, (totals.get(row.origin_id) ?? 0) + tokenThroughput(row));
  const origins = [...totals.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([id]) => id);
  const weeks = [...new Set(rows.map((row) => row.week_start))].sort();
  const data = weeks.map((week) => {
    const point: Record<string, string | number> = { week };
    for (const origin of origins) point[origin] = 0;
    for (const row of rows) {
      if (row.week_start === week && origins.includes(row.origin_id)) {
        point[row.origin_id] = Number(point[row.origin_id] ?? 0) + tokenThroughput(row);
      }
    }
    return point;
  });
  if (data.length === 0 || origins.length === 0) return <EmptyChart label="ORIGIN HISTORY ACQUIRING" />;
  const colors: DitherColor[] = ["gold", "orange", "purple", "cyan", "green", "blue"];
  const config = Object.fromEntries(origins.map((origin, index) => [origin, { label: originHandle(origin), color: colors[index] }])) as ChartConfig;
  return (
    <div className="chart-stage medium">
      <BarChart data={data} config={config} stackType="stacked" margins={{ left: 48, bottom: 30 }} bloom="low" bloomOnHover>
        <Grid horizontal />
        {origins.map((origin, index) => <Bar key={origin} dataKey={origin} variant={index % 2 ? "dotted" : "hatched"} isClickable />)}
        <XAxis dataKey="week" tickFormatter={(value) => String(value).slice(5)} maxTicks={6} />
        <YAxis tickFormatter={formatTokens} />
        <Legend isClickable />
        <Tooltip labelKey="week" valueFormatter={(value) => `${formatTokens(value)} tok`} />
      </BarChart>
    </div>
  );
}

function DemandTrendChart({ hourly }: { hourly: HourlyUsage[] }) {
  const data = dailyDemandSeries(hourly);
  if (data.length < 2) return <EmptyChart label="DAILY DEMAND HISTORY ACQUIRING" />;
  const config: ChartConfig = {
    demand: { label: "Daily demand", color: "gold" },
    trend: { label: "3-day trend", color: "cyan" },
  };
  return (
    <div className="chart-stage large">
      <LineChart data={data} config={config} margins={{ left: 52, bottom: 28 }} bloom="low" bloomOnHover>
        <Grid horizontal />
        <Line dataKey="demand" isClickable />
        <Line dataKey="trend" isClickable />
        <XAxis dataKey="date" tickFormatter={(value) => String(value).slice(5)} maxTicks={7} />
        <YAxis tickFormatter={formatTokens} />
        <Legend isClickable />
        <Tooltip labelKey="date" valueFormatter={(value) => `${formatTokens(value)} tok`} />
      </LineChart>
    </div>
  );
}

function CapacityForecastTable({ forecasts }: { forecasts: CapacityForecast[] }) {
  return (
    <div className="capacity-table" role="table" aria-label="Provider capacity forecast">
      <div className="capacity-row capacity-head" role="row"><span>PROVIDER</span><span>LOAD</span><span>SUPPLY</span><span>MIN</span><span>+20%</span><span>ACTION</span></div>
      {forecasts.map((forecast) => {
        const state = forecast.minimumToAdd > 0 ? "gap" : forecast.bufferedToAdd > 0 ? "buffer" : "covered";
        return (
          <div className={classNames("capacity-row", state)} role="row" key={forecast.provider} style={{ "--provider": PROVIDERS[forecast.provider].color } as CSSProperties}>
            <span className="capacity-provider"><i>{PROVIDERS[forecast.provider].glyph}</i><b>{PROVIDERS[forecast.provider].label}</b><small>{forecast.measuredAccounts} measured</small></span>
            <span><b>{forecast.loadEquivalents.toFixed(1)}</b><small>ACCT-EQ</small></span>
            <span><b>{forecast.activeAccounts}</b><small>ACTIVE</small></span>
            <span><b>{forecast.baselineAccounts}</b><small>BASELINE</small></span>
            <span><b>{forecast.bufferedAccounts}</b><small>TARGET</small></span>
            <span className="capacity-action"><b>{forecast.minimumToAdd > 0 ? `+${forecast.minimumToAdd} NOW` : forecast.bufferedToAdd > 0 ? `+${forecast.bufferedToAdd} BUFFER` : "COVERED"}</b><small>{forecast.earliestFullMinutes !== null ? `FULL IN ${formatReset(Math.floor(forecast.earliestFullMinutes))}` : "LASTS TO RESET"}</small></span>
          </div>
        );
      })}
    </div>
  );
}

type InsightMode = "overview" | "capacity" | "flow" | "demand";

function providerDisplay(provider: Provider | "unknown") {
  return provider in PROVIDERS
    ? PROVIDERS[provider as Provider]
    : { label: "Unknown", color: "#9c967f", dither: "grey" as DitherColor, glyph: "·" };
}

function Insights({ stats, signal, onAccounts }: { stats: PoolStats | null; signal: SignalAnalytics | null; onAccounts: () => void }) {
  const [mode, setMode] = useState<InsightMode>("overview");
  if (!stats || !signal) return <SignalSkeleton />;
  const tabs: Array<[InsightMode, string, string]> = [
    ["overview", "OVERVIEW", "At-a-glance risk and actions"],
    ["capacity", "CAPACITY", "Measured limits, resets, scenarios"],
    ["flow", "FLOW", "Stranded supply and routing balance"],
    ["demand", "DEMAND", "Peaks, models, concentration"],
  ];
  return (
    <div className="signal-view insights-view">
      <div className="view-title"><span>I.00</span><h1>Resource intelligence</h1><p>Measure the real limits, move demand intelligently, and know what changes next.</p></div>
      <nav className="insight-tabs" aria-label="Insights dashboards">
        {tabs.map(([id, label, description], index) => (
          <button key={id} className={mode === id ? "active" : ""} onClick={() => setMode(id)} aria-pressed={mode === id}>
            <span>I.{String(index + 1).padStart(2, "0")}</span><b>{label}</b><small>{description}</small>
          </button>
        ))}
      </nav>
      {mode === "overview" && <InsightsOverview stats={stats} signal={signal} onAccounts={onAccounts} />}
      {mode === "capacity" && <CapacityDashboard stats={stats} signal={signal} onAccounts={onAccounts} />}
      {mode === "flow" && <FlowDashboard stats={stats} signal={signal} onAccounts={onAccounts} />}
      {mode === "demand" && <DemandDashboard stats={stats} signal={signal} />}
    </div>
  );
}

function CapacityHistoryChart({ rows }: { rows: QuotaCapacityPoint[] }) {
  const eligible = rows.filter((row) => row.estimated_weekly_tokens > 0 && row.account_type in PROVIDERS);
  const series = [...new Set(eligible.map((row) => `${row.account_type}|${row.plan_type}`))];
  const weeks = [...new Set(eligible.map((row) => row.week_start))].sort();
  const data = weeks.map((week) => {
    const point: Record<string, string | number> = { week };
    for (const row of eligible.filter((item) => item.week_start === week)) point[`${row.account_type}|${row.plan_type}`] = row.estimated_weekly_tokens;
    return point;
  });
  if (data.length === 0) return <EmptyChart label="TOKEN CAPACITY MODEL ACQUIRING // QUOTA TICKS REQUIRED" />;
  const config = Object.fromEntries(series.map((key) => {
    const [provider, plan] = key.split("|") as [Provider, string];
    return [key, { label: `${PROVIDERS[provider].label} ${plan}`, color: PROVIDERS[provider].dither }];
  })) as ChartConfig;
  return (
    <div className="chart-stage large">
      <LineChart data={data} config={config} margins={{ left: 52, bottom: 28 }} bloom="low" bloomOnHover>
        <Grid horizontal />
        {series.map((key) => <Line key={key} dataKey={key} isClickable />)}
        <XAxis dataKey="week" tickFormatter={(value) => String(value).slice(5)} maxTicks={6} />
        <YAxis tickFormatter={formatTokens} />
        <Legend isClickable />
        <Tooltip labelKey="week" valueFormatter={(value) => `${formatTokens(value)} tok/week`} />
      </LineChart>
    </div>
  );
}

function CapacityEvidenceTable({ rows }: { rows: QuotaCapacityPoint[] }) {
  const latestWeek = rows.reduce((latest, row) => row.week_start > latest ? row.week_start : latest, "");
  const latest = rows.filter((row) => row.week_start === latestWeek).sort((a, b) => b.estimated_weekly_tokens - a.estimated_weekly_tokens);
  return (
    <div className="evidence-table" role="table" aria-label="Empirical token capacity estimates">
      <div className="evidence-row evidence-head" role="row"><span>PLAN</span><span>WEEKLY TOKENS</span><span>RANGE</span><span>OBSERVED</span><span>CONFIDENCE</span></div>
      {latest.length === 0 && <div className="empty-signal">NO QUOTA MOVEMENT SAMPLES YET</div>}
      {latest.map((row) => {
        const provider = providerDisplay(row.account_type);
        return (
          <div className="evidence-row" role="row" key={`${row.account_type}-${row.plan_type}`} style={{ "--provider": provider.color } as CSSProperties}>
            <span className="evidence-plan"><i>{provider.glyph}</i><b>{provider.label}</b><small>{row.plan_type}</small></span>
            <span><b>{formatTokens(row.estimated_weekly_tokens)}</b><small>OBSERVED MIX</small></span>
            <span><b>{formatTokens(row.low_estimate_tokens)}–{formatTokens(row.high_estimate_tokens)}</b><small>INTERVAL IQR</small></span>
            <span><b>{row.observed_quota_pct.toFixed(1)}%</b><small>{row.interval_count} TICKS</small></span>
            <span className={`confidence ${row.confidence}`}><b>{row.confidence}</b><small>{row.request_count} REQUESTS</small></span>
          </div>
        );
      })}
      <footer>INFERRED FROM COMPLETE TOKEN INTERVALS BETWEEN WEEKLY QUOTA TICKS // RANGE IS OBSERVED, NOT A PROVIDER-PUBLISHED LIMIT</footer>
    </div>
  );
}

type CalendarEvent = { id: string; at: Date; provider: Provider | "unknown"; kind: string; detail: string; tone: "future" | "credit" | "risk" };

function ResetCalendar({ stats, forecasts, observations }: { stats: PoolStats; forecasts: CapacityForecast[]; observations: ResetObservation[] }) {
  const generated = new Date(stats.generated_at).valueOf();
  const events: CalendarEvent[] = [];
  for (const account of stats.accounts) {
    if (account.secondary_window_available && account.secondary_reset_minutes >= 0) {
      events.push({ id: `${account.id}-weekly`, at: new Date(generated + account.secondary_reset_minutes * 60000), provider: account.type, kind: "WEEKLY RESET", detail: `${account.secondary_window_used_pct.toFixed(0)}% used · ${account.id.slice(-5)}`, tone: "future" });
    }
    for (const [index, expiration] of (account.reset_credit_expirations ?? []).entries()) {
      const at = new Date(expiration);
      if (!Number.isNaN(at.valueOf())) events.push({ id: `${account.id}-credit-${index}`, at, provider: account.type, kind: "BANKED RESET EXPIRES", detail: `${account.id.slice(-5)} · redeemable capacity`, tone: "credit" });
    }
  }
  for (const forecast of forecasts) {
    if (forecast.earliestFullMinutes !== null) {
      events.push({ id: `${forecast.provider}-full`, at: new Date(generated + forecast.earliestFullMinutes * 60000), provider: forecast.provider, kind: "PROJECTED EXHAUSTION", detail: `${forecast.loadEquivalents.toFixed(1)} account-eq load`, tone: "risk" });
    }
  }
  events.sort((a, b) => a.at.valueOf() - b.at.valueOf());
  return (
    <div className="calendar-board">
      <div className="calendar-list">
        {events.slice(0, 14).map((event) => {
          const provider = providerDisplay(event.provider);
          return (
            <div className={`calendar-event ${event.tone}`} key={event.id}>
              <time>{event.at.toLocaleDateString([], { month: "short", day: "numeric" })}<b>{event.at.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}</b></time>
              <i style={{ color: provider.color }}>{provider.glyph}</i>
              <span><b>{event.kind}</b><small>{provider.label} · {event.detail}</small></span>
            </div>
          );
        })}
        {events.length === 0 && <div className="empty-signal">NO UPCOMING RESET EVENTS REPORTED</div>}
      </div>
      <div className="reset-behavior">
        <header><b>OBSERVED RESET BEHAVIOR</b><span>{observations.length} EVENTS / 30D</span></header>
        {observations.slice(0, 8).map((event) => {
          const provider = providerDisplay(event.account_type);
          const deviation = event.deviation_minutes;
          return (
            <div className={`reset-observation ${event.timing}`} key={`${event.account_id}-${event.observed_at}`}>
              <i style={{ color: provider.color }}>{provider.glyph}</i>
              <span><b>{provider.label} {event.timing.replace("_", " ").toUpperCase()}</b><small>{event.from_used_pct.toFixed(0)}% → {event.to_used_pct.toFixed(0)}% · {new Date(event.observed_at).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" })}</small></span>
              <strong>{deviation === undefined ? "SCHEDULE UNKNOWN" : `${deviation > 0 ? "+" : ""}${Math.round(deviation / 60)}H`}</strong>
            </div>
          );
        })}
        {observations.length === 0 && <div className="empty-signal compact-empty">RESET TIMING BASELINE STARTS WITH THIS DEPLOY</div>}
      </div>
    </div>
  );
}

function ScenarioPlanner({ forecasts, onAccounts }: { forecasts: CapacityForecast[]; onAccounts: () => void }) {
  const [demandPct, setDemandPct] = useState(100);
  const [reservePct, setReservePct] = useState(20);
  const rows = forecasts.map((forecast) => {
    const load = forecast.loadEquivalents * demandPct / 100;
    const required = Math.ceil(load * (1 + reservePct / 100));
    return { ...forecast, scenarioLoad: load, required, add: Math.max(0, required - forecast.activeAccounts) };
  });
  const totalAdds = rows.reduce((sum, row) => sum + row.add, 0);
  return (
    <div className="scenario-planner">
      <div className="scenario-controls">
        <label><span>DEMAND</span><b>{demandPct}%</b><input type="range" min="50" max="200" step="5" value={demandPct} onChange={(event) => setDemandPct(Number(event.target.value))} /></label>
        <label><span>RESERVE</span><b>{reservePct}%</b><input type="range" min="0" max="50" step="5" value={reservePct} onChange={(event) => setReservePct(Number(event.target.value))} /></label>
        <div className={classNames("scenario-outcome", totalAdds > 0 && "risk")}><span>POOL ACTION</span><strong>{totalAdds ? `ADD ${totalAdds}` : "CAPACITY HOLDS"}</strong><button onClick={onAccounts}>OPEN ACCOUNTS →</button></div>
      </div>
      <div className="scenario-rows">
        {rows.map((row) => <div key={row.provider} style={{ "--provider": PROVIDERS[row.provider].color } as CSSProperties}><b>{PROVIDERS[row.provider].glyph} {PROVIDERS[row.provider].label}</b><span>{row.scenarioLoad.toFixed(1)} acct-eq demand</span><span>{row.activeAccounts} active</span><strong>{row.add ? `+${row.add} REQUIRED` : `${row.required} REQUIRED`}</strong></div>)}
      </div>
      <footer>SCENARIO SCALES THE CURRENT OBSERVED QUOTA DRAIN; IT DOES NOT ASSUME TOKENS ARE INTERCHANGEABLE BETWEEN PROVIDERS.</footer>
    </div>
  );
}

function ModelSubsidyTable({ rows }: { rows: ModelQuotaEfficiency[] }) {
  const eligible = rows.filter((row) => row.api_value > 0 && row.observed_quota_pct > 0).slice(0, 12);
  return (
    <div className="subsidy-table">
      <div className="subsidy-row subsidy-head"><span>MODEL</span><span>QUOTA</span><span>API VALUE</span><span>VALUE / 1%</span><span>VS PROVIDER</span><span>CONF.</span></div>
      {eligible.map((row) => {
        const provider = providerDisplay(row.account_type);
        return <div className="subsidy-row" key={`${row.account_type}-${row.model}`} style={{ "--provider": provider.color } as CSSProperties}>
          <span><i>{provider.glyph}</i><b>{row.model}</b><small>{provider.label}</small></span>
          <span><b>{row.observed_quota_pct.toFixed(1)}%</b><small>{row.interval_count} intervals</small></span>
          <span><b>{preciseMoney.format(row.api_value)}</b><small>{formatTokens(row.tokens)} tok</small></span>
          <span><b>{preciseMoney.format(row.api_value_per_quota_pct)}</b><small>API-EQUIV</small></span>
          <span className={row.relative_subsidy >= 1 ? "favorable" : "costly"}><b>{row.relative_subsidy.toFixed(2)}×</b><small>{row.relative_subsidy >= 1 ? "MORE SUBSIDIZED" : "LESS SUBSIDIZED"}</small></span>
          <span className={`confidence ${row.confidence}`}><b>{row.confidence}</b></span>
        </div>;
      })}
      {eligible.length === 0 && <div className="empty-signal">MODEL SUBSIDY ACQUIRING // NEEDS PRICED REQUESTS WITH QUOTA MOVEMENT</div>}
      <footer>SUBSIDY INDEX COMPARES API-EQUIVALENT VALUE PER OBSERVED QUOTA POINT WITH OTHER MODELS ON THE SAME PROVIDER. 1.00× IS PROVIDER AVERAGE.</footer>
    </div>
  );
}

function CapacityDashboard({ stats, signal, onAccounts }: { stats: PoolStats; signal: SignalAnalytics; onAccounts: () => void }) {
  const forecasts = capacityForecasts(stats.accounts);
  const latestCapacity = signal.quota_capacity.filter((row) => row.week_start === signal.quota_capacity.reduce((latest, row) => row.week_start > latest ? row.week_start : latest, ""));
  const measuredWeekly = latestCapacity.reduce((sum, row) => sum + row.estimated_weekly_tokens, 0);
  const highConfidence = latestCapacity.filter((row) => row.confidence === "high").length;
  const surpriseCount = signal.reset_observations.filter((event) => event.timing === "early" || event.timing === "late").length;
  return (
    <div className="insight-dashboard">
      <section className="inline-instruments insights-instruments">
        <Instrument label="MEASURED / WEEK" value={measuredWeekly ? formatTokens(measuredWeekly) : "acquiring"} accent />
        <Instrument label="PLANS MEASURED" value={String(latestCapacity.length)} />
        <Instrument label="HIGH CONFIDENCE" value={String(highConfidence)} accent />
        <Instrument label="QUOTA INTERVALS" value={String(latestCapacity.reduce((sum, row) => sum + row.interval_count, 0))} />
        <Instrument label="RESET SURPRISES / 30D" value={String(surpriseCount)} danger={surpriseCount > 0} />
        <Instrument label="MODEL REFRESH" value={signal.quota_generated_at ? new Date(signal.quota_generated_at).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }) : "acquiring"} />
      </section>
      <section className="capacity-history-grid">
        <SignalPanel code="C.10" title="EMPIRICAL TOKEN CAPACITY // WEEK OVER WEEK"><CapacityHistoryChart rows={signal.quota_capacity} /></SignalPanel>
        <SignalPanel code="C.11" title="LATEST CAPACITY EVIDENCE"><CapacityEvidenceTable rows={signal.quota_capacity} /></SignalPanel>
      </section>
      <SignalPanel code="C.20" title="CAPACITY CALENDAR // RETURNS · EXPIRATIONS · SURPRISES"><ResetCalendar stats={stats} forecasts={forecasts} observations={signal.reset_observations} /></SignalPanel>
      <section className="capacity-lower-grid">
        <SignalPanel code="C.30" title="WHAT-IF PLANNER // DEMAND × RESERVE"><ScenarioPlanner forecasts={forecasts} onAccounts={onAccounts} /></SignalPanel>
        <SignalPanel code="C.31" title="MODEL SUBSIDY // API VALUE PER QUOTA POINT"><ModelSubsidyTable rows={signal.model_efficiency} /></SignalPanel>
      </section>
    </div>
  );
}

function AccountFlowTable({ rows }: { rows: AccountFlow[] }) {
  return (
    <div className="flow-table">
      <div className="flow-row flow-head"><span>ACCOUNT</span><span>USED</span><span>PROJECTED AT RESET</span><span>UNUSED</span><span>ROUTING CALL</span></div>
      {rows.map((row) => {
        const provider = PROVIDERS[row.provider];
        const canReceiveShift = row.state === "stranded" && rows.some((candidate) => candidate.provider === row.provider && candidate.id !== row.id && (candidate.state === "exhausts" || candidate.state === "tight"));
        return <div className={`flow-row ${row.state}`} key={row.id} style={{ "--provider": provider.color } as CSSProperties}>
          <span><i>{provider.glyph}</i><b>{provider.label}</b><small>{row.id.slice(-7)}</small></span>
          <span><b>{row.usedPct.toFixed(0)}%</b><small>NOW</small></span>
          <span><div className="flow-meter"><i style={{ width: `${Math.min(100, row.projectedFinalPct)}%` }} /></div><b>{row.projectedFinalPct.toFixed(0)}%</b></span>
          <span><b>{row.strandedPct.toFixed(0)}%</b><small>FORECAST</small></span>
          <span><b>{row.state === "exhausts" ? "ROUTE AWAY" : canReceiveShift ? "ROUTE HERE" : row.state === "stranded" ? "SURPLUS" : row.state === "tight" ? "WATCH" : "BALANCED"}</b><small>RESETS IN {formatReset(row.resetMinutes)}</small></span>
        </div>;
      })}
    </div>
  );
}

function FlowDashboard({ stats, signal, onAccounts }: { stats: PoolStats; signal: SignalAnalytics; onAccounts: () => void }) {
  const flows = accountFlow(stats.accounts);
  const stranded = flows.reduce((sum, row) => sum + row.strandedPct / 100, 0);
  const exhausting = flows.filter((row) => row.state === "exhausts");
  const providers = [...new Set(flows.map((row) => row.provider))];
  const routingCalls = providers.map((provider) => {
    const rows = flows.filter((row) => row.provider === provider);
    const hot = rows[0];
    const cold = [...rows].sort((a, b) => a.projectedFinalPct - b.projectedFinalPct)[0];
    const spread = hot && cold ? hot.projectedFinalPct - cold.projectedFinalPct : 0;
    return { provider, hot, cold, spread, score: Math.max(0, 100 - spread) };
  }).sort((a, b) => a.score - b.score);
  const unhealthy = stats.accounts.filter((account) => account.status !== "healthy").length;
  const cyberFailures = stats.cyber_policy?.counters?.swap_no_candidate ?? 0;
  return (
    <div className="insight-dashboard">
      <section className="inline-instruments insights-instruments">
        <Instrument label="STRANDED FORECAST" value={`${stranded.toFixed(1)} acct-eq`} accent />
        <Instrument label="EXHAUSTING EARLY" value={String(exhausting.length)} danger={exhausting.length > 0} />
        <Instrument label="BALANCED" value={String(flows.filter((row) => row.state === "balanced").length)} />
        <Instrument label="ROUTING SPREAD" value={`${(routingCalls[0]?.spread ?? 0).toFixed(0)}pt`} danger={(routingCalls[0]?.spread ?? 0) > 40} />
        <Instrument label="UNHEALTHY ACCOUNTS" value={String(unhealthy)} danger={unhealthy > 0} />
        <Instrument label="UNSERVED POLICY SWAPS" value={String(cyberFailures)} danger={cyberFailures > 0} />
      </section>
      <section className="flow-grid">
        <SignalPanel code="F.10" title="ACCOUNT FLOW // PROJECTED WEEK-END UTILIZATION"><AccountFlowTable rows={flows} /></SignalPanel>
        <SignalPanel code="F.11" title="ROUTING BALANCE // WITHIN PROVIDER">
          <div className="routing-calls">
            {routingCalls.map((call) => <div className={call.score < 60 ? "risk" : ""} key={call.provider} style={{ "--provider": PROVIDERS[call.provider].color } as CSSProperties}>
              <span><i>{PROVIDERS[call.provider].glyph}</i><b>{PROVIDERS[call.provider].label}</b><small>{call.score.toFixed(0)}/100 BALANCE</small></span>
              <p>{call.hot && call.cold && call.hot.id !== call.cold.id && call.spread > 20 ? <>Shift new traffic from <b>{call.hot.id.slice(-5)}</b> toward <b>{call.cold.id.slice(-5)}</b>; projected utilization differs by {call.spread.toFixed(0)} points.</> : <>Current accounts are draining within a reasonable range.</>}</p>
            </div>)}
          </div>
        </SignalPanel>
      </section>
      <section className="flow-lower-grid">
        <SignalPanel code="F.20" title="STRANDED CAPACITY // LIKELY TO RESET UNUSED">
          <div className="stranded-list">
            {flows.filter((row) => row.strandedPct >= 20).slice(0, 10).map((row) => <div key={row.id}><span style={{ color: PROVIDERS[row.provider].color }}>{PROVIDERS[row.provider].glyph}</span><b>{PROVIDERS[row.provider].label} {row.id.slice(-5)}</b><div><i style={{ width: `${row.strandedPct}%` }} /></div><strong>{row.strandedPct.toFixed(0)}% UNUSED</strong></div>)}
            {flows.every((row) => row.strandedPct < 20) && <div className="empty-signal">NO MATERIAL STRANDED WEEKLY CAPACITY</div>}
          </div>
        </SignalPanel>
        <SignalPanel code="F.21" title="LIVE HEALTH // CURRENT PROCESS WINDOW">
          <div className="health-board">
            <div><span>HEALTHY</span><b>{stats.accounts.filter((account) => account.status === "healthy").length}</b><small>routing normally</small></div>
            <div><span>DEGRADED</span><b>{stats.accounts.filter((account) => account.status === "degraded").length}</b><small>penalty elevated</small></div>
            <div><span>COOLDOWN</span><b>{stats.accounts.filter((account) => account.status === "cooldown").length}</b><small>temporarily unavailable</small></div>
            <div><span>DEAD</span><b>{stats.accounts.filter((account) => account.status === "dead").length}</b><small>not in supply</small></div>
            <footer>RELIABILITY COUNTERS ARE PROCESS-LIFETIME SIGNALS TODAY. DURABLE LATENCY AND FAILURE HISTORY IS NOT YET RECORDED, SO THIS PANEL DOES NOT CLAIM A LONG-TERM SLA.</footer>
            <button onClick={onAccounts}>INSPECT ACCOUNTS →</button>
          </div>
        </SignalPanel>
      </section>
    </div>
  );
}

function PeakDemandHeatmap({ hourly }: { hourly: HourlyUsage[] }) {
  const cells = peakHeatmap(hourly);
  const maximum = Math.max(1, ...cells.map((cell) => cell.averageTokens));
  const days = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];
  return (
    <div className="peak-heatmap">
      <div className="heatmap-hours">{Array.from({ length: 24 }, (_, hour) => <span key={hour}>{hour % 3 === 0 ? String(hour).padStart(2, "0") : ""}</span>)}</div>
      {days.map((day, dayIndex) => <div className="heatmap-row" key={day}><b>{day}</b><div>{cells.filter((cell) => cell.day === dayIndex).map((cell) => {
        const intensity = cell.averageTokens / maximum;
        return <i key={cell.hour} title={`${day} ${String(cell.hour).padStart(2, "0")}:00 UTC · ${formatTokens(cell.averageTokens)} tokens · ${cell.averageRequests.toFixed(1)} requests`} style={{ opacity: 0.12 + intensity * 0.88 }} />;
      })}</div></div>)}
      <footer><span>QUIET</span><i /><i /><i /><i /><i /><span>PEAK</span><b>UTC · 14D HOURLY AVERAGE</b></footer>
    </div>
  );
}

function ModelDemandTable({ rows }: { rows: ModelDailyUsage[] }) {
  const models = modelMix(rows);
  const [metric, setMetric] = useState<"tokens" | "requests" | "apiValue">("tokens");
  const ranked = [...models].sort((a, b) => b[metric] - a[metric]);
  const total = ranked.reduce((sum, row) => sum + row[metric], 0);
  return (
    <div className="model-demand-table">
      <div className="model-demand-controls">
        <span>ALL {models.length} MODELS · RANK BY</span>
        {(["tokens", "requests", "apiValue"] as const).map((value) => <button className={metric === value ? "active" : ""} key={value} onClick={() => setMetric(value)}>{value === "apiValue" ? "API VALUE" : value.toUpperCase()}</button>)}
      </div>
      {ranked.map((row, index) => {
        const provider = providerDisplay(row.provider);
        const share = total ? row[metric] / total * 100 : 0;
        return <div key={`${row.provider}-${row.model}`} style={{ "--provider": provider.color } as CSSProperties}>
          <span><i>{String(index + 1).padStart(2, "0")}</i><b>{row.model}</b><small>{provider.label}</small></span>
          <div><i style={{ width: `${Math.max(1, share)}%` }} /></div>
          <strong>{share.toFixed(1)}%</strong><span><b>{metric === "tokens" ? formatTokens(row.tokens) : metric === "requests" ? `${compact.format(row.requests)} req` : preciseMoney.format(row.apiValue)}</b><small>{formatTokens(row.requests ? row.tokens / row.requests : 0)}/req · {preciseMoney.format(row.apiValue)}</small></span>
        </div>;
      })}
      {models.length === 0 && <div className="empty-signal">MODEL DEMAND HISTORY ACQUIRING</div>}
    </div>
  );
}

function ConservationBoard({ stats, signal }: { stats: PoolStats; signal: SignalAnalytics }) {
  const concentration = originConcentration(signal.origin_weekly);
  const models = modelMix(signal.model_daily);
  const totalTokens = models.reduce((sum, row) => sum + row.tokens, 0);
  const totalRequests = models.reduce((sum, row) => sum + row.requests, 0);
  const cacheShare = stats.aggregate.total_input_tokens ? stats.aggregate.total_cached_tokens / stats.aggregate.total_input_tokens * 100 : 0;
  const reasoningShare = stats.aggregate.total_billable_tokens ? stats.aggregate.total_reasoning_tokens / stats.aggregate.total_billable_tokens * 100 : 0;
  const calls = [
    { label: "CACHE REUSE", value: `${cacheShare.toFixed(1)}%`, state: cacheShare < 20 ? "review" : "good", copy: cacheShare < 20 ? "Low observed cache share. Repeated large contexts are the first conservation target." : "Cache reuse is materially reducing repeated input work." },
    { label: "REASONING LOAD", value: `${reasoningShare.toFixed(1)}%`, state: reasoningShare > 30 ? "review" : "good", copy: reasoningShare > 30 ? "Reasoning is a large share of billable work. Check whether every origin needs the current effort level." : "Reasoning share is within the current operating band." },
    { label: "AVG REQUEST", value: formatTokens(totalRequests ? totalTokens / totalRequests : 0), state: "neutral", copy: "Use the model and origin tables to investigate workloads far above this pool-wide baseline." },
    { label: "TOP ORIGIN", value: `${concentration.topOriginShare.toFixed(1)}%`, state: concentration.topOriginShare > 40 ? "review" : "good", copy: concentration.topOriginShare > 40 ? "One origin drives a large share of this week’s drain. Review it before adding broad capacity." : "Demand is not dominated by a single origin." },
  ];
  return <div className="conservation-board">{calls.map((call) => <div className={call.state} key={call.label}><span>{call.label}</span><b>{call.value}</b><p>{call.copy}</p></div>)}</div>;
}

function DemandDashboard({ stats, signal }: { stats: PoolStats; signal: SignalAnalytics }) {
  const concentration = originConcentration(signal.origin_weekly);
  const models = modelMix(signal.model_daily);
  const topModel = models[0];
  const demand = demandSummary(signal.hourly);
  return (
    <div className="insight-dashboard">
      <section className="inline-instruments insights-instruments">
        <Instrument label="24H DEMAND" value={formatTokens(demand.current24)} accent />
        <Instrument label="P95 BURST" value={`${demand.peakFactor.toFixed(1)}×`} danger={demand.peakFactor > 2} />
        <Instrument label="ACTIVE ORIGINS" value={String(concentration.origins)} />
        <Instrument label="TOP ORIGIN SHARE" value={`${concentration.topOriginShare.toFixed(1)}%`} danger={concentration.topOriginShare > 40} />
        <Instrument label="TOP 3 SHARE" value={`${concentration.topThreeShare.toFixed(1)}%`} />
        <Instrument label="TOP MODEL" value={topModel?.model ?? "acquiring"} accent />
      </section>
      <section className="demand-grid">
        <SignalPanel code="D.10" title="PEAK DEMAND MAP // WHEN THE POOL GETS HIT"><PeakDemandHeatmap hourly={signal.hourly} /></SignalPanel>
        <SignalPanel code="D.11" title="MODEL MIX // 14D TOKENS · REQUESTS · VALUE"><ModelDemandTable rows={signal.model_daily} /></SignalPanel>
      </section>
      <section className="demand-lower-grid">
        <SignalPanel code="D.20" title="CONCENTRATION // CURRENT WEEK">
          <div className="concentration-board">
            <div className="concentration-gauge" style={{ "--share": `${concentration.topOriginShare}%` } as CSSProperties}><strong>{concentration.topOriginShare.toFixed(1)}%</strong><span>TOP ORIGIN</span></div>
            <div><span>ACTIVE ORIGINS</span><b>{concentration.origins}</b></div><div><span>TOP THREE</span><b>{concentration.topThreeShare.toFixed(1)}%</b></div><div><span>GINI</span><b>{concentration.gini.toFixed(2)}</b></div>
            <p>{concentration.topOriginShare > 40 ? "Demand is concentrated enough that one workload can materially change account requirements." : "Demand is distributed; broad pool growth matters more than a single origin."}</p>
          </div>
        </SignalPanel>
        <SignalPanel code="D.21" title="CONSERVATION CALLS // OBSERVED SIGNALS"><ConservationBoard stats={stats} signal={signal} /></SignalPanel>
      </section>
    </div>
  );
}

function InsightsOverview({ stats, signal, onAccounts }: { stats: PoolStats; signal: SignalAnalytics; onAccounts: () => void }) {
  const demand = demandSummary(signal.hourly);
  const forecasts = capacityForecasts(stats.accounts);
  const minimumAdds = forecasts.reduce((sum, forecast) => sum + forecast.minimumToAdd, 0);
  const bufferedAdds = forecasts.reduce((sum, forecast) => sum + forecast.bufferedToAdd, 0);
  const primaryRisk = forecasts.find((forecast) => forecast.minimumToAdd > 0) ?? forecasts.find((forecast) => forecast.bufferedToAdd > 0) ?? forecasts[0];
  const modeledProviders = new Set(forecasts.map((forecast) => forecast.provider));
  const unmodeled = [...new Set(stats.accounts.map((account) => account.type))].filter((provider) => !modeledProviders.has(provider));
  const sampleDays = forecasts.reduce((sum, forecast) => sum + forecast.sampleAccountDays, 0);
  const demandDirection = demand.deltaPct >= 0 ? `+${demand.deltaPct.toFixed(1)}%` : `${demand.deltaPct.toFixed(1)}%`;

  return (
    <>
      <section className="inline-instruments insights-instruments" aria-label="Capacity planning summary">
        <Instrument label="DEMAND / 24H" value={formatTokens(demand.current24)} accent />
        <Instrument label="DAY / DAY" value={demandDirection} danger={demand.deltaPct > 20} />
        <Instrument label="7D DAILY AVG" value={formatTokens(demand.averageDay7d)} />
        <Instrument label="P95 BURST" value={`${demand.peakFactor.toFixed(1)}×`} danger={demand.peakFactor > 2} />
        <Instrument label="MINIMUM ADDS" value={`+${minimumAdds}`} danger={minimumAdds > 0} />
        <Instrument label="20% BUFFER ADDS" value={`+${bufferedAdds}`} accent />
      </section>

      <section className={classNames("capacity-directive", minimumAdds > 0 ? "urgent" : bufferedAdds > 0 ? "advisory" : "clear")}>
        <span>PRIMARY ACTION</span>
        {primaryRisk ? (
          <>
            <strong>{primaryRisk.minimumToAdd > 0 ? `ADD ${primaryRisk.minimumToAdd} ${PROVIDERS[primaryRisk.provider].label.toUpperCase()} ACCOUNT${primaryRisk.minimumToAdd === 1 ? "" : "S"} MINIMUM` : primaryRisk.bufferedToAdd > 0 ? `ADD ${primaryRisk.bufferedToAdd} ${PROVIDERS[primaryRisk.provider].label.toUpperCase()} FOR RESERVE` : "CURRENT CAPACITY HOLDS"}</strong>
            <p>Observed drain equals {primaryRisk.loadEquivalents.toFixed(1)} current-plan account equivalents against {primaryRisk.activeAccounts} active. Target {primaryRisk.bufferedAccounts} for a 20% operating buffer.</p>
          </>
        ) : <><strong>CAPACITY MODEL ACQUIRING</strong><p>No provider is reporting enough weekly-window history yet.</p></>}
        <button onClick={onAccounts}>OPEN ACCOUNTS →</button>
      </section>

      <section className="insights-grid">
        <SignalPanel code="I.10" title="DAILY DEMAND // COMPLETE DAYS + 3D TREND"><DemandTrendChart hourly={signal.hourly} /></SignalPanel>
        <SignalPanel code="I.11" title="ACCOUNT CAPACITY // CURRENT PACE"><CapacityForecastTable forecasts={forecasts} /></SignalPanel>
      </section>

      <section className="insight-actions">
        <header><span>I.20</span><h2>OPERATING CALLS</h2><small>{sampleDays.toFixed(1)} ACCOUNT-DAYS OBSERVED</small></header>
        {forecasts.map((forecast) => (
          <div className="insight-action-row" key={forecast.provider}>
            <span style={{ color: PROVIDERS[forecast.provider].color }}>{PROVIDERS[forecast.provider].glyph}</span>
            <b>{PROVIDERS[forecast.provider].label.toUpperCase()}</b>
            <p>{forecast.minimumToAdd > 0 ? `Add ${forecast.minimumToAdd} now to make the current weekly drain sustainable; add ${forecast.bufferedToAdd} total for the 20% reserve.` : forecast.bufferedToAdd > 0 ? `Baseline is covered. Add ${forecast.bufferedToAdd} for a 20% reserve against demand growth and uneven routing.` : "Current supply covers observed demand with the 20% reserve intact."}</p>
            <strong>{forecast.headroomPct >= 0 ? `${forecast.headroomPct.toFixed(0)}% HEADROOM` : `${Math.abs(forecast.headroomPct).toFixed(0)}% OVER CAPACITY`}</strong>
          </div>
        ))}
        {unmodeled.length > 0 && <footer>CAPACITY UNMODELED // {unmodeled.map((provider) => PROVIDERS[provider].label.toUpperCase()).join(" · ")} DO NOT REPORT A WEEKLY LIMIT. THEIR TOKENS ARE INCLUDED IN DEMAND TRENDS, NOT ACCOUNT RECOMMENDATIONS.</footer>}
      </section>

      <section className="insight-method">
        <b>HOW THE ACCOUNT NUMBER WORKS</b>
        <span>For each provider: sum <code>weekly used % ÷ expected used % by now</code>, then round up. “+20%” adds an operating reserve. Recommendations are current-plan equivalents and update every 30 seconds.</span>
      </section>
    </>
  );
}

function Usage({ stats, signal, session }: { stats: PoolStats | null; signal: SignalAnalytics | null; session: FriendSession }) {
  if (!stats || !signal) return <SignalSkeleton />;
  const burn = burnSummary(signal.hourly);
  const cacheShare = stats.aggregate.total_input_tokens ? (stats.aggregate.total_cached_tokens / stats.aggregate.total_input_tokens) * 100 : 0;
  const hottest = [...stats.accounts]
    .filter((account) => account.secondary_window_available)
    .sort((a, b) => b.secondary_window_used_pct - a.secondary_window_used_pct)[0];

  return (
    <div className="signal-view usage-view">
      <div className="view-title"><span>U.00</span><h1>Burn analysis</h1><p>Where the compute went, who drank it, and how hard the subscriptions are working.</p></div>
      <section className="inline-instruments usage-instruments" aria-label="Burn summary">
        <Instrument label="BURN / 24H" value={formatTokens(burn.current24)} accent />
        <Instrument label="LATEST HOUR" value={`${formatTokens(burn.latestHour)}/h`} />
        <Instrument label="ACCELERATION" value={`${burn.delta >= 0 ? "+" : ""}${burn.delta.toFixed(1)}%`} danger={burn.delta > 25} />
        <Instrument label="CACHE SHARE" value={`${cacheShare.toFixed(1)}%`} accent />
        <Instrument label="YOUR HANDLE" value={originHandle(session.origin_id)} accent />
        <Instrument label="HOTTEST WEEK" value={hottest ? `${hottest.secondary_window_used_pct.toFixed(0)}%` : "n/a"} danger={Boolean(hottest && hottest.secondary_window_used_pct >= 85)} />
      </section>
      <section className="usage-grid">
        <SignalPanel code="U.10" title="BURN VELOCITY // 14D"><BurnChart hourly={signal.hourly} /></SignalPanel>
        <SignalPanel code="U.11" title="TOKEN COMPOSITION // 14D"><TokenComposition hourly={signal.hourly} /></SignalPanel>
        <SignalPanel code="U.20" title="PROVIDER CAPITAL // VALUE VS MATCHED SPEND"><ProviderCapitalChart accounts={stats.accounts} /></SignalPanel>
        <SignalPanel code="U.21" title="HASHED-IP DRAIN // WEEK OVER WEEK"><OriginWeeklyChart rows={signal.origin_weekly} /></SignalPanel>
      </section>
    </div>
  );
}

function Accounts({ stats, adminAccounts, operatorToken, onUnlocked, onAccountsChanged }: {
  stats: PoolStats | null;
  adminAccounts: AdminAccount[];
  operatorToken: string;
  onUnlocked: (token: string, accounts: AdminAccount[]) => void;
  onAccountsChanged: () => Promise<void>;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const [unlocking, setUnlocking] = useState(false);
  const [contributing, setContributing] = useState(false);
  const [action, setAction] = useState<"enable" | "disable" | "resurrect" | "refresh" | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  if (!stats) return <SignalSkeleton />;
  const selectedAdmin = adminAccounts.find((account) => account.id === selected) ?? null;
  const selectedAccount = stats.accounts.find((account) => {
    const adminMatch = adminAccounts.find((candidate) => candidate.public_id === account.id);
    return (adminMatch?.id ?? account.id) === selected;
  }) ?? null;

  const perform = async (nextAction: typeof action) => {
    if (!selectedAdmin || !nextAction) return;
    if (action !== nextAction) {
      setAction(nextAction);
      return;
    }
    setBusy(true);
    try {
      await mutateAccount(selectedAdmin.id, nextAction);
      setMessage(`${selectedAdmin.id} ${nextAction} complete`);
      setAction(null);
      await onAccountsChanged();
    } catch (cause) {
      setMessage(cause instanceof Error ? cause.message : "Action failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="signal-view accounts-view">
      <div className="view-title account-title">
        <span>C.00</span><h1>Account contribution</h1>
        <p>Every paid seat, what it burned, and whether it deserves to stay plugged in.</p>
        <div className="account-title-actions">
          <button className="contribute-button" onClick={() => setContributing(true)}>＋ CONTRIBUTE ACCOUNT</button>
          {!operatorToken && <button className="unlock-button" onClick={() => setUnlocking(true)}>⌑ UNLOCK CONTROLS</button>}
          {operatorToken && <button className="operator-badge" onClick={async () => { await reloadAccounts(); await onAccountsChanged(); }}>OPERATOR // RELOAD POOL</button>}
        </div>
      </div>
      <div className={classNames("accounts-layout", selectedAdmin && "inspecting")}>
        <div className="account-table" role="table" aria-label="Provider accounts">
          <div className="account-row account-head" role="row">
            <span>PROVIDER / PLAN / ACCOUNT</span><span>STATE</span><span>WEEKLY PACE</span><span>RESET WINDOWS</span><span>BANKED RESETS</span><span>BURN</span><span>VALUE</span><span>SPEND</span><span>ROI</span><span>TRACE</span>
          </div>
          {stats.accounts.map((account) => {
            const adminMatch = adminAccounts.find((candidate) => candidate.public_id === account.id);
            const rowID = adminMatch?.id ?? account.id;
            return (
              <button className={classNames("account-row", selected === rowID && "selected")} key={account.id} onClick={() => setSelected(rowID)} style={{ "--provider": PROVIDERS[account.type].color } as CSSProperties}>
                <span className="account-identity"><i>{PROVIDERS[account.type].glyph}</i><b>{PROVIDERS[account.type].label}</b><small><em>{account.plan_type || "unknown plan"}</em><span>{operatorToken && adminMatch ? adminMatch.id : account.id}</span></small></span>
                <span className={`state ${account.status}`}>{account.status === "dead" ? "cooked" : account.status}</span>
                <WeeklyPace account={account} />
                <span className="account-windows">
                  <ResetWindow label="PRIMARY" available={account.primary_window_available} used={account.primary_window_used_pct} resetMinutes={account.primary_reset_minutes} compact />
                  <ResetWindow label="WEEKLY" available={account.secondary_window_available} used={account.secondary_window_used_pct} resetMinutes={account.secondary_reset_minutes} compact />
                </span>
                <ResetCreditBadge account={account} />
                <span>{formatTokens(accountThroughput(account))}</span>
                <span>{money.format(account.api_cost_estimate)}</span>
                <span>{money.format(account.subscription_spend)}</span>
                <strong>{account.subscription_spend ? `${account.roi.toFixed(2)}×` : "—"}</strong>
                <span className="account-spark"><Sparkline data={[0, account.total_input_tokens, accountThroughput(account), account.total_output_tokens]} color={PROVIDERS[account.type].dither} /></span>
              </button>
            );
          })}
        </div>
        {selected && (
          <aside className="account-inspector">
            <button className="inspector-close" onClick={() => setSelected(null)}>×</button>
            {selectedAccount ? (
              <>
                <span className="inspector-code">ACCOUNT // SIGNAL VIEW</span>
                <h2>{selectedAccount.id}</h2>
                <div className="inspector-provider" style={{ color: PROVIDERS[selectedAccount.type].color }}>{PROVIDERS[selectedAccount.type].label.toUpperCase()} / {selectedAccount.plan_type}</div>
                <div className="account-admission">IN POOL {formatAdmission(selectedAccount.account_added_at)} // SPEND {money.format(selectedAccount.subscription_spend)}</div>
                <div className="inspector-windows" aria-label="Account usage reset windows">
                  <ResetWindow label="PRIMARY WINDOW" available={selectedAccount.primary_window_available} used={selectedAccount.primary_window_used_pct} resetMinutes={selectedAccount.primary_reset_minutes} paceRatio={selectedAccount.primary_pace_ratio} showPace />
                  <ResetWindow label="WEEKLY WINDOW" available={selectedAccount.secondary_window_available} used={selectedAccount.secondary_window_used_pct} resetMinutes={selectedAccount.secondary_reset_minutes} paceRatio={selectedAccount.secondary_pace_ratio} showPace />
                </div>
                {selectedAccount.type === "codex" && (
                  <section className="inspector-reset-credits" aria-label="Banked usage resets">
                    <header><span>BANKED USAGE RESETS</span><strong>{selectedAccount.reset_credits_known ? selectedAccount.reset_credits_available ?? 0 : "—"}</strong></header>
                    <div>
                      {selectedAccount.reset_credits_known ? <ResetCreditExpirations account={selectedAccount} /> : <span>RESET CREDIT DATA NOT REPORTED</span>}
                    </div>
                    <small>EXPIRATIONS ARE SHOWN IN YOUR LOCAL TIME</small>
                  </section>
                )}
                <div className="inspector-metrics">
                  <Instrument label="BURN" value={formatTokens(accountThroughput(selectedAccount))} accent />
                  <Instrument label="CACHE" value={`${selectedAccount.cache_hit_rate_pct.toFixed(1)}%`} />
                  <Instrument label="VALUE" value={money.format(selectedAccount.api_cost_estimate)} />
                  <Instrument label="ROI" value={selectedAccount.subscription_spend ? `${selectedAccount.roi.toFixed(2)}×` : "—"} />
                </div>
                {selectedAdmin ? (
                  <>
                    <span className="inspector-code operator-section">OPERATOR // {selectedAdmin.id}</span>
                    <div className="inspector-metrics operator-metrics">
                      <Instrument label="SCORE" value={selectedAdmin.score.toFixed(2)} accent />
                      <Instrument label="PENALTY" value={selectedAdmin.penalty.toFixed(1)} danger={selectedAdmin.penalty > 2} />
                      <Instrument label="INFLIGHT" value={String(selectedAdmin.inflight)} />
                      <Instrument label="PRIMARY" value={selectedAdmin.is_primary ? "YES" : "NO"} />
                    </div>
                    <pre className="score-trace">{selectedAdmin.score_tooltip || "NO SCORE TRACE"}</pre>
                    <div className="operator-actions">
                      <button disabled={busy} className={action === (selectedAdmin.disabled ? "enable" : "disable") ? "confirm" : ""} onClick={() => perform(selectedAdmin.disabled ? "enable" : "disable")}>{action === (selectedAdmin.disabled ? "enable" : "disable") ? `CONFIRM ${selectedAdmin.disabled ? "ENABLE" : "DISABLE"}` : selectedAdmin.disabled ? "ENABLE ACCOUNT" : "DISABLE ACCOUNT"}</button>
                      <button disabled={busy || !selectedAdmin.dead} className={action === "resurrect" ? "confirm" : ""} onClick={() => perform("resurrect")}>{action === "resurrect" ? "CONFIRM RESURRECT" : "RESURRECT"}</button>
                      <button disabled={busy} className={action === "refresh" ? "confirm" : ""} onClick={() => perform("refresh")}>{action === "refresh" ? "CONFIRM REFRESH" : "FORCE REFRESH"}</button>
                    </div>
                    {message && <div className="operator-message" role="status">{message}</div>}
                  </>
                ) : (
                  <div className="locked-inspector"><span>⌑</span><b>OPERATOR CONTROLS LOCKED</b><p>Reset windows and account economics stay visible. Unlock only to change pool state.</p><button onClick={() => setUnlocking(true)}>UNLOCK CONTROLS</button></div>
                )}
              </>
            ) : null}
          </aside>
        )}
      </div>
      {contributing && <AccountContribution onClose={() => setContributing(false)} onAdded={async () => { await onAccountsChanged(); setContributing(false); }} />}
      {unlocking && <OperatorUnlock onClose={() => setUnlocking(false)} onUnlocked={(token, accounts) => { onUnlocked(token, accounts); setUnlocking(false); }} />}
    </div>
  );
}

type ContributableProvider = "codex" | "claude" | "antigravity" | "kimi" | "minimax" | "zai" | "xiaomi" | "grok";

const CONTRIBUTION_PROVIDERS: Array<{ id: ContributableProvider; label: string; mode: "oauth" | "key" | "json" }> = [
  { id: "codex", label: "Codex", mode: "oauth" },
  { id: "claude", label: "Claude", mode: "oauth" },
	  { id: "antigravity", label: "Google Antigravity", mode: "oauth" },
  { id: "kimi", label: "Kimi", mode: "key" },
  { id: "minimax", label: "MiniMax", mode: "key" },
  { id: "zai", label: "Z.ai", mode: "key" },
  { id: "xiaomi", label: "Xiaomi", mode: "key" },
  { id: "grok", label: "Grok", mode: "json" },
];

function oauthCode(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return "";
  try {
    const parsed = new URL(trimmed);
    return parsed.searchParams.get("code") ?? trimmed;
  } catch {
    const match = trimmed.match(/(?:^|[?&])code=([^&]+)/);
    return match ? decodeURIComponent(match[1]) : trimmed;
  }
}

function AccountContribution({ onClose, onAdded }: { onClose: () => void; onAdded: () => Promise<void> }) {
  const [provider, setProvider] = useState<ContributableProvider>("codex");
  const [credential, setCredential] = useState("");
	  const [oauth, setOAuth] = useState<{ verifier?: string; sessionID?: string; state?: string; url: string } | null>(null);
	  const oauthCompleted = useRef(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const selected = CONTRIBUTION_PROVIDERS.find((candidate) => candidate.id === provider)!;

	  useEffect(() => {
	    if (provider !== "antigravity" || !oauth?.sessionID) return;
	    let stopped = false;
	    const complete = async () => {
	      if (stopped || oauthCompleted.current) return;
	      oauthCompleted.current = true;
	      await onAdded();
	    };
	    const onMessage = (event: MessageEvent) => {
	      if (event.origin !== window.location.origin || event.data?.type !== "codex-pool-antigravity-oauth" || event.data?.session_id !== oauth.sessionID) return;
	      if (event.data.status === "complete") void complete();
	      if (event.data.status === "error") setError(event.data.error || "Google sign-in failed");
	    };
	    window.addEventListener("message", onMessage);
	    const timer = window.setInterval(async () => {
	      try {
	        const status = await antigravityOAuthStatus(oauth.sessionID!);
	        if (status.status === "complete") { window.clearInterval(timer); await complete(); }
	        if (status.status === "error") { window.clearInterval(timer); setError(status.error || "Google sign-in failed"); }
	      } catch { /* polling is only a fallback for a missed popup message */ }
	    }, 1200);
	    return () => { stopped = true; window.clearInterval(timer); window.removeEventListener("message", onMessage); };
	  }, [oauth?.sessionID, onAdded, provider]);

	  const choose = (next: ContributableProvider) => {
	    oauthCompleted.current = false;
    setProvider(next);
    setCredential("");
    setOAuth(null);
    setError("");
  };

  const startOAuth = async () => {
    // Reserve the tab while the click is still a trusted user gesture. Opening
    // it after the network response is commonly blocked as a popup.
    const authorizationWindow = window.open("about:blank", "_blank");
	    if (authorizationWindow && provider !== "antigravity") authorizationWindow.opener = null;
    setBusy(true);
    setError("");
    try {
	      const result = provider === "antigravity" ? await startAntigravityOAuth() : await startAccountOAuth(provider as "codex" | "claude");
	      if (!result.oauth_url || (provider === "antigravity" ? !result.session_id : !result.verifier)) throw new Error("Provider did not return an OAuth session");
	      oauthCompleted.current = false;
	      setOAuth({ verifier: result.verifier, sessionID: result.session_id, state: result.state, url: result.oauth_url });
      authorizationWindow?.location.replace(result.oauth_url);
    } catch (cause) {
      authorizationWindow?.close();
      setError(cause instanceof Error ? cause.message : "Could not start OAuth");
    } finally {
      setBusy(false);
    }
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (selected.mode === "oauth") {
        if (!oauth) {
          await startOAuth();
          return;
        }
	        if (provider === "antigravity") {
	          if (!oauth.sessionID || !credential.trim()) throw new Error("Paste the authorization code or callback URL");
	          await exchangeAntigravityOAuth(oauth.sessionID, credential, oauth.state || "");
	        } else {
	          const code = oauthCode(credential);
	          if (!code || !oauth.verifier) throw new Error("Paste the authorization code or callback URL");
	          await exchangeAccountOAuth(provider as "codex" | "claude", code, oauth.verifier);
	        }
      } else if (selected.mode === "json") {
        await contributeGrok(credential);
      } else {
        await contributeAPIKey(provider as "kimi" | "minimax" | "zai" | "xiaomi", credential);
      }
      await onAdded();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Account contribution failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="operator-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <form className="operator-dialog contribution-dialog" onSubmit={submit} role="dialog" aria-modal="true" aria-labelledby="contribution-title">
        <span>FRIEND UPLINK // CREDENTIALS GO STRAIGHT TO THE POOL</span>
        <h2 id="contribution-title">Contribute an account</h2>
        <p>Add capacity without unlocking operator controls. We validate the credential before it joins the rotation.</p>
        <div className="contribution-providers" aria-label="Provider">
          {CONTRIBUTION_PROVIDERS.map((candidate) => <button type="button" key={candidate.id} className={provider === candidate.id ? "active" : ""} onClick={() => choose(candidate.id)}>{candidate.label}</button>)}
        </div>
        {selected.mode === "oauth" ? (
          <div className="contribution-oauth">
            {!oauth ? (
              <button type="button" className="oauth-launch" disabled={busy} onClick={startOAuth}>{busy ? "TUNING…" : `OPEN ${selected.label.toUpperCase()} AUTHORIZATION ↗`}</button>
            ) : (
              <>
                <a href={oauth.url} target="_blank" rel="noreferrer">Authorization opened. Reopen it here ↗</a>
                <label className="contribution-field"><span>Authorization code or callback URL</span><input value={credential} onChange={(event) => setCredential(event.target.value)} autoFocus autoComplete="off" /></label>
              </>
            )}
          </div>
        ) : selected.mode === "json" ? (
          <label className="contribution-field"><span>Grok auth JSON</span><textarea value={credential} onChange={(event) => setCredential(event.target.value)} autoFocus spellCheck={false} /></label>
        ) : (
          <label className="contribution-field"><span>{selected.label} API key</span><input type="password" value={credential} onChange={(event) => setCredential(event.target.value)} autoFocus autoComplete="off" /></label>
        )}
        {error && <div className="access-error" role="alert">{error}</div>}
        <div><button type="button" onClick={onClose}>CANCEL</button>{(selected.mode !== "oauth" || oauth) && <button className="gold-button" disabled={busy || !credential.trim()}>{busy ? "VALIDATING" : "ADD TO POOL"}</button>}</div>
      </form>
    </div>
  );
}

function OperatorUnlock({ onClose, onUnlocked }: { onClose: () => void; onUnlocked: (token: string, accounts: AdminAccount[]) => void }) {
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      onUnlocked(token, await unlockOperator(token));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unlock failed");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="operator-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <form className="operator-dialog" onSubmit={submit} role="dialog" aria-modal="true" aria-labelledby="operator-title">
        <span>PRIVILEGED FREQUENCY // SESSION ONLY</span>
        <h2 id="operator-title">Unlock operator controls</h2>
        <p>The token stays in this tab. Refreshing the planet remains unsupported.</p>
        <input type="password" value={token} onChange={(event) => setToken(event.target.value)} autoFocus aria-label="Admin token" />
        {error && <div className="access-error" role="alert">{error}</div>}
        <div><button type="button" onClick={onClose}>CANCEL</button><button className="gold-button" disabled={busy || !token}>{busy ? "VERIFYING" : "UNLOCK"}</button></div>
      </form>
    </div>
  );
}

function Models({ models }: { models: ModelDescriptor[] }) {
	const [query, setQuery] = useState("");
	const [provider, setProvider] = useState<Provider | "all">("all");
	const [copied, setCopied] = useState("");
	const providers = [...new Set(models.map((model) => model.provider))].sort();
	const normalizedQuery = query.trim().toLowerCase();
	const filtered = models.filter((model) => {
		if (provider !== "all" && model.provider !== provider) return false;
		if (!normalizedQuery) return true;
		return [model.id, model.name, model.upstream_id, ...(model.aliases ?? [])]
			.filter(Boolean)
			.some((value) => String(value).toLowerCase().includes(normalizedQuery));
	});
	const available = models.filter((model) => model.available_now).length;
	const copyID = async (id: string) => {
		try {
			await navigator.clipboard.writeText(id);
			setCopied(id);
			window.setTimeout(() => setCopied(""), 1400);
		} catch {
			setCopied("");
		}
	};
	return (
		<div className="signal-view models-view">
			<div className="view-title"><span>M.00</span><h1>Supported models</h1><p>Exact routing names from the current pool catalog.</p></div>
			<div className="model-summary" aria-label="Model catalog summary">
				<Instrument label="ROUTING NAMES" value={String(models.length)} accent />
				<Instrument label="AVAILABLE NOW" value={String(available)} />
				<Instrument label="PROVIDERS" value={String(providers.length)} />
			</div>
			<div className="model-controls">
				<label><span>SEARCH</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="model name or alias" /></label>
				<div className="model-provider-filter" aria-label="Filter by provider">
					<button className={provider === "all" ? "active" : ""} onClick={() => setProvider("all")}>ALL</button>
					{providers.map((id) => <button key={id} className={provider === id ? "active" : ""} onClick={() => setProvider(id)}>{PROVIDERS[id].label}</button>)}
				</div>
				<span>{filtered.length} MATCHES</span>
			</div>
			<div className="model-table" role="table" aria-label="Supported model routing names">
				<div className="model-row model-head" role="row"><span>ROUTING ID / ALIASES</span><span>PROVIDER</span><span>STATUS</span><span>PROTOCOLS</span><span>CONTEXT</span><span>OUTPUT</span><span>ACCOUNTS</span></div>
				{filtered.map((model) => {
					const reset = model.next_reset_at ? new Date(model.next_reset_at) : null;
					const hasReset = Boolean(reset && !Number.isNaN(reset.valueOf()) && reset.getUTCFullYear() > 2000);
					return <div className="model-row" role="row" key={`${model.provider}:${model.id}`} style={{ "--provider": PROVIDERS[model.provider].color } as CSSProperties}>
						<span className="model-route"><button onClick={() => copyID(model.id)}>{copied === model.id ? "COPIED" : model.id}</button><small>{model.name && model.name !== model.id ? model.name : "canonical"}{model.aliases?.length ? ` // ${model.aliases.join(" // ")}` : ""}</small></span>
						<span className="model-provider">{PROVIDERS[model.provider].label}</span>
						<span className={classNames("model-status", model.available_now ? "available" : "unavailable")}>{model.available_now ? "AVAILABLE" : hasReset && reset ? `RESET ${reset.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}` : "UNAVAILABLE"}{model.stale ? " / STALE" : ""}</span>
						<span>{(model.protocols?.length ? model.protocols : [model.protocol]).join(" / ")}</span>
						<span>{model.contextWindow ? formatTokens(model.contextWindow) : "n/a"}</span>
						<span>{model.max_output_tokens ? formatTokens(model.max_output_tokens) : "n/a"}</span>
						<span>{model.available_accounts ?? 0}/{model.supporting_accounts ?? 0}</span>
					</div>;
				})}
				{filtered.length === 0 && <div className="model-empty">NO ROUTING NAMES MATCH THIS FILTER</div>}
			</div>
		</div>
	);
}

function Setup({ session }: { session: FriendSession }) {
  const [tool, setTool] = useState<"codex" | "claude" | "gemini" | "grok" | "cute" | "pi" | "realtime" | "api">("codex");
	const [piModels, setPiModels] = useState(session.pi_models_json);
	const [cuteCodeSettings, setCuteCodeSettings] = useState(session.cute_code_settings_json);
	useEffect(() => {
		let active = true;
		Promise.all([loadLivePiModels(session.download_token), loadLiveCuteCodeSettings(session.download_token)])
			.then(([nextPiModels, nextCuteCodeSettings]) => {
				if (!active) return;
				setPiModels(nextPiModels);
				setCuteCodeSettings(nextCuteCodeSettings);
			})
			.catch(() => { /* The claim-time snapshot remains usable if regeneration fails. */ });
		return () => { active = false; };
	}, [session.download_token]);
  const setup: Record<typeof tool, { title: string; note: string; commands: Array<[string, string]> }> = {
    codex: { title: "Codex CLI", note: "Automatic installer first. Raw auth remains inspectable because trust issues are healthy.", commands: [["MACOS / LINUX", `curl -sL "${session.public_url}/setup/codex/${session.download_token}" | bash`], ["WINDOWS / POWERSHELL", `irm "${session.public_url}/setup/codex/${session.download_token}?shell=powershell" | iex`], ["AUTH.JSON", session.auth_json]] },
    claude: { title: "Claude Code", note: "Sets the pool endpoint, OAuth token, and skips the ceremony.", commands: [["MACOS / LINUX", `source <(curl -sL "${session.public_url}/setup/claude/${session.download_token}")`], ["WINDOWS / POWERSHELL", `irm "${session.public_url}/setup/claude/${session.download_token}?shell=powershell" | iex`], ["ENV", `export ANTHROPIC_BASE_URL="${session.public_url}"\nexport CLAUDE_CODE_OAUTH_TOKEN="${session.claude_api_key}"`]] },
    gemini: { title: "Gemini CLI", note: "API-key mode. No OAuth scavenger hunt required.", commands: [["MACOS / LINUX", `curl -sL "${session.public_url}/setup/gemini/${session.download_token}" | bash`], ["WINDOWS / POWERSHELL", `irm "${session.public_url}/setup/gemini/${session.download_token}?shell=powershell" | iex`], ["API KEY", session.gemini_api_key]] },
    grok: { title: "Grok Build CLI", note: "Runs Grok entirely through the pool, including the other pool models. Existing Grok OAuth is deactivated and backed up.", commands: [["MACOS / LINUX", `curl -sL "${session.public_url}/setup/grok/${session.download_token}" | bash`], ["WINDOWS / POWERSHELL", `irm "${session.public_url}/setup/grok/${session.download_token}?shell=powershell" | iex`], ["VERIFY", `grok inspect\ngrok models`]] },
	  cute: { title: "Cute Code", note: "Generated from the live catalog. Re-run this installer after pool models change.", commands: [["MACOS / LINUX", `curl -sL "${session.public_url}/setup/cute-code/${session.download_token}" | bash`], ["WINDOWS / POWERSHELL", `irm "${session.public_url}/setup/cute-code/${session.download_token}?shell=powershell" | iex`], ["SETTINGS.JSON", cuteCodeSettings]] },
	  pi: { title: "Pi", note: "Generated from the live catalog. Re-run this installer, then open /model, after pool models change.", commands: [["MACOS / LINUX", `curl -sL "${session.public_url}/setup/pi/${session.download_token}" | bash`], ["WINDOWS / POWERSHELL", `irm "${session.public_url}/setup/pi/${session.download_token}?shell=powershell" | iex`], ["MODELS.JSON", piModels]] },
    realtime: { title: "GPT Realtime 2.1", note: "Verified: the pool mints a short-lived key; WebRTC media goes directly to OpenAI.", commands: [["EPHEMERAL KEY", `curl -sS "${session.public_url}/v1/realtime/client_secrets" \\
  -H "Authorization: Bearer ${session.claude_api_key}" \\
  -H "Content-Type: application/json" \\
  -d '{"session":{"type":"realtime","model":"gpt-realtime-2.1","audio":{"output":{"voice":"marin"}}}}'`], ["VERIFIED VOICE SMOKE", `git clone https://github.com/darvell/codex-pool.git && cd codex-pool
POOL_URL="${session.public_url}" \\
POOL_TOKEN="${session.claude_api_key}" \\
go run ./cmd/realtime-voice-smoke -say 'Say verified and nothing else.'`]] },
    api: { title: "Raw APIs", note: "Anthropic-compatible and OpenAI-compatible. Pick your poison.", commands: [["ANTHROPIC", `export ANTHROPIC_BASE_URL="${session.public_url}"\nexport ANTHROPIC_API_KEY="${session.claude_api_key}"`], ["OPENAI", `export OPENAI_BASE_URL="${session.public_url}/v1"\nexport OPENAI_API_KEY="${session.claude_api_key}"`], ["SMOKE TEST", `curl ${session.public_url}/v1/responses \\\n  -H "Authorization: Bearer ${session.claude_api_key}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"model":"gpt-5.6-luna","input":"Reply with exactly: pool ok"}'`]] },
  };
  return (
    <div className="signal-view setup-view">
      <div className="view-title"><span>S.00</span><h1>Setup frequencies</h1><p>Pick the client. Copy the signal. Pretend this was difficult.</p></div>
      <div className="setup-grid">
        <div className="setup-tools">
          {Object.entries({ codex: "Codex", claude: "Claude", gemini: "Gemini", grok: "Grok Build", cute: "Cute Code", pi: "Pi", realtime: "GPT Realtime", api: "Raw APIs" }).map(([id, label]) => <button key={id} className={tool === id ? "active" : ""} onClick={() => setTool(id as typeof tool)}>{label}</button>)}
        </div>
        <section className="setup-console">
          <span>SIGNAL // {tool.toUpperCase()}</span><h2>{setup[tool].title}</h2><p>{setup[tool].note}</p>
          {setup[tool].commands.map(([label, content]) => <CodeWell key={label} label={label} content={content} />)}
        </section>
      </div>
    </div>
  );
}

function CodeWell({ label, content }: { label: string; content: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };
  return <div className="code-well"><header><span>{label}</span><button onClick={copy}>{copied ? "COPIED" : "COPY"}</button></header><pre>{content}</pre></div>;
}

function EmptyChart({ label }: { label: string }) {
  return <div className="empty-chart"><span>{label}</span><i aria-hidden="true" /></div>;
}

function SignalSkeleton() {
  return <div className="signal-skeleton" aria-label="Loading signal data"><i /><i /><i /><i /></div>;
}
