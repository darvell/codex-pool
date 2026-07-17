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
import type {
  AccountStats,
  AdminAccount,
  FriendSession,
  HourlyUsage,
	ModelDescriptor,
  OriginWeeklyUsage,
  PoolStats,
  Provider,
  SignalAnalytics,
} from "./types";

type View = "pulse" | "usage" | "accounts" | "models" | "setup";

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

function ResetWindow({ label, available, used, resetMinutes, paceRatio, showPace = false }: { label: string; available: boolean; used: number; resetMinutes: number; paceRatio?: number; showPace?: boolean }) {
  if (!available) return <span className="reset-window unavailable"><b>{label}</b><small>NOT REPORTED</small></span>;
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
            <span>PROVIDER / PLAN / ACCOUNT</span><span>STATE</span><span>WEEKLY LIMIT</span><span>RESET WINDOWS</span><span>BANKED RESETS</span><span>BURN</span><span>VALUE</span><span>SPEND</span><span>ROI</span><span>TRACE</span>
          </div>
          {stats.accounts.map((account) => {
            const adminMatch = adminAccounts.find((candidate) => candidate.public_id === account.id);
            const rowID = adminMatch?.id ?? account.id;
            return (
              <button className={classNames("account-row", selected === rowID && "selected")} key={account.id} onClick={() => setSelected(rowID)} style={{ "--provider": PROVIDERS[account.type].color } as CSSProperties}>
                <span className="account-identity"><i>{PROVIDERS[account.type].glyph}</i><b>{PROVIDERS[account.type].label}</b><small><em>{account.plan_type || "unknown plan"}</em><span>{operatorToken && adminMatch ? adminMatch.id : account.id}</span></small></span>
                <span className={`state ${account.status}`}>{account.status === "dead" ? "cooked" : account.status}</span>
                <span className="quota-limit">{account.secondary_window_available ? <><b>{account.secondary_window_used_pct.toFixed(0)}%</b><small>{paceLabel(account.secondary_pace_ratio)}</small></> : "n/a"}</span>
                <span className="account-windows">
                  <ResetWindow label="PRIMARY" available={account.primary_window_available} used={account.primary_window_used_pct} resetMinutes={account.primary_reset_minutes} />
                  <ResetWindow label="WEEKLY" available={account.secondary_window_available} used={account.secondary_window_used_pct} resetMinutes={account.secondary_reset_minutes} />
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
  const [tool, setTool] = useState<"codex" | "claude" | "gemini" | "grok" | "cute" | "pi" | "api">("codex");
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
    api: { title: "Raw APIs", note: "Anthropic-compatible and OpenAI-compatible. Pick your poison.", commands: [["ANTHROPIC", `export ANTHROPIC_BASE_URL="${session.public_url}"\nexport ANTHROPIC_API_KEY="${session.claude_api_key}"`], ["OPENAI", `export OPENAI_BASE_URL="${session.public_url}/v1"\nexport OPENAI_API_KEY="${session.claude_api_key}"`], ["SMOKE TEST", `curl ${session.public_url}/v1/responses \\\n  -H "Authorization: Bearer ${session.claude_api_key}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"model":"gpt-5.6-luna","input":"Reply with exactly: pool ok"}'`]] },
  };
  return (
    <div className="signal-view setup-view">
      <div className="view-title"><span>S.00</span><h1>Setup frequencies</h1><p>Pick the client. Copy the signal. Pretend this was difficult.</p></div>
      <div className="setup-grid">
        <div className="setup-tools">
          {Object.entries({ codex: "Codex", claude: "Claude", gemini: "Gemini", grok: "Grok Build", cute: "Cute Code", pi: "Pi", api: "Raw APIs" }).map(([id, label]) => <button key={id} className={tool === id ? "active" : ""} onClick={() => setTool(id as typeof tool)}>{label}</button>)}
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
