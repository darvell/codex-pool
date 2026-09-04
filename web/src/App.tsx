import { type CSSProperties, type FormEvent, type KeyboardEvent as ReactKeyboardEvent, type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { browserSupportsWebAuthn, startAuthentication, startRegistration } from "@simplewebauthn/browser";
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
	  antigravityOAuthStatus,
  clearFriendSession,
  contributeAPIKey,
  contributeGrok,
  exchangeAccountOAuth,
	  exchangeAntigravityOAuth,
  loadAdminAccounts,
  legacySignup,
	loadModelCatalog,
  loadPoolStats,
  loadSignalAnalytics,
  loadPassportMe,
  exchangeLegacySession,
  passportJoin,
  passportLogin,
  passportLogout,
  beginPasskeyLogin,
  finishPasskeyLogin,
  beginPasskeyRegistration,
  finishPasskeyRegistration,
  loadPasskeys,
  removePasskey,
  redeemMemberRecovery,
  createMemberLink,
  updateMyProfile,
  uploadMyAvatar,
  loadMyClients,
  createMyClient,
  rotateMyClient,
  revealMyClient,
  revokeMyClient,
  loadPasses,
  createPass,
  updatePass,
  revokePass,
  restorePass,
  rotatePassLink,
  loadMyUsage,
  loadConsolePrincipals,
  loadConsolePrincipalUsage,
  loadConsoleAudit,
  loadAnalyticsHealth,
  setPrincipalStatus,
  lockOperator,
  mutateAccount,
  reloadAccounts,
  storedAdminToken,
  storedFriendSession,
  startAccountOAuth,
	  startAntigravityOAuth,
  unlockOperator,
  loadAuthConfig,
  operatorBootstrap,
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
  GuestPass,
  PasskeyCredential,
  PassportPrincipal,
  ClientCredential,
  ConsolePrincipal,
  PassportAuditEntry,
  PassportUsagePoint,
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

type View = "pulse" | "insights" | "mine" | "passes" | "console" | "accounts" | "models" | "setup";
type InsightMode = "overview" | "capacity" | "flow" | "demand";
type HistoryMode = "push" | "replace";

const VIEWS: View[] = ["pulse", "insights", "mine", "passes", "console", "accounts", "models", "setup"];
const INSIGHT_MODES: InsightMode[] = ["overview", "capacity", "flow", "demand"];

export function viewFromSearch(search: string): View {
  const candidate = new URLSearchParams(search).get("view") as View | null;
  return candidate && VIEWS.includes(candidate) ? candidate : "pulse";
}

function queryValue(name: string) {
  return new URLSearchParams(window.location.search).get(name);
}

function updateURL(changes: Record<string, string | null>, mode: HistoryMode = "replace") {
  const url = new URL(window.location.href);
  for (const [name, value] of Object.entries(changes)) {
    if (value) url.searchParams.set(name, value);
    else url.searchParams.delete(name);
  }
  window.history[`${mode}State`](null, "", `${url.pathname}${url.search}${url.hash}`);
}

function allowedViews(principal: PassportPrincipal): View[] {
  if (principal.kind === "operator") return VIEWS;
  if (principal.kind === "guest") return ["mine", "setup"];
  return ["mine", "setup", "passes"];
}

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
  adverserial: { label: "Adverserial", color: "#ff5454", dither: "red", glyph: "◬" },
  opencode_go: { label: "OpenCode Go", color: "#ffd23f", dither: "gold", glyph: "⬢" },
};

const compact = new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 });
const money = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 });
const preciseMoney = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 2 });

export function poolSurplus(aggregate: Pick<PoolStats["aggregate"], "total_api_cost" | "total_subscription_cost">) {
  return aggregate.total_api_cost - aggregate.total_subscription_cost;
}

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
  if (!paceRatio || paceRatio <= 0) return "Pace unavailable";
  return paceRatio >= 1.1 ? `${paceRatio.toFixed(1)}× over pace` : `${paceRatio.toFixed(1)}× within pace`;
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
        <b>—</b><small>{budgetPerDay.toFixed(1)}% daily budget</small><em>Not enough history</em>
      </span>
    );
  }
  const exhaustsEarly = estimate.fullInMinutes < account.secondary_reset_minutes;
  const forecast = exhaustsEarly ? `FULL IN ${formatReset(Math.max(1, Math.floor(estimate.fullInMinutes)))}` : "LASTS TO RESET";
  return (
    <span className={classNames("quota-limit", exhaustsEarly ? "fast" : "safe")} aria-label={`Burning ${estimate.burnPerDay.toFixed(1)} percent per day against a ${budgetPerDay.toFixed(1)} percent daily budget. ${forecast.toLowerCase()}.`}>
      <b>{estimate.burnPerDay.toFixed(1)}% per day</b><small>{budgetPerDay.toFixed(1)}% daily budget</small><em>{forecast === "LASTS TO RESET" ? "Lasts to reset" : forecast.toLowerCase()}</em>
    </span>
  );
}

function ResetWindow({ label, available, used, resetMinutes, paceRatio, showPace = false, compact = false }: { label: string; available: boolean; used: number; resetMinutes: number; paceRatio?: number; showPace?: boolean; compact?: boolean }) {
  if (!available) return <span className={classNames("reset-window unavailable", compact && "compact")}><b>{label}</b><small>NOT REPORTED</small></span>;
  if (compact) return <span className="reset-window compact" aria-label={`${label} ${used.toFixed(0)}%, resets in ${formatReset(resetMinutes)}`}><b>{label}</b><strong>{used.toFixed(0)}%</strong><small>{formatReset(resetMinutes)}</small></span>;
  return <span className="reset-window"><b>{label} {used.toFixed(0)}%</b><small>Resets in {formatReset(resetMinutes)}{showPace ? ` · ${paceLabel(paceRatio)}` : ""}</small></span>;
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
  if (remainingMinutes <= 0) return `${absolute} · expired`;
  const days = Math.floor(remainingMinutes / 1440);
  const hours = Math.floor((remainingMinutes % 1440) / 60);
  const minutes = remainingMinutes % 60;
  const relative = days > 0 ? `${days}D ${hours}H` : hours > 0 ? `${hours}H ${minutes}M` : `${minutes}M`;
  return `${absolute} · in ${relative.toLowerCase()}`;
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
  const [passport, setPassport] = useState<PassportPrincipal | null>(null);
  const [booting, setBooting] = useState(true);
  const [view, setView] = useState<View>(() => viewFromSearch(window.location.search));
  const [pendingJoin, setPendingJoin] = useState<{ token: string; current: PassportPrincipal } | null>(null);
  const [recoveryToken, setRecoveryToken] = useState("");
  const [joinError, setJoinError] = useState("");
  const [stats, setStats] = useState<PoolStats | null>(null);
  const [signal, setSignal] = useState<SignalAnalytics | null>(null);
	const [models, setModels] = useState<ModelDescriptor[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [operatorToken, setOperatorToken] = useState(storedAdminToken());
  const [adminAccounts, setAdminAccounts] = useState<AdminAccount[]>([]);
  const adminLoadVersion = useRef(0);

  const goToView = useCallback((nextView: View, params: Record<string, string | null> = {}) => {
    const cleanup: Record<string, string | null> = { account: null, member: null };
    if (nextView !== "insights") cleanup.insight = null;
    if (nextView !== "accounts") cleanup.accounts = null;
    updateURL({ ...cleanup, view: nextView, ...params }, "push");
    setView(nextView);
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
	  const [nextStats, nextSignal, nextCatalog] = await Promise.all([loadPoolStats(), loadSignalAnalytics(), loadModelCatalog()]);
      setStats(nextStats);
      setSignal(nextSignal);
	  setModels(nextCatalog.models);
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to refresh pool data. Try again.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const boot = async () => {
      const memberToken = window.location.pathname === "/recover" ? decodeURIComponent(window.location.hash.replace(/^#/, "")) : "";
      if (memberToken) {
        window.history.replaceState(null, "", "/recover");
        setRecoveryToken(memberToken);
        return;
      }
      const joinToken = window.location.pathname === "/join" ? decodeURIComponent(window.location.hash.replace(/^#/, "")) : "";
      if (joinToken) {
        window.history.replaceState(null, "", "/");
        try {
          const result = await passportJoin(joinToken);
          if (result.switch_required && result.current) {
            setPendingJoin({ token: joinToken, current: result.current });
            return;
          }
          if (result.principal) {
            setPassport(result.principal);
            setView("mine");
            if (result.principal.kind !== "guest") await refresh();
            return;
          }
        } catch (cause) {
          setJoinError(cause instanceof Error ? cause.message : "This pass is unavailable");
          return;
        }
      }
      try {
        const principal = await loadPassportMe();
        setPassport(principal);
        if (principal.kind === "guest") setView("mine");
        else await refresh();
      } catch {
        const legacy = storedFriendSession();
        if (legacy?.download_token) {
          try {
            const principal = await exchangeLegacySession(legacy.download_token);
            clearFriendSession();
            setPassport(principal);
            setView("mine");
            return;
          } catch {
            clearFriendSession();
          }
        }
      }
    };
    boot().finally(() => setBooting(false));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const restoreView = () => setView(viewFromSearch(window.location.search));
    window.addEventListener("popstate", restoreView);
    return () => window.removeEventListener("popstate", restoreView);
  }, []);

  useEffect(() => {
    updateURL({ view }, "replace");
  }, [view]);

  useEffect(() => {
    if (!passport) return;
    const permitted = allowedViews(passport);
    if (permitted.includes(view)) return;
    const fallback = passport.kind === "operator" ? "pulse" : "mine";
    setView(fallback);
    updateURL({ view: fallback, insight: null, account: null, accounts: null, member: null }, "replace");
  }, [passport, view]);

  useEffect(() => {
    if (!passport || passport.kind === "guest") return;
    refresh();
    const timer = window.setInterval(refresh, 30_000);
    return () => window.clearInterval(timer);
  }, [passport, refresh]);

  useEffect(() => {
    const version = ++adminLoadVersion.current;
    if (!operatorToken) {
      setAdminAccounts([]);
      return;
    }
    loadAdminAccounts()
      .then((accounts) => {
        if (version === adminLoadVersion.current && storedAdminToken() === operatorToken) setAdminAccounts(accounts);
      })
      .catch(() => {
        if (version !== adminLoadVersion.current) return;
        lockOperator();
        setOperatorToken("");
        setAdminAccounts([]);
      });
    return () => { adminLoadVersion.current++; };
  }, [operatorToken]);

  if (booting) return <BootScreen />;
  if (recoveryToken && !passport) return <MemberRecovery token={recoveryToken} onAccess={(next) => { setRecoveryToken(""); setPassport(next); setView("mine"); refresh(); }} />;
  if (pendingJoin) {
    return <JoinSwitch current={pendingJoin.current} onCancel={() => { setPassport(pendingJoin.current); setView("mine"); setPendingJoin(null); }} onConfirm={async () => {
      try {
        const result = await passportJoin(pendingJoin.token, true);
        if (result.principal) {
          setPassport(result.principal);
          setPendingJoin(null);
          setView("mine");
        }
      } catch (cause) {
        setPendingJoin(null);
        setJoinError(cause instanceof Error ? cause.message : "This pass is unavailable");
      }
    }} />;
  }
  if (!passport) {
    return joinError ? <JoinUnavailable /> : <AccessGate onAccess={(next) => { setPassport(next); setView(next.kind === "guest" ? "mine" : "pulse"); if (next.kind !== "guest") refresh(); }} />;
  }

  const signOut = async () => {
    if (passport) await passportLogout().catch(() => undefined);
    adminLoadVersion.current++;
    clearFriendSession();
    lockOperator();
    setOperatorToken("");
    setAdminAccounts([]);
    setPassport(null);
    setStats(null);
    setSignal(null);
    setModels([]);
    updateURL({ view: null, insight: null, account: null, accounts: null, member: null }, "replace");
  };

  return (
    <div className="signal-app">
      <Header
        stats={stats}
        loading={loading}
        operator={Boolean(operatorToken)}
        onRefresh={passport?.kind === "guest" ? undefined : refresh}
        onLock={() => { adminLoadVersion.current++; lockOperator(); setOperatorToken(""); setAdminAccounts([]); }}
      />
      <div className="app-grid">
        <Navigation view={view} principal={passport} onChange={goToView} onSignOut={signOut} />
        <main className="signal-main" id="main-content">
          {error && <div className="signal-error" role="alert"> {error}</div>}
          {view === "pulse" && <Pulse stats={stats} signal={signal} onAccounts={() => goToView("accounts", { accounts: "attention" })} />}
          {view === "insights" && <Insights stats={stats} signal={signal} onAccounts={() => goToView("accounts", { accounts: null })} />}
          {view === "mine" && <PassportMine principal={passport} onPrincipal={setPassport} />}
          {view === "passes" && passport && passport.kind !== "guest" && <Passes />}
          {view === "console" && passport && passport.kind !== "guest" && <PassportConsole principal={passport} />}
          {view === "accounts" && (
            <Accounts
              stats={stats}
              adminAccounts={adminAccounts}
              operatorToken={operatorToken}
              onUnlocked={(token, accounts) => { setOperatorToken(token); setAdminAccounts(accounts); }}
              onAccountsChanged={async () => {
                const version = ++adminLoadVersion.current;
                const token = operatorToken;
                if (!token) {
                  await refresh();
                  return;
                }
                const [accounts] = await Promise.all([loadAdminAccounts(), refresh()]);
                if (version === adminLoadVersion.current && storedAdminToken() === token) setAdminAccounts(accounts);
              }}
            />
          )}
		  {view === "models" && <Models models={models} />}
          {view === "setup" && <SetupPage />}
        </main>
      </div>
    </div>
  );
}

// Every unauthenticated screen shares one composition: the crest carries the
// identity at full size, the panel carries the single task. Boot has no task,
// so it shows the crest alone rather than an empty panel.
function Threshold({ title, lede, children }: { title: string; lede?: string; children?: ReactNode }) {
  return (
    <div className="threshold">
      <div className="threshold-crest" aria-hidden="true" />
      <div className="threshold-panel">
        <div className="threshold-body">
          <h1>{title}</h1>
          {lede && <p className="threshold-lede">{lede}</p>}
          {children}
        </div>
      </div>
    </div>
  );
}

function BootScreen() {
  return (
    <div className="threshold booting">
      <div className="threshold-crest" aria-hidden="true" />
      <p className="threshold-booting" role="status">Restoring your session…</p>
    </div>
  );
}

function JoinUnavailable() {
  return (
    <Threshold title="Pass unavailable" lede="This invitation has expired or been revoked. Ask whoever sent it to issue a new one.">
      <div className="threshold-actions">
        <button className="threshold-submit" onClick={() => { window.history.replaceState(null, "", "/"); window.location.reload(); }}>Go to sign in</button>
      </div>
    </Threshold>
  );
}

function JoinSwitch({ current, onConfirm, onCancel }: { current: PassportPrincipal; onConfirm: () => void | Promise<void>; onCancel: () => void }) {
  const who = current.display_name || current.email || current.id.slice(0, 8);
  return (
    <Threshold title="Switch accounts?" lede={`You are signed in as ${who}. Accepting this pass replaces that session in this browser.`}>
      <div className="threshold-actions">
        <button className="threshold-submit" onClick={onConfirm}>Accept the pass</button>
        <button type="button" className="threshold-alt" onClick={onCancel}>Stay signed in as {who}</button>
      </div>
    </Threshold>
  );
}

function MemberRecovery({ token, onAccess }: { token: string; onAccess: (principal: PassportPrincipal) => void }) {
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [confirmationTouched, setConfirmationTouched] = useState(false);
  const mismatch = confirmationTouched && password !== confirmation;
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setConfirmationTouched(true);
    if (password !== confirmation) { setError("Passwords must match."); return; }
    setBusy(true); setError("");
    try { onAccess(await redeemMemberRecovery(token, password)); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "This recovery link is unavailable."); }
    finally { setBusy(false); }
  };
  return (
    <Threshold title="Set your password" lede="This link works once and expires 30 minutes after it was issued.">
      <form className="threshold-form" onSubmit={submit}>
        <label className="threshold-field">
          <span>New password<i>12 characters minimum</i></span>
          <input type="password" minLength={12} autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} required autoFocus />
        </label>
        <label className={classNames("threshold-field", mismatch && "invalid")}>
          <span>Confirm password</span>
          <input type="password" minLength={12} autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} onBlur={() => setConfirmationTouched(true)} aria-invalid={mismatch} aria-describedby={mismatch ? "password-match-hint" : undefined} required />
          {mismatch && <em id="password-match-hint" className="threshold-hint">Passwords must match.</em>}
        </label>
        {error && <p className="threshold-error" role="alert">{error}</p>}
        <button className="threshold-submit" disabled={busy}>{busy ? "Setting…" : "Set password"}</button>
      </form>
    </Threshold>
  );
}

function AccessGate({ onAccess }: { onAccess: (principal: PassportPrincipal) => void }) {
  const [mode, setMode] = useState<"login" | "signup" | "bootstrap">("login");
  const [authConfig, setAuthConfig] = useState<{ legacy_signup: boolean; operator_exists: boolean } | null>(null);
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    loadAuthConfig().then((config) => {
      setAuthConfig(config);
      if (!config.operator_exists) setMode("bootstrap");
    }).catch(() => {});
  }, []);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (mode === "bootstrap") {
        const principal = await operatorBootstrap(username, email, password, displayName);
        onAccess(principal);
      } else if (mode === "signup") {
        const legacy = storedFriendSession();
        const principal = await legacySignup(code, username, password, legacy?.download_token || "");
        clearFriendSession();
        onAccess(principal);
      } else {
        onAccess(await passportLogin(email.trim(), password));
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Access denied");
    } finally {
      setBusy(false);
    }
  };
  const passkey = async () => {
    setBusy(true); setError("");
    try {
      const begin = await beginPasskeyLogin();
      const credential = await startAuthentication({ optionsJSON: begin.options });
      onAccess(await finishPasskeyLogin(begin.challenge_id, credential));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Passkey sign-in failed");
    } finally { setBusy(false); }
  };

  const showLegacy = authConfig?.legacy_signup && mode !== "bootstrap";
  const passkeyAvailable = mode === "login" && browserSupportsWebAuthn();

  if (mode === "bootstrap") {
    return (
      <Threshold title="Set up this pool" lede="Create the operator account to manage members and pool access.">
        <form onSubmit={submit} className="threshold-form">
          <label className="threshold-field">
            <span>Email</span>
            <input value={email} onChange={(event) => setEmail(event.target.value)} type="email" required autoFocus autoComplete="email" />
          </label>
          <label className="threshold-field">
            <span>Username<i>letters, numbers, . _ -</i></span>
            <input value={username} onChange={(event) => setUsername(event.target.value)} minLength={3} maxLength={32} pattern="[A-Za-z0-9._-]+" required autoComplete="username" />
          </label>
          <label className="threshold-field">
            <span>Display name<i>optional</i></span>
            <input value={displayName} onChange={(event) => setDisplayName(event.target.value)} maxLength={48} autoComplete="name" placeholder="How you appear to members" />
          </label>
          <label className="threshold-field">
            <span>Password<i>12 characters minimum</i></span>
            <input value={password} onChange={(event) => setPassword(event.target.value)} type="password" minLength={12} required autoComplete="new-password" />
          </label>
          {error && <p className="threshold-error" role="alert">{error}</p>}
          <button className="threshold-submit" disabled={busy}>{busy ? "Creating…" : "Create operator account"}</button>
        </form>
      </Threshold>
    );
  }

  return (
    <Threshold title={mode === "signup" ? "Claim your account" : "Sign in"} lede={mode === "signup" ? "Exchange the pool code you were given for a permanent account." : undefined}>
      <form onSubmit={submit} className="threshold-form">
        {mode === "signup" ? (
          <>
            <label className="threshold-field">
              <span>Pool code</span>
              <input value={code} onChange={(event) => setCode(event.target.value)} type="password" required autoFocus autoComplete="off" />
            </label>
            <label className="threshold-field">
              <span>Choose a username<i>letters, numbers, . _ -</i></span>
              <input value={username} onChange={(event) => setUsername(event.target.value)} minLength={3} maxLength={32} pattern="[A-Za-z0-9._-]+" required autoComplete="username" />
            </label>
          </>
        ) : (
          <label className="threshold-field">
            <span>Username or email</span>
            <input value={email} onChange={(event) => setEmail(event.target.value)} required autoFocus autoComplete="username" />
          </label>
        )}
        <label className="threshold-field">
          <span>Password{mode === "signup" && <i>12 characters minimum</i>}</span>
          <input value={password} onChange={(event) => setPassword(event.target.value)} type="password" minLength={mode === "signup" ? 12 : undefined} required autoComplete={mode === "signup" ? "new-password" : "current-password"} />
        </label>
        {error && <p className="threshold-error" role="alert">{error}</p>}
        <button className="threshold-submit" disabled={busy}>{busy ? (mode === "signup" ? "Creating…" : "Signing in…") : mode === "signup" ? "Create account" : "Sign in"}</button>
        {passkeyAvailable && <button type="button" className="threshold-alt" disabled={busy} onClick={passkey}>Use a passkey instead</button>}
      </form>
      <div className="threshold-aside">
        {showLegacy && (
          <button type="button" className="threshold-link" disabled={busy} onClick={() => { setMode(mode === "login" ? "signup" : "login"); setError(""); setPassword(""); }}>
            {mode === "login" ? "Have an old pool code?" : "Back to sign in"}
          </button>
        )}
        {mode === "login" && <p>Locked out? Ask the operator for a recovery link.</p>}
      </div>
    </Threshold>
  );
}

function PassportMine({ principal, onPrincipal }: { principal: PassportPrincipal; onPrincipal: (principal: PassportPrincipal) => void }) {
  const [clients, setClients] = useState<ClientCredential[]>([]);
  const [passkeys, setPasskeys] = useState<PasskeyCredential[]>([]);
  const [usage, setUsage] = useState<PassportUsagePoint[]>([]);
  const [clientsLoading, setClientsLoading] = useState(true);
  const [usageLoading, setUsageLoading] = useState(true);
  const [passkeysLoading, setPasskeysLoading] = useState(principal.kind !== "guest");
  const [label, setLabel] = useState("");
  const [nickname, setNickname] = useState(principal.display_name || "");
  const [passkeyPassword, setPasskeyPassword] = useState("");
  const [passkeyLabel, setPasskeyLabel] = useState("");
  const [setupFor, setSetupFor] = useState<string | null>(null);
  const [setupToken, setSetupToken] = useState("");
  const [setupPlatform, setSetupPlatform] = useState("codex");
  const [showMint, setShowMint] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [busy, setBusy] = useState("");
  const [notice, setNotice] = useState("");
  const [errors, setErrors] = useState({ clients: "", usage: "", passkeys: "", profile: "" });

  const loadClientsData = useCallback(async () => {
    setClientsLoading(true);
    try {
      setClients(await loadMyClients());
      setErrors((current) => ({ ...current, clients: "" }));
    } catch (cause) {
      setErrors((current) => ({ ...current, clients: cause instanceof Error ? cause.message : "Unable to load clients" }));
    } finally {
      setClientsLoading(false);
    }
  }, []);

  const loadUsageData = useCallback(async () => {
    setUsageLoading(true);
    try {
      const result = await loadMyUsage();
      setUsage(result.hourly);
      setErrors((current) => ({ ...current, usage: "" }));
    } catch (cause) {
      setErrors((current) => ({ ...current, usage: cause instanceof Error ? cause.message : "Unable to load usage" }));
    } finally {
      setUsageLoading(false);
    }
  }, []);

  const loadPasskeysData = useCallback(async () => {
    if (principal.kind === "guest") {
      setPasskeys([]);
      setPasskeysLoading(false);
      return;
    }

    setPasskeysLoading(true);
    try {
      setPasskeys(await loadPasskeys());
      setErrors((current) => ({ ...current, passkeys: "" }));
    } catch (cause) {
      setErrors((current) => ({ ...current, passkeys: cause instanceof Error ? cause.message : "Unable to load passkeys" }));
    } finally {
      setPasskeysLoading(false);
    }
  }, [principal.kind]);

  useEffect(() => {
    void loadClientsData();
    void loadUsageData();
    void loadPasskeysData();
  }, [loadClientsData, loadPasskeysData, loadUsageData]);

  const total = usage.reduce((sum, row) => sum + row.billable_tokens, 0);
  const cost = usage.reduce((sum, row) => sum + row.api_equivalent_cost_usd, 0);
  const chartData = Array.from(usage.reduce((hours, row) => {
    const key = row.hour;
    const existing = hours.get(key) ?? { hour: key, tokens: 0 };
    existing.tokens += row.billable_tokens;
    hours.set(key, existing);
    return hours;
  }, new Map<string, { hour: string; tokens: number }>()).values()).sort((a, b) => a.hour.localeCompare(b.hour));
  const base = window.location.origin;
  const platforms: Record<string, string> = {
    codex: `curl -sL "${base}/setup/codex/${setupToken}" | bash`,
    claude: `source <(curl -sL "${base}/setup/claude/${setupToken}")`,
    gemini: `curl -sL "${base}/setup/gemini/${setupToken}" | bash`,
    grok: `curl -sL "${base}/setup/grok/${setupToken}" | bash`,
    "cute-code": `curl -sL "${base}/setup/cute-code/${setupToken}" | bash`,
    pi: `curl -sL "${base}/setup/pi/${setupToken}" | bash`,
  };

  const reveal = async (clientID: string) => {
    setBusy(`reveal:${clientID}`);
    try {
      const result = await revealMyClient(clientID);
      setSetupFor(clientID);
      setSetupToken(result.setup_token);
      setErrors((current) => ({ ...current, clients: "" }));
    } catch (cause) {
      setErrors((current) => ({ ...current, clients: cause instanceof Error ? cause.message : "Unable to reveal setup" }));
    } finally {
      setBusy("");
    }
  };

  const create = async (event: FormEvent) => {
    event.preventDefault();
    setBusy("create-client");
    try {
      const result = await createMyClient(label);
      setSetupFor(result.id ?? null);
      setSetupToken(result.setup_token);
      setLabel("");
      setShowMint(false);
      await loadClientsData();
    } catch (cause) {
      setErrors((current) => ({ ...current, clients: cause instanceof Error ? cause.message : "Unable to create client" }));
    } finally {
      setBusy("");
    }
  };

  const rotate = async (client: ClientCredential) => {
    if (!window.confirm(client.status === "active"
      ? `Replace the key for ${client.label}? Apps using its current key will stop working. This cannot be undone.`
      : `Restore ${client.label} with a new key? You will need to run setup again.`)) return;
    setBusy(`rotate:${client.id}`);
    try {
      const result = await rotateMyClient(client.id);
      setSetupFor(client.id);
      setSetupToken(result.setup_token);
      setNotice(`${client.label} has a new key. Run setup again on this device.`);
      await loadClientsData();
    } catch (cause) {
      setErrors((current) => ({ ...current, clients: cause instanceof Error ? cause.message : "Unable to rotate client" }));
    } finally {
      setBusy("");
    }
  };

  const revoke = async (client: ClientCredential) => {
    if (!window.confirm(`Revoke ${client.label}? Apps using this key will lose access. This cannot be undone.`)) return;

    setBusy(`revoke:${client.id}`);
    try {
      await revokeMyClient(client.id);
      if (setupFor === client.id) {
        setSetupFor(null);
        setSetupToken("");
      }
      await loadClientsData();
    } catch (cause) {
      setErrors((current) => ({ ...current, clients: cause instanceof Error ? cause.message : "Unable to revoke client" }));
    } finally {
      setBusy("");
    }
  };

  const saveProfile = async (event: FormEvent) => {
    event.preventDefault();
    setBusy("profile");
    try {
      onPrincipal(await updateMyProfile(nickname));
      setErrors((current) => ({ ...current, profile: "" }));
    } catch (cause) {
      setErrors((current) => ({ ...current, profile: cause instanceof Error ? cause.message : "Unable to save profile" }));
    } finally {
      setBusy("");
    }
  };

  const uploadAvatar = async (file?: File) => {
    if (!file) return;

    setBusy("avatar");
    try {
      await uploadMyAvatar(file);
      onPrincipal(await loadPassportMe());
      setErrors((current) => ({ ...current, profile: "" }));
    } catch (cause) {
      setErrors((current) => ({ ...current, profile: cause instanceof Error ? cause.message : "Unable to upload avatar" }));
    } finally {
      setBusy("");
    }
  };

  const registerPasskey = async (event: FormEvent) => {
    event.preventDefault();
    setBusy("passkey");
    try {
      const begin = await beginPasskeyRegistration(passkeyPassword, passkeyLabel || "Passkey");
      const credential = await startRegistration({ optionsJSON: begin.options });
      await finishPasskeyRegistration(begin.challenge_id, credential);
      setPasskeyPassword("");
      setPasskeyLabel("");
      await loadPasskeysData();
    } catch (cause) {
      setErrors((current) => ({ ...current, passkeys: cause instanceof Error ? cause.message : "Unable to add passkey" }));
    } finally {
      setBusy("");
    }
  };

  const deletePasskey = async (passkey: PasskeyCredential) => {
    if (!window.confirm(`Remove ${passkey.label}? You will no longer be able to sign in with this passkey.`)) return;

    setBusy(`passkey:${passkey.id}`);
    try {
      await removePasskey(passkey.id);
      await loadPasskeysData();
    } catch (cause) {
      setErrors((current) => ({ ...current, passkeys: cause instanceof Error ? cause.message : "Unable to remove passkey" }));
    } finally {
      setBusy("");
    }
  };

  const error = Object.values(errors).filter(Boolean).join(" · ");

  return <section className="view-stack mine-page">
    {error && <div className="signal-error" role="alert">{error}</div>}
    {notice && <div className="signal-success" role="status">{notice}</div>}
    <div className="view-title"><h1>Your usage</h1></div>
    <div className="identity-strip">
      <div className="passport-avatar">{principal.avatar_url ? <img src={principal.avatar_url} alt="" /> : <span>{(principal.display_name || principal.email || "G").slice(0, 2).toUpperCase()}</span>}</div>
      <div><strong>{principal.display_name || principal.email || `Guest ${principal.id.slice(0, 8)}`}</strong><small>{principal.kind}</small></div>
      <button className="quiet-button" onClick={() => setShowProfile(!showProfile)}>{showProfile ? "Close profile" : "Edit profile"}</button>
    </div>

    {showProfile && <SignalPanel title="Profile and sign-in security">
      <div className="profile-settings">
        <form className="access-form profile-form" onSubmit={saveProfile}>
          <label><span>Display name</span><input value={nickname} onChange={(event) => setNickname(event.target.value)} maxLength={48} placeholder="How you appear" /></label>
          <button className="gold-button" disabled={busy === "profile"}>{busy === "profile" ? "Saving…" : "Save profile"}</button>
        </form>
        <label className="avatar-upload"><span>Avatar</span><input type="file" accept="image/png,image/jpeg" disabled={busy === "avatar"} onChange={(event) => uploadAvatar(event.target.files?.[0])} /></label>
        {principal.kind !== "guest" && browserSupportsWebAuthn() && <section className="passkey-settings" aria-labelledby="passkey-heading">
          <h3 id="passkey-heading">Passkeys</h3>
          {passkeysLoading ? <div className="empty-state">Loading passkeys…</div> : passkeys.length > 0 && <div className="passkey-list">{passkeys.map((passkey) => <div key={passkey.id}><span><strong>{passkey.label}</strong><small>{passkey.last_used_at ? `Used ${new Date(passkey.last_used_at).toLocaleDateString()}` : `Added ${new Date(passkey.created_at).toLocaleDateString()}`}</small></span><button className="danger-action" disabled={busy === `passkey:${passkey.id}`} onClick={() => deletePasskey(passkey)}>{busy === `passkey:${passkey.id}` ? "Removing…" : "Remove"}</button></div>)}</div>}
          <form className="passkey-form" onSubmit={registerPasskey}>
            <label><span>Passkey label</span><input value={passkeyLabel} onChange={(event) => setPasskeyLabel(event.target.value)} placeholder="MacBook Touch ID" maxLength={80} required /></label>
            <label><span>Password</span><input type="password" value={passkeyPassword} onChange={(event) => setPasskeyPassword(event.target.value)} autoComplete="current-password" required /></label>
            <button className="quiet-button" disabled={busy === "passkey"}>{busy === "passkey" ? "Adding…" : "Add passkey"}</button>
          </form>
        </section>}
      </div>
    </SignalPanel>}

    <section className="mine-clients" aria-labelledby="client-heading">
      <header className="section-heading">
        <div><h2 id="client-heading">Clients</h2><p>Use a separate client for each device.</p></div>
        {!showMint && clients.length > 0 && <button className="quiet-button" onClick={() => setShowMint(true)}>Add client</button>}
      </header>
      {showMint && <form className="access-form client-create" onSubmit={create}>
        <label><span>Label</span><input value={label} onChange={(event) => setLabel(event.target.value)} placeholder="MacBook, server, work laptop…" maxLength={80} required autoFocus /></label>
        <button className="gold-button" disabled={busy === "create-client"}>{busy === "create-client" ? "Creating…" : "Create client"}</button>
        {clients.length > 0 && <button type="button" className="quiet-button" onClick={() => setShowMint(false)}>Cancel</button>}
      </form>}
      {clientsLoading ? <div className="empty-state">Loading clients…</div> : clients.length === 0 && !showMint ? <div className="empty-state client-empty"><p>No client credentials yet.</p><button className="gold-button" onClick={() => setShowMint(true)}>Create first client</button></div> : clients.map((client) => <article key={client.id} className="client-card">
        <div className="client-header">
          <span><strong>{client.label}</strong>{client.status !== "active" && <small>{client.status}</small>}</span>
          <div className="row-actions">
            <button disabled={Boolean(busy) || client.status !== "active"} onClick={() => setupFor === client.id ? (setSetupFor(null), setSetupToken("")) : reveal(client.id)}>{busy === `reveal:${client.id}` ? "Loading…" : setupFor === client.id ? "Hide setup" : "Show setup"}</button>
            <button disabled={Boolean(busy)} onClick={() => rotate(client)}>{busy === `rotate:${client.id}` ? "Updating…" : client.status === "active" ? "Replace key" : "Restore"}</button>
            {client.status === "active" && <button className="danger-action" disabled={Boolean(busy)} onClick={() => revoke(client)}>{busy === `revoke:${client.id}` ? "Revoking…" : "Revoke"}</button>}
          </div>
        </div>
        {setupFor === client.id && setupToken && <div className="setup-secret" role="status">
          <div className="tabs client-platform-tabs">
            {Object.keys(platforms).map((platform) => <button key={platform} className={classNames("tab", setupPlatform === platform && "active")} onClick={() => setSetupPlatform(platform)}>{platform}</button>)}
          </div>
          <code>{platforms[setupPlatform]}</code>
          <CopyButton text={platforms[setupPlatform]} />
        </div>}
      </article>)}
    </section>

    <div className="instrument-grid mine-instruments">
      <Instrument label="7-day billable" value={usageLoading ? "…" : formatTokens(total)} accent />
      <Instrument label="API-equivalent value" value={usageLoading ? "…" : `$${cost.toFixed(2)}`} />
      <Instrument label="Active clients" value={clientsLoading ? "…" : String(clients.filter((client) => client.status === "active").length)} />
    </div>
    <SignalPanel title="Usage · last 7 days">
      {usageLoading ? <div className="empty-state">Loading usage…</div> : chartData.length ? <div className="chart-stage medium"><BarChart data={chartData} config={{ tokens: { label: "Tokens", color: "orange" } }} margins={{ left: 52, bottom: 34 }}><Grid horizontal /><Bar dataKey="tokens" variant="hatched" isClickable /><XAxis dataKey="hour" tickFormatter={(value) => String(value).slice(11, 16)} maxTicks={8} /><YAxis tickFormatter={(value) => compact.format(Number(value))} /><Tooltip /></BarChart></div> : <div className="empty-state">No usage in the last 7 days.</div>}
    </SignalPanel>

  </section>;
}

function CopyButton({ text, label = "Copy", className }: { text: string; label?: string; className?: string }) {
  const [copiedText, setCopiedText] = useState("");
  const [failedText, setFailedText] = useState("");
  const copy = async () => {
    setCopiedText("");
    setFailedText("");
    try {
      await navigator.clipboard.writeText(text);
      setCopiedText(text);
    } catch {
      setFailedText(text);
    }
  };
  return <>
    <button type="button" className={className} onClick={copy} onBlur={() => setCopiedText("")}>{copiedText === text ? "Copied" : label}</button>
    {failedText === text && <span className="access-error" role="alert">Copy failed. Select the text and copy it manually.</span>}
  </>;
}

function SetupPage() {
  const [clients, setClients] = useState<ClientCredential[]>([]);
  const [selected, setSelected] = useState("");
  const [setupToken, setSetupToken] = useState("");
  const [tool, setTool] = useState("codex");
  const [label, setLabel] = useState("");
  const [showMint, setShowMint] = useState(false);
  const [loading, setLoading] = useState(true);
  const [revealing, setRevealing] = useState(false);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState("");
  const revealVersion = useRef(0);
  const base = window.location.origin;

  const reveal = useCallback(async (id: string) => {
    const version = ++revealVersion.current;
    setSelected(id);
    setSetupToken("");
    setRevealing(true);
    setError("");
    try {
      const result = await revealMyClient(id);
      if (version === revealVersion.current) setSetupToken(result.setup_token);
    } catch (cause) {
      if (version === revealVersion.current) setError(cause instanceof Error ? cause.message : "Unable to load setup. Select the client to retry.");
    } finally {
      if (version === revealVersion.current) setRevealing(false);
    }
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const items = await loadMyClients();
      setClients(items);
      const target = items.find(client => client.status === "active");
      if (target) await reveal(target.id);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load clients. Try again.");
    } finally {
      setLoading(false);
    }
  }, [reveal]);
  useEffect(() => { void refresh(); return () => { revealVersion.current++; }; }, [refresh]);

  const create = async (event: FormEvent) => {
    event.preventDefault();
    if (creating) return;
    setCreating(true);
    setError("");
    try {
      const result = await createMyClient(label);
      revealVersion.current++;
      setClients(current => [...current, result]);
      setSelected(result.id);
      setSetupToken(result.setup_token);
      setRevealing(false);
      setLabel("");
      setShowMint(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to create client. Try again.");
    } finally {
      setCreating(false);
    }
  };

  const token = setupToken || "…";
  const cliTools: Record<string, { name: string; install: string; oneliner: string; powershell: string; manual: { file: string; url: string }[] }> = {
    codex: {
      name: "Codex",
      install: "npm install -g @openai/codex    # or: brew install codex",
      oneliner: `curl -sL "${base}/setup/codex/${token}" | bash`,
      powershell: `irm "${base}/setup/codex/${token}?shell=powershell" | iex`,
      manual: [{ file: "~/.codex/auth.json", url: `${base}/config/codex/${token}` }],
    },
    claude: {
      name: "Claude Code",
      install: "npm install -g @anthropic-ai/claude-code",
      oneliner: `source <(curl -sL "${base}/setup/claude/${token}")`,
      powershell: `irm "${base}/setup/claude/${token}?shell=powershell" | iex`,
      manual: [{ file: "~/.claude/settings.json", url: `${base}/config/claude/${token}` }],
    },
    gemini: {
      name: "Gemini",
      install: "npm install -g @google/gemini-cli    # or: brew install gemini-cli",
      oneliner: `curl -sL "${base}/setup/gemini/${token}" | bash`,
      powershell: `irm "${base}/setup/gemini/${token}?shell=powershell" | iex`,
      manual: [{ file: "~/.gemini/oauth_creds.json", url: `${base}/config/gemini/${token}` }],
    },
    grok: {
      name: "Grok",
      install: "npm install -g @xai/grok-cli",
      oneliner: `curl -sL "${base}/setup/grok/${token}" | bash`,
      powershell: `irm "${base}/setup/grok/${token}?shell=powershell" | iex`,
      manual: [{ file: "grok auth", url: `${base}/config/grok/${token}` }],
    },
    "cute-code": {
      name: "Cute Code",
      install: "curl -fsSL https://git.irrigate.cc/pp/cute-code/raw/branch/main/install.sh | bash",
      oneliner: `curl -sL "${base}/setup/cute-code/${token}" | bash`,
      powershell: `irm "${base}/setup/cute-code/${token}?shell=powershell" | iex`,
      manual: [{ file: "~/.claude/settings.json", url: `${base}/config/cute-code/${token}` }],
    },
    pi: {
      name: "Pi",
      install: "npm install -g pi-cli",
      oneliner: `curl -sL "${base}/setup/pi/${token}" | bash`,
      powershell: `irm "${base}/setup/pi/${token}?shell=powershell" | iex`,
      manual: [{ file: "pi models.json", url: `${base}/config/pi/${token}` }],
    },
  };
  const sdkTools: Record<string, { name: string; summary: string; examples: { label: string; code: string }[] }> = {
    anthropic: {
      name: "Anthropic API",
      summary: "Use the pool token as an Anthropic API key. Claude models route natively; GPT/Kimi/MiniMax/GLM/Xiaomi are translated through /v1/messages.",
      examples: [
        { label: "Python SDK", code: `pip install anthropic\n\nfrom anthropic import Anthropic\nclient = Anthropic(base_url="${base}", api_key="${token}")\nmsg = client.messages.create(model="claude-sonnet-5", max_tokens=1024, messages=[{"role": "user", "content": "hello"}])` },
        { label: "Env + curl", code: `export ANTHROPIC_BASE_URL="${base}"\nexport ANTHROPIC_API_KEY="${token}"\n\ncurl "$ANTHROPIC_BASE_URL/v1/messages" \\\n  -H "x-api-key: $ANTHROPIC_API_KEY" \\\n  -H "anthropic-version: 2023-06-01" \\\n  -H "content-type: application/json" \\\n  -d '{"model":"claude-sonnet-5","max_tokens":1024,"messages":[{"role":"user","content":"hello"}]}'` },
      ],
    },
    openai: {
      name: "OpenAI SDK",
      summary: "Works with the official OpenAI SDK, Cursor, Continue, Aider, LiteLLM, and any OpenAI-compatible client. Chat Completions and Responses both work; model names route automatically.",
      examples: [
        { label: "Python SDK", code: `pip install openai\n\nfrom openai import OpenAI\nclient = OpenAI(base_url="${base}/v1", api_key="${token}")\nresp = client.responses.create(model="gpt-6-astra", input="hello")` },
        { label: "TypeScript SDK", code: `npm install openai\n\nimport OpenAI from "openai";\nconst client = new OpenAI({ baseURL: "${base}/v1", apiKey: "${token}" });\nconst resp = await client.responses.create({ model: "gpt-6-astra", input: "hello" });` },
        { label: "curl", code: `curl "${base}/v1/responses" \\\n  -H "Authorization: Bearer ${token}" \\\n  -H "content-type: application/json" \\\n  -d '{"model":"gpt-6-astra","input":"hello"}'` },
      ],
    },
  };
  const modelPills = ["claude-sonnet-5", "claude-opus-5", "gpt-6-astra", "gpt-5.6-sol", "gpt-5.4", "kimi-for-coding", "MiniMax-M3", "glm-5.3", "grok-4.5", "opencode-go/longcat-2.0"];

  const activeTool = cliTools[tool];
  const activeSdk = sdkTools[tool];

  return <section className="signal-view setup-page">
    {error && <div className="signal-error" role="alert">{error}</div>}
    <div className="view-title"><h1>Set up a client</h1></div>
    <section className="setup-client-bar" aria-labelledby="setup-client-title">
      <div><span id="setup-client-title">Client</span></div>
      <div className="setup-clients">
      {clients.map((client) => <button key={client.id} className={classNames("client-pill", selected === client.id && "active", client.status !== "active" && "inactive")} disabled={client.status !== "active" || creating} aria-pressed={selected === client.id} onClick={() => reveal(client.id)}>{client.label}</button>)}
      {!showMint && clients.length > 0 && <button className="client-pill add" onClick={() => setShowMint(true)}>Add client</button>}
        {showMint && <form className="setup-client-create" onSubmit={create}>
          <input aria-label="Client name" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Work laptop" maxLength={80} required autoFocus />
          <button className="gold-button" disabled={creating}>{creating ? "Creating…" : "Add client"}</button>
          <button type="button" className="quiet-button" onClick={() => setShowMint(false)}>Cancel</button>
        </form>}
      </div>
    </section>
    {!loading && !error && !clients.some(client => client.status === "active") && !showMint && <div className="empty-state setup-empty"><p>No active clients. Create one to connect a tool.</p><button className="gold-button" onClick={() => setShowMint(true)}>Create a client</button></div>}
    {loading || revealing ? <div className="empty-state setup-loading" role="status">Loading setup…</div> : error && !setupToken && <button className="quiet-button" onClick={() => selected ? reveal(selected) : refresh()}>Retry setup</button>}
    {setupToken && <>
      <nav className="tool-tabs" aria-label="Tool to configure">
        {Object.keys(cliTools).map((key) => <button key={key} className={classNames("tab", tool === key && "active")} onClick={() => setTool(key)}>{cliTools[key].name}</button>)}
        <span className="tool-tab-divider" aria-hidden="true" />
        {Object.keys(sdkTools).map((key) => <button key={key} className={classNames("tab", tool === key && "active")} onClick={() => setTool(key)}>{sdkTools[key].name}</button>)}
      </nav>
      {activeTool && <div className="tool-detail">
        <header className="tool-heading"><h2>{activeTool.name}</h2></header>
        <section className="setup-step"><span>1</span><div><h3>Install {activeTool.name}</h3><div className="code-wrapper"><div className="code-block"><pre>{activeTool.install}</pre></div><CopyButton className="copy-btn" text={activeTool.install} /></div></div></section>
        <section className="setup-step"><span>2</span><div><h3>Connect it to Codex Pool</h3><p className="step-note">macOS or Linux</p><div className="code-wrapper"><div className="code-block"><pre>{activeTool.oneliner}</pre></div><CopyButton className="copy-btn" text={activeTool.oneliner} /></div><p className="step-note">Windows PowerShell</p><div className="code-wrapper"><div className="code-block"><pre>{activeTool.powershell}</pre></div><CopyButton className="copy-btn" text={activeTool.powershell} /></div></div></section>
        <details className="manual-setup"><summary>Configure files manually</summary><p>Fetch the config file directly and place it yourself.</p>{activeTool.manual.map((item) => <div key={item.file} className="code-wrapper"><div className="code-block"><pre>{`curl -sL "${item.url}"\n# → ${item.file}`}</pre></div><CopyButton className="copy-btn" text={`curl -sL "${item.url}"`} /></div>)}</details>
      </div>}
      {activeSdk && <div className="tool-detail">
        <header className="tool-heading"><h2>{activeSdk.name}</h2><p>{activeSdk.summary}</p></header>
        <div className="api-cards">
          <div className="api-card"><div className="api-card-title">Base URL</div><code>{tool === "openai" ? `${base}/v1` : base}</code></div>
          <div className="api-card"><div className="api-card-title">Authentication</div><code>{tool === "openai" ? "Authorization: Bearer <token>" : "x-api-key: <token>"}</code></div>
        </div>
        {activeSdk.examples.map((ex) => <section className="sdk-example" key={ex.label}><h3>{ex.label}</h3><div className="code-wrapper"><div className="code-block"><pre>{ex.code}</pre></div><CopyButton className="copy-btn" text={ex.code} /></div></section>)}
        <h3 className="models-heading">Model IDs</h3>
        <div className="model-pills">{modelPills.map((m) => <span key={m} className="model-pill">{m}</span>)}</div>
      </div>}
    </>}
  </section>;
}

export function shouldShowPassFormOnLoad(passes: GuestPass[]) {
  return passes.length === 0;
}

function localDateTime(value: string) {
  const date = new Date(value);
  const pad = (part: number) => String(part).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function Passes() {
  const [passes, setPasses] = useState<GuestPass[]>([]);
  const [note, setNote] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [expiry, setExpiry] = useState("");
  const [editing, setEditing] = useState<GuestPass | null>(null);
  const [fresh, setFresh] = useState<{ link: string; setupToken?: string } | null>(null);
  const [showForm, setShowForm] = useState(false);
  const initialLoad = useRef(true);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const refresh = useCallback(async () => {
    try {
      const items = await loadPasses();
      setPasses(items);
      if (initialLoad.current) {
        setShowForm(shouldShowPassFormOnLoad(items));
        initialLoad.current = false;
      }
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load passes. Try again.");
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => { refresh(); }, [refresh]);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      const expiresAt = expiry ? new Date(expiry).toISOString() : null;
      if (editing) {
        await updatePass(editing.id, note, displayName, expiresAt);
      } else {
        const result = await createPass(note, displayName, expiresAt);
        setFresh({ link: result.link, setupToken: result.setup_token });
      }
      setEditing(null); setNote(""); setDisplayName(""); setExpiry(""); setShowForm(false); await refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to save pass. Try again."); }
    finally { setBusy(false); }
  };
  const beginEdit = (pass: GuestPass) => { setEditing(pass); setNote(pass.note); setDisplayName(pass.display_name || ""); setExpiry(pass.expires_at ? localDateTime(pass.expires_at) : ""); setShowForm(true); };
  const act = async (action: () => Promise<unknown>) => {
    if (busy) return;
    setBusy(true);
    setError("");
    try { await action(); await refresh(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Pass action failed. Try again."); }
    finally { setBusy(false); }
  };
  return <section className="view-stack passes-page">
    {error && <div className="signal-error" role="alert">{error}</div>}
    <div className="view-title">
      <h1>Guest passes</h1>
      <p>Share access with an optional expiry.</p>
      {!showForm && <button className="gold-button" onClick={() => { setEditing(null); setNote(""); setDisplayName(""); setExpiry(""); setShowForm(true); }}>Create a pass</button>}
    </div>
    {fresh && <div className="setup-secret"><code>{window.location.origin + fresh.link}</code><CopyButton text={window.location.origin + fresh.link} label="Copy link" />{fresh.setupToken && <details><summary>Setup token</summary><code>{fresh.setupToken}</code><CopyButton text={fresh.setupToken} label="Copy token" /></details>}</div>}
    {showForm && <form className="pass-form" onSubmit={submit}>
      <label><span>Who is this for?</span><textarea value={note} onChange={(e) => setNote(e.target.value)} maxLength={300} placeholder="Dave from climbing" required /></label>
      <label><span>Name (optional)</span><input value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={48} placeholder="Dave" /></label>
      <label><span>Expiry (optional)</span><input type="datetime-local" value={expiry} onChange={(e) => setExpiry(e.target.value)} /></label>
      <div className="join-actions"><button className="gold-button" disabled={busy}>{busy ? "Saving…" : editing ? "Save changes" : "Create pass"}</button><button type="button" className="quiet-button" onClick={() => { setShowForm(false); setEditing(null); }}>Cancel</button></div>
    </form>}
    <div className="pass-list" role="list" aria-label="Guest passes">
      {loading ? <div className="empty-state" role="status">Loading passes…</div> : passes.length === 0 ? (!showForm && <div className="empty-state">{error ? <button className="quiet-button" onClick={refresh}>Retry loading passes</button> : "No passes yet."}</div>) : passes.map((pass) => <article className="pass-row" role="listitem" key={pass.id}>
        <div className="passport-avatar small">{pass.avatar_url ? <img src={pass.avatar_url} alt="" /> : <span>{(pass.display_name || "G").slice(0, 2).toUpperCase()}</span>}</div>
        <div className="pass-identity"><strong>{pass.note}</strong><span>{pass.display_name || pass.id.slice(0, 8)}</span><small>{pass.expires_at ? `Expires ${new Date(pass.expires_at).toLocaleDateString()}` : "No expiry"} · {pass.clients} client{pass.clients === 1 ? "" : "s"}</small></div>
        <span className={classNames("pass-status", pass.status !== "active" && "inactive")}>{pass.status !== "active" ? pass.status : ""}</span>
        <div className="row-actions"><CopyButton text={window.location.origin + pass.link} label="Copy link" /><button disabled={busy} onClick={() => beginEdit(pass)}>Edit</button><button disabled={busy} onClick={() => window.confirm(`Replace the invitation link for ${pass.note}? The old link will stop working.`) && act(async () => { const result = await rotatePassLink(pass.id); setFresh({ link: result.link }); })}>Replace link</button>{pass.status === "active" ? <button className="danger-action" disabled={busy} onClick={() => window.confirm(`Revoke access for ${pass.note}? Their ${pass.clients} client${pass.clients === 1 ? "" : "s"} will lose pool access.`) && act(() => revokePass(pass.id))}>Revoke</button> : <button disabled={busy} onClick={() => act(() => restorePass(pass.id))}>Restore</button>}</div>
      </article>)}
    </div>
  </section>;
}

function PassportConsole({ principal }: { principal: PassportPrincipal }) {
  const [principals, setPrincipals] = useState<ConsolePrincipal[]>([]);
  const [audit, setAudit] = useState<PassportAuditEntry[]>([]);
  const [selected, setSelected] = useState<ConsolePrincipal | null>(null);
  const [usage, setUsage] = useState<PassportUsagePoint[]>([]);
  const [usageLoading, setUsageLoading] = useState(false);
  const [health, setHealth] = useState<Awaited<ReturnType<typeof loadAnalyticsHealth>> | null>(null);
  const [hours, setHours] = useState(168);
  const [memberQuery, setMemberQuery] = useState("");
  const [memberEmail, setMemberEmail] = useState("");
  const [memberName, setMemberName] = useState("");
  const [memberLink, setMemberLink] = useState<{ label: string; link: string } | null>(null);
  const [showMemberForm, setShowMemberForm] = useState(false);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const usageLoadVersion = useRef(0);

  const refresh = useCallback(async () => {
    try {
      const [ranking, entries, analyticsHealth] = await Promise.all([loadConsolePrincipals(hours), loadConsoleAudit(), loadAnalyticsHealth()]);
      setPrincipals(ranking.principals);
      setAudit(entries);
      setHealth(analyticsHealth);
      setError("");
      setSelected((current) => {
        const requestedID = queryValue("member") || current?.id;
        return requestedID ? ranking.principals.find((item) => item.id === requestedID) || ranking.principals[0] || null : ranking.principals[0] || null;
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load console");
    }
  }, [hours]);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => {
    if (selected) updateURL({ member: selected.id }, "replace");
  }, [selected]);
  useEffect(() => {
    const restoreMember = () => {
      const requestedID = queryValue("member");
      setSelected(requestedID ? principals.find((item) => item.id === requestedID) || principals[0] || null : principals[0] || null);
    };
    window.addEventListener("popstate", restoreMember);
    return () => window.removeEventListener("popstate", restoreMember);
  }, [principals]);
  useEffect(() => {
    const version = ++usageLoadVersion.current;
    if (!selected) {
      setUsage([]);
      setUsageLoading(false);
      return;
    }

    setUsage([]);
    setUsageLoading(true);
    loadConsolePrincipalUsage(selected.id, hours)
      .then((result) => {
        if (version === usageLoadVersion.current) setUsage(result.hourly);
      })
      .catch((cause) => {
        if (version === usageLoadVersion.current) setError(cause instanceof Error ? cause.message : "Unable to load principal usage");
      })
      .finally(() => {
        if (version === usageLoadVersion.current) setUsageLoading(false);
      });

    return () => { usageLoadVersion.current++; };
  }, [selected, hours]);

  const changeStatus = async (target: ConsolePrincipal) => {
    const status = target.status === "active" ? "suspended" : "active";
    if (!window.confirm(`${status === "suspended" ? "Suspend" : "Restore"} ${target.note || target.display_name || target.id}? ${status === "suspended" ? "Their clients will lose pool access until restored." : "Their active clients will regain pool access."}`)) return;

    setBusy(`status:${target.id}`);
    try {
      await setPrincipalStatus(target.id, status);
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Status change failed");
    } finally {
      setBusy("");
    }
  };

  const issueMemberLink = async (event: FormEvent) => {
    event.preventDefault();
    setBusy("onboard");
    try {
      const result = await createMemberLink(memberEmail, memberName, "onboard");
      setMemberLink({ label: `Invite link for ${memberName || memberEmail}`, link: result.link });
      setMemberEmail("");
      setMemberName("");
      setShowMemberForm(false);
      setError("");
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to create member link");
    } finally {
      setBusy("");
    }
  };

  const issueRecovery = async (target: ConsolePrincipal) => {
    if (!target.email) {
      setError("This member has no email address to recover.");
      return;
    }

    setBusy(`recover:${target.id}`);
    try {
      const result = await createMemberLink(target.email, target.display_name ?? "", "recover");
      setMemberLink({ label: `Recovery link for ${target.display_name || target.email}`, link: result.link });
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to create recovery link");
    } finally {
      setBusy("");
    }
  };

  const total = principals.reduce((sum, item) => sum + item.billable_tokens, 0);
  const normalizedMemberQuery = memberQuery.trim().toLowerCase();
  const filteredPrincipals = principals.filter((item) => !normalizedMemberQuery || [item.note, item.display_name, item.email, item.username, item.id, item.kind, item.status].some((value) => value?.toLowerCase().includes(normalizedMemberQuery)));
  const chartData = usage.map((row) => ({ hour: row.hour, tokens: row.billable_tokens, cost: row.api_equivalent_cost_usd }));
  const windowLabel = hours === 24 ? "24 hours" : hours === 168 ? "7 days" : hours === 720 ? "30 days" : "1 year";
  const auditLabel = (action: string) => action.split(".").map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(" ");

  return <section className="view-stack members-page">
    {error && <div className="signal-error" role="alert">{error}</div>}
    <div className="view-title">
      <h1>Members</h1>
      {principal.kind === "operator" && !showMemberForm && <button className="quiet-button" onClick={() => setShowMemberForm(true)}>Add member</button>}
    </div>
    {showMemberForm && principal.kind === "operator" && <div className="member-admin">
      <form className="access-form" onSubmit={issueMemberLink}>
        <label><span>Email</span><input type="email" value={memberEmail} onChange={(event) => setMemberEmail(event.target.value)} required /></label>
        <label><span>Name</span><input value={memberName} onChange={(event) => setMemberName(event.target.value)} maxLength={48} /></label>
        <button className="gold-button" disabled={busy === "onboard"}>{busy === "onboard" ? "Creating…" : "Create invite link"}</button>
        <button type="button" className="quiet-button" onClick={() => setShowMemberForm(false)}>Cancel</button>
      </form>
    </div>}
    {memberLink && <div className="setup-secret member-link-result" role="status"><span>{memberLink.label}</span><code>{memberLink.link}</code><CopyButton text={memberLink.link} label="Copy link" /><small>Expires in 30 minutes. Send privately; it works once.</small></div>}
    <div className="console-toolbar">
      <div><strong>{principals.length}</strong><span>Members and guests</span></div>
      <div><strong>{formatTokens(total)}</strong><span>Tokens in window</span></div>
      <label><span>Window</span><select value={hours} onChange={(event) => setHours(Number(event.target.value))}><option value={24}>24 hours</option><option value={168}>7 days</option><option value={720}>30 days</option><option value={8760}>1 year</option></select></label>
      <div className={classNames("analytics-health", health?.health.state.toLowerCase())}><strong>{health?.health.state || "…"}</strong><span>Outbox {health?.health.outbox_depth ?? "–"}</span></div>
    </div>
    {health?.active_gap && <div className="accounting-gap" role="alert"><strong>Accounting gap open since {new Date(health.active_gap.started_at).toLocaleString()}</strong><span>Traffic is still being served. Totals spanning this interval are incomplete.</span></div>}
    {health?.health.state === "FAULTED" && <div className="accounting-gap" role="alert"><strong>Analytics reconciliation failed</strong><span>{health.health.fault || health.health.last_reconciliation?.detail}</span></div>}
    <label className="member-search"><span>Search members</span><input value={memberQuery} onChange={(event) => setMemberQuery(event.target.value)} placeholder="Name, email, role, or status" /></label>
    <div className="console-layout">
      <div className="principal-roster" role="list" aria-label="Members and guests ranked by usage">
        {filteredPrincipals.length === 0 && <div className="empty-state">{principals.length === 0 ? "No members or guests yet." : "No members match this search."}</div>}
        {filteredPrincipals.map((item, index) => {
          const primary = item.note || item.display_name || item.email || item.id;
          const secondary = item.email && item.email !== primary ? item.email : `${item.kind} · ${item.id.slice(0, 8)}`;
          return <button className={classNames("principal-row", selected?.id === item.id && "selected", item.status !== "active" && "inactive")} key={item.id} onClick={() => { updateURL({ member: item.id }, "push"); setSelected(item); }} aria-label={`Open ${primary}`}>
            <span className="rank">{String(index + 1).padStart(2, "0")}</span>
            <span className="passport-avatar small">{item.avatar_url ? <img src={item.avatar_url} alt="" /> : (item.display_name || item.email || "G").slice(0, 2).toUpperCase()}</span>
            <span className="principal-copy"><strong>{primary}</strong><small>{secondary}</small></span>
            <span className="principal-usage"><strong>{formatTokens(item.billable_tokens)}</strong><small>{preciseMoney.format(item.api_equivalent_cost_usd)}</small></span>
            <span className={classNames("pass-status", item.status !== "active" && "inactive")}>{item.status !== "active" ? item.status : ""}</span>
          </button>;
        })}
      </div>
      <aside className="principal-detail">
        {!selected ? <div className="empty-state">Select a member or guest to view usage.</div> : <>
          <div className="detail-heading">
            <div><span>{selected.kind}</span><h3>{selected.note || selected.display_name || selected.id}</h3><p>{selected.display_name || selected.email || selected.id}</p></div>
            {principal.kind === "operator" && selected.kind !== "operator" && <div className="detail-actions">
              {selected.kind === "member" && <button className="quiet-button" disabled={busy === `recover:${selected.id}`} onClick={() => issueRecovery(selected)}>{busy === `recover:${selected.id}` ? "Creating…" : "Recovery link"}</button>}
              <button className={selected.status === "active" ? "danger-action" : "quiet-button"} disabled={busy === `status:${selected.id}`} onClick={() => changeStatus(selected)}>{busy === `status:${selected.id}` ? "Updating…" : selected.status === "active" ? "Suspend" : "Restore"}</button>
            </div>}
          </div>
          <div className="detail-facts"><span>Last seen <b>{selected.last_seen_at ? new Date(selected.last_seen_at).toLocaleDateString() : "Never"}</b></span><span>Requests <b>{selected.request_count.toLocaleString()}</b></span><span>Value <b>{preciseMoney.format(selected.api_equivalent_cost_usd)}</b></span>{selected.expires_at && <span>Expires <b>{new Date(selected.expires_at).toLocaleDateString()}</b></span>}</div>
          <SignalPanel title={`Usage · ${windowLabel}`}>{usageLoading ? <div className="empty-state">Loading usage…</div> : chartData.length ? <div className="chart-stage medium"><AreaChart data={chartData} config={{ tokens: { label: "Tokens", color: "orange" } }} margins={{ left: 52, bottom: 34 }}><Grid horizontal /><Area dataKey="tokens" variant="hatched" isClickable /><XAxis dataKey="hour" tickFormatter={(value) => String(value).slice(5, 13)} maxTicks={7} /><YAxis tickFormatter={(value) => compact.format(Number(value))} /><Tooltip /></AreaChart></div> : <div className="empty-state">No usage in this period.</div>}</SignalPanel>
        </>}
      </aside>
    </div>
    <details className="audit-disclosure">
      <summary>Audit log <span>{audit.length}</span></summary>
      <div className="audit-list" role="log" aria-label="Recent account actions">{audit.length === 0 ? <div className="empty-state">No actions recorded.</div> : audit.slice(0, 50).map((entry) => <div key={entry.id}><time>{new Date(entry.at).toLocaleString()}</time><strong>{auditLabel(entry.action)}</strong><small>{entry.detail || "No additional detail."}</small><details><summary>Technical details</summary><code>Actor {entry.actor_id} · Subject {entry.subject_id}</code></details></div>)}</div>
    </details>
  </section>;
}

function Header({ stats, loading, operator, onRefresh, onLock }: {
  stats: PoolStats | null;
  loading: boolean;
  operator: boolean;
  onRefresh?: () => void;
  onLock: () => void;
}) {
  const generated = stats ? new Date(stats.generated_at) : null;
  return (
    <header className="command-rail">
      <a href="#main-content" className="skip-link">Skip to content</a>
      <div className="command-brand">
        <span className="command-mark" aria-hidden="true" />
        <div className="command-brand-copy">
          <span>Codex Pool</span>
          <em>Shared model access</em>
        </div>
      </div>
      <div className="rail-readouts">
        {stats && <span>{stats.active_accounts} of {stats.total_accounts} accounts live</span>}
        {stats && <span>{formatTokens(stats.last_24h_tokens)} tokens today</span>}
        {generated && <span>Updated {generated.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}</span>}
        {onRefresh && <button onClick={onRefresh} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</button>}
        {operator && <button className="operator-live" onClick={onLock}><span className="desktop-label">Lock operator</span><span className="mobile-label">Lock</span></button>}
      </div>
    </header>
  );
}

type NavGroup = { label: string; items: Array<[View, string]> };

function Navigation({ view, principal, onChange, onSignOut }: { view: View; principal: PassportPrincipal | null; onChange: (view: View) => void; onSignOut: () => void | Promise<void> }) {
  const groups: NavGroup[] = principal?.kind === "guest"
    ? [{ label: "Your access", items: [["mine", "Usage"], ["setup", "Setup"]] }]
    : principal?.kind === "operator"
    ? [
        { label: "Operate", items: [["pulse", "Pool status"], ["insights", "Insights"], ["models", "Models"]] },
        { label: "Manage", items: [["accounts", "Accounts"], ["passes", "Guest passes"], ["console", "Members"]] },
        { label: "Personal", items: [["mine", "Your usage"], ["setup", "Setup"]] },
      ]
    : [
        { label: "Personal", items: [["mine", "Your usage"], ["setup", "Setup"]] },
        { label: "Sharing", items: [["passes", "Guest passes"]] },
      ];
  return (
    <nav className="signal-nav" aria-label="Codex Pool">
      <div className="mobile-nav">
        <label>
          <span>Workspace</span>
          <select value={view} onChange={(event) => onChange(event.target.value as View)}>
            {groups.map((group) => <optgroup label={group.label} key={group.label}>{group.items.map(([id, label]) => <option key={id} value={id}>{label}</option>)}</optgroup>)}
          </select>
        </label>
        <button onClick={onSignOut}>Sign out</button>
      </div>
      <div className="nav-groups">
        {groups.map((group) => (
          <section className="nav-group" key={group.label} aria-label={group.label}>
            <h2>{group.label}</h2>
            {group.items.map(([id, label]) => (
              <button key={id} className={classNames("nav-item", view === id && "active")} onClick={() => onChange(id)} aria-current={view === id ? "page" : undefined}>
                {label}
              </button>
            ))}
          </section>
        ))}
      </div>
      <div className="nav-account">
        <span>{principal?.display_name || principal?.username || principal?.email || "Pool member"}</span>
        <small>{principal?.kind ?? "member"}</small>
        <button onClick={onSignOut}>Sign out</button>
      </div>
    </nav>
  );
}

function Pulse({ stats, signal, onAccounts }: { stats: PoolStats | null; signal: SignalAnalytics | null; onAccounts: () => void }) {
  if (!stats || !signal) return <SignalSkeleton />;
  const surplus = poolSurplus(stats.aggregate);
  const burn = burnSummary(signal.hourly);
  const intervention = stats.accounts.filter((account) => account.status !== "healthy" || account.secondary_window_used_pct >= 80);

  const generated = new Date(stats.generated_at);
  const healthCopy = intervention.length === 0
    ? "All accounts are within their reported windows."
    : `${intervention.length} ${intervention.length === 1 ? "account needs" : "accounts need"} attention.`;

  return (
    <div className="signal-view pulse-view">
      <header className="pulse-heading">
        <div>
          <h1>Pool status</h1>
          <p>{healthCopy} Data updated {generated.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}.</p>
        </div>
      </header>

      {intervention.length > 0 && (
        <button className="intervention-strip" onClick={onAccounts}>
          <span><strong>{intervention.length}</strong> {intervention.length === 1 ? "account needs attention" : "accounts need attention"}</span>
          <span className="intervention-items">
            {intervention.slice(0, 4).map((account) => {
              const provider = providerDisplay(account.type);
              const state = account.status === "dead" ? "offline" : account.secondary_window_used_pct >= 80 ? `${account.secondary_window_used_pct.toFixed(0)}% weekly used` : account.status;
              return <b key={account.id} style={{ color: provider.color }}>{provider.label}: {state}</b>;
            })}
          </span>
          <i>Review accounts</i>
        </button>
      )}

      <section className="inline-instruments" aria-label="Pool economics and demand">
        <Instrument label="API-equivalent value" value={money.format(stats.aggregate.total_api_cost)} note={`${stats.aggregate.overall_roi.toFixed(2)}× subscription cost`} accent />
        <Instrument label="Subscription spend" value={money.format(stats.aggregate.total_subscription_cost)} note={`${money.format(stats.aggregate.total_subscription_monthly)} per month`} />
        <Instrument label="Net surplus" value={money.format(surplus)} note="API value less subscription spend" accent={surplus >= 0} danger={surplus < 0} />
        <Instrument label="Tokens in 24 hours" value={formatTokens(burn.current24)} note={`${burn.delta >= 0 ? "+" : ""}${burn.delta.toFixed(1)}% from prior day`} danger={burn.delta > 25} />
      </section>

      <SignalPanel title="Provider health and capacity">
        <ProviderLanes accounts={stats.accounts} />
      </SignalPanel>

      <section className="primary-signal-grid">
        <SignalPanel title="Value produced over subscription cost" className="value-panel">
          <ValueGapChart data={signal.economics} />
          <div className="chart-corner-readout">
            <strong>{stats.aggregate.overall_roi.toFixed(2)}×</strong>
            <span>return on cost</span>
            <small>{money.format(stats.aggregate.total_subscription_monthly)} / month</small>
          </div>
        </SignalPanel>
        <SignalPanel title="Token demand by provider" className="burn-panel">
          <BurnChart hourly={signal.hourly} />
          <div className="burn-readout"><span>Now {formatTokens(burn.latestHour)}/h</span><span>14d avg {formatTokens(burn.averageHour)}/h</span></div>
        </SignalPanel>
      </section>

      <section className="lower-signal-grid">
        <SignalPanel title="Token mix, 14 days">
          <TokenComposition hourly={signal.hourly} />
        </SignalPanel>
        <SignalPanel title="Heavy users this week">
          <OriginDrain rows={signal.origin_weekly} />
        </SignalPanel>
      </section>
    </div>
  );
}

function Instrument({ label, value, note, accent, danger }: { label: string; value: string; note?: string; accent?: boolean; danger?: boolean }) {
  return <div className={classNames("instrument", accent && "accent", danger && "danger")}><span>{label}</span><strong>{value}</strong>{note && <small>{note}</small>}</div>;
}

function SignalPanel({ title, className, children }: { title: string; className?: string; children: ReactNode }) {
  return (
    <section className={classNames("signal-panel", className)}>
      <header><h2>{title}</h2></header>
      <div className="panel-body">{children}</div>
    </section>
  );
}

function ValueGapChart({ data }: { data: SignalAnalytics["economics"] }) {
  const chartData = data.map((point) => ({ date: point.date, value: point.cumulative_api_value, spend: point.cumulative_subscription_spend }));
  if (chartData.length < 2) return <EmptyChart label="Waiting for enough cost history to draw this chart." />;
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
  if (data.length < 2 || providers.length === 0) return <EmptyChart label="Waiting for enough provider usage history." />;
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
      <div className="provider-head" aria-hidden="true">
        <span>Provider</span><span>Weekly capacity</span><span>API value</span><span>Spend</span><span>Return</span><span>Trend</span><span>State</span>
      </div>
      {groups.map(({ provider, rows }) => {
        const used = rows.filter((row) => row.secondary_window_available).reduce((sum, row) => sum + row.secondary_window_used_pct, 0) / Math.max(1, rows.filter((row) => row.secondary_window_available).length);
        const value = rows.reduce((sum, row) => sum + row.api_cost_estimate, 0);
        const spend = rows.reduce((sum, row) => sum + row.subscription_spend, 0);
        const roi = spend ? value / spend : 0;
        const spark = rows.map(accountThroughput);
        const status = rows.some((row) => row.status === "dead") ? "cooked" : used > 80 ? "leaning hard" : roi > 2 ? "carrying" : roi < 0.5 && spend ? "paid for" : "live";
        return (
          <div className="provider-lane" key={provider} style={{ "--provider": PROVIDERS[provider].color } as CSSProperties}>
            <div className="provider-name"><span className="provider-mark" aria-hidden="true" /><b>{PROVIDERS[provider].label}</b><small>{rows.length} account{rows.length === 1 ? "" : "s"}</small></div>
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
  if (data.length < 2) return <EmptyChart label="Waiting for enough token history." />;
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
      {origins.length === 0 && <div className="empty-signal">No origin activity has been recorded for this period.</div>}
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
      <footer>{latestWeek ? `Week of ${latestWeek}` : "No weekly data"} · origin IDs are hashed at ingest · {origins.length} active</footer>
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
  if (data.length === 0) return <EmptyChart label="No subscription or API-value history has been recorded yet." />;
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
  if (data.length === 0 || origins.length === 0) return <EmptyChart label="No origin history has been recorded yet." />;
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
  if (data.length < 2) return <EmptyChart label="Waiting for two complete days of demand history." />;
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
            <span className="capacity-provider"><i className="provider-mark" aria-hidden="true" /><b>{PROVIDERS[forecast.provider].label}</b><small>{forecast.measuredAccounts} measured</small></span>
            <span><b>{forecast.loadEquivalents.toFixed(1)}</b><small>ACCOUNT LOAD</small></span>
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

export function providerDisplay(provider: string) {
  return provider in PROVIDERS
    ? PROVIDERS[provider as Provider]
    : { label: "Unknown", color: "#9c967f", dither: "grey" as DitherColor, glyph: "·" };
}

function Insights({ stats, signal, onAccounts }: { stats: PoolStats | null; signal: SignalAnalytics | null; onAccounts: () => void }) {
  const [mode, setMode] = useState<InsightMode>(() => {
    const candidate = queryValue("insight") as InsightMode | null;
    return candidate && INSIGHT_MODES.includes(candidate) ? candidate : "overview";
  });
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const tabs: Array<[InsightMode, string, string]> = [
    ["overview", "Overview", "Risk and recommended actions"],
    ["capacity", "Capacity", "Measured limits, resets, and scenarios"],
    ["flow", "Flow", "Unused supply and routing balance"],
    ["demand", "Demand", "Peaks, models, and concentration"],
  ];

  useEffect(() => updateURL({ insight: mode }, "replace"), [mode]);
  useEffect(() => {
    const restoreMode = () => {
      const candidate = queryValue("insight") as InsightMode | null;
      setMode(candidate && INSIGHT_MODES.includes(candidate) ? candidate : "overview");
    };
    window.addEventListener("popstate", restoreMode);
    return () => window.removeEventListener("popstate", restoreMode);
  }, []);

  const chooseMode = (nextMode: InsightMode) => {
    if (nextMode === mode) return;
    updateURL({ insight: nextMode }, "push");
    setMode(nextMode);
  };

  const handleTabKey = (event: ReactKeyboardEvent<HTMLButtonElement>, index: number) => {
    let next = index;
    if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
    else if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = tabs.length - 1;
    else return;

    event.preventDefault();
    chooseMode(tabs[next][0]);
    tabRefs.current[next]?.focus();
  };

  if (!stats || !signal) return <SignalSkeleton />;

  return (
    <div className="signal-view insights-view">
      <div className="view-title"><h1>Capacity planning</h1><p>Forecast demand, find unused capacity, and decide when accounts need to be added.</p></div>
      <nav className="insight-tabs" aria-label="Insights dashboards" role="tablist">
        {tabs.map(([id, label, description], index) => (
          <button
            key={id}
            ref={(node) => { tabRefs.current[index] = node; }}
            id={`insight-tab-${id}`}
            className={mode === id ? "active" : ""}
            onClick={() => chooseMode(id)}
            onKeyDown={(event) => handleTabKey(event, index)}
            role="tab"
            aria-controls={`insight-panel-${id}`}
            aria-selected={mode === id}
            tabIndex={mode === id ? 0 : -1}
          >
            <b>{label}</b><small>{description}</small>
          </button>
        ))}
      </nav>
      <div id={`insight-panel-${mode}`} role="tabpanel" aria-labelledby={`insight-tab-${mode}`} tabIndex={0}>
        {mode === "overview" && <InsightsOverview stats={stats} signal={signal} onAccounts={onAccounts} />}
        {mode === "capacity" && <CapacityDashboard stats={stats} signal={signal} onAccounts={onAccounts} />}
        {mode === "flow" && <FlowDashboard stats={stats} signal={signal} onAccounts={onAccounts} />}
        {mode === "demand" && <DemandDashboard stats={stats} signal={signal} />}
      </div>
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
  if (data.length === 0) return <EmptyChart label="A weekly quota change is required before capacity can be estimated." />;
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
            <span className="evidence-plan"><i className="provider-mark" aria-hidden="true" /><b>{provider.label}</b><small>{row.plan_type}</small></span>
            <span><b>{formatTokens(row.estimated_weekly_tokens)}</b><small>OBSERVED MIX</small></span>
            <span><b>{formatTokens(row.low_estimate_tokens)}–{formatTokens(row.high_estimate_tokens)}</b><small>MIDDLE 50% RANGE</small></span>
            <span><b>{row.observed_quota_pct.toFixed(1)}%</b><small>{row.interval_count} TICKS</small></span>
            <span className={`confidence ${row.confidence}`}><b>{row.confidence}</b><small>{row.request_count} REQUESTS</small></span>
          </div>
        );
      })}
      <footer>Estimated from complete intervals between weekly quota changes. The range is observed, not provider-published.</footer>
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
              <i className="provider-mark" style={{ "--provider": provider.color } as CSSProperties} aria-hidden="true" />
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
              <i className="provider-mark" style={{ "--provider": provider.color } as CSSProperties} aria-hidden="true" />
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
        {rows.map((row) => <div key={row.provider} style={{ "--provider": PROVIDERS[row.provider].color } as CSSProperties}><b><i className="provider-mark" aria-hidden="true" /> {PROVIDERS[row.provider].label}</b><span>{row.scenarioLoad.toFixed(1)} account-equivalent demand</span><span>{row.activeAccounts} active</span><strong>{row.add ? `+${row.add} REQUIRED` : `${row.required} REQUIRED`}</strong></div>)}
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
          <span><i className="provider-mark" aria-hidden="true" /><b>{row.model}</b><small>{provider.label}</small></span>
          <span><b>{row.observed_quota_pct.toFixed(1)}%</b><small>{row.interval_count} intervals</small></span>
          <span><b>{preciseMoney.format(row.api_value)}</b><small>{formatTokens(row.tokens)} tok</small></span>
          <span><b>{preciseMoney.format(row.api_value_per_quota_pct)}</b><small>API-EQUIV</small></span>
          <span className={row.relative_subsidy >= 1 ? "favorable" : "costly"}><b>{row.relative_subsidy.toFixed(2)}×</b><small>{row.relative_subsidy >= 1 ? "MORE SUBSIDIZED" : "LESS SUBSIDIZED"}</small></span>
          <span className={`confidence ${row.confidence}`}><b>{row.confidence}</b></span>
        </div>;
      })}
      {eligible.length === 0 && <div className="empty-signal">Model efficiency needs priced requests observed across a quota change.</div>}
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
        <SignalPanel title="Observed weekly token capacity"><CapacityHistoryChart rows={signal.quota_capacity} /></SignalPanel>
        <SignalPanel title="Latest capacity evidence"><CapacityEvidenceTable rows={signal.quota_capacity} /></SignalPanel>
      </section>
      <SignalPanel title="Capacity calendar"><ResetCalendar stats={stats} forecasts={forecasts} observations={signal.reset_observations} /></SignalPanel>
      <section className="capacity-lower-grid">
        <SignalPanel title="Demand and reserve planner"><ScenarioPlanner forecasts={forecasts} onAccounts={onAccounts} /></SignalPanel>
        <SignalPanel title="API value per quota point"><ModelSubsidyTable rows={signal.model_efficiency} /></SignalPanel>
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
          <span><i className="provider-mark" aria-hidden="true" /><b>{provider.label}</b><small>{row.id.slice(-7)}</small></span>
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
        <SignalPanel title="Projected account utilization"><AccountFlowTable rows={flows} /></SignalPanel>
        <SignalPanel title="Routing balance by provider">
          <div className="routing-calls">
            {routingCalls.map((call) => <div className={call.score < 60 ? "risk" : ""} key={call.provider} style={{ "--provider": PROVIDERS[call.provider].color } as CSSProperties}>
              <span><i className="provider-mark" aria-hidden="true" /><b>{PROVIDERS[call.provider].label}</b><small>{call.score.toFixed(0)}/100 balance</small></span>
              <p>{call.hot && call.cold && call.hot.id !== call.cold.id && call.spread > 20 ? <>Shift new traffic from <b>{call.hot.id.slice(-5)}</b> toward <b>{call.cold.id.slice(-5)}</b>; projected utilization differs by {call.spread.toFixed(0)} points.</> : <>Current accounts are draining within a reasonable range.</>}</p>
            </div>)}
          </div>
        </SignalPanel>
      </section>
      <section className="flow-lower-grid">
        <SignalPanel title="Capacity likely to reset unused">
          <div className="stranded-list">
            {flows.filter((row) => row.strandedPct >= 20).slice(0, 10).map((row) => <div key={row.id}><span className="provider-mark" style={{ "--provider": PROVIDERS[row.provider].color } as CSSProperties} aria-hidden="true" /><b>{PROVIDERS[row.provider].label} {row.id.slice(-5)}</b><div><i style={{ width: `${row.strandedPct}%` }} /></div><strong>{row.strandedPct.toFixed(0)}% UNUSED</strong></div>)}
            {flows.every((row) => row.strandedPct < 20) && <div className="empty-signal">NO MATERIAL STRANDED WEEKLY CAPACITY</div>}
          </div>
        </SignalPanel>
        <SignalPanel title="Current routing health">
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
      {models.length === 0 && <div className="empty-signal">No model demand history has been recorded yet.</div>}
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
        <SignalPanel title="Peak demand by hour"><PeakDemandHeatmap hourly={signal.hourly} /></SignalPanel>
        <SignalPanel title="Model mix over 14 days"><ModelDemandTable rows={signal.model_daily} /></SignalPanel>
      </section>
      <section className="demand-lower-grid">
        <SignalPanel title="Usage concentration this week">
          <div className="concentration-board">
            <div className="concentration-gauge" style={{ "--share": `${concentration.topOriginShare}%` } as CSSProperties}><strong>{concentration.topOriginShare.toFixed(1)}%</strong><span>TOP ORIGIN</span></div>
            <div><span>ACTIVE ORIGINS</span><b>{concentration.origins}</b></div><div><span>TOP THREE</span><b>{concentration.topThreeShare.toFixed(1)}%</b></div><div><span>GINI</span><b>{concentration.gini.toFixed(2)}</b></div>
            <p>{concentration.topOriginShare > 40 ? "Demand is concentrated enough that one workload can materially change account requirements." : "Demand is distributed; broad pool growth matters more than a single origin."}</p>
          </div>
        </SignalPanel>
        <SignalPanel title="Opportunities to conserve capacity"><ConservationBoard stats={stats} signal={signal} /></SignalPanel>
      </section>
    </div>
  );
}

function InsightsOverview({ stats, signal, onAccounts }: { stats: PoolStats; signal: SignalAnalytics; onAccounts: () => void }) {
  const demand = demandSummary(signal.hourly);
  const forecasts = capacityForecasts(stats.accounts);
  const minimumAdds = forecasts.reduce((sum, forecast) => sum + forecast.minimumToAdd, 0);
  const bufferedAdds = forecasts.reduce((sum, forecast) => sum + forecast.bufferedToAdd, 0);
  const required = forecasts.filter((forecast) => forecast.minimumToAdd > 0);
  const reserves = forecasts.filter((forecast) => forecast.bufferedToAdd > 0);
  const directiveForecasts = minimumAdds > 0 ? required : reserves;
  const directiveBreakdown = directiveForecasts.map((forecast) => {
    const count = minimumAdds > 0 ? forecast.minimumToAdd : forecast.bufferedToAdd;
    return `${PROVIDERS[forecast.provider].label.toUpperCase()} ${count}`;
  }).join(" · ");
  const directiveTitle = minimumAdds > 0
    ? `ADD ${minimumAdds} ACCOUNT${minimumAdds === 1 ? "" : "S"} NOW`
    : bufferedAdds > 0
      ? `ADD ${bufferedAdds} ACCOUNT${bufferedAdds === 1 ? "" : "S"} FOR RESERVE`
      : forecasts.length > 0 ? "CURRENT CAPACITY HOLDS" : "WAITING FOR WEEKLY QUOTA HISTORY";
  const directiveDetail = minimumAdds > 0
    ? `${directiveBreakdown}. The 20% reserve target is +${bufferedAdds} total.`
    : bufferedAdds > 0
      ? `${directiveBreakdown}. Baseline demand is covered; these additions establish the 20% reserve.`
      : forecasts.length > 0
        ? "Observed weekly drain is covered with the 20% operating reserve intact."
        : "No provider is reporting enough weekly-window history yet.";
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
        <span>Recommended action</span>
        <strong>{directiveTitle}</strong>
        <p>{directiveDetail}</p>
        <button onClick={onAccounts}>OPEN ACCOUNTS →</button>
      </section>

      <section className="insights-grid">
        <SignalPanel title="Daily demand and three-day trend"><DemandTrendChart hourly={signal.hourly} /></SignalPanel>
        <SignalPanel title="Account capacity at the current pace"><CapacityForecastTable forecasts={forecasts} /></SignalPanel>
      </section>

      <section className="insight-method">
        <b>HOW THE ACCOUNT NUMBER WORKS</b>
        <span>For each provider: sum <code>weekly used % ÷ expected used % by now</code>, then round up. “+20%” adds an operating reserve. Recommendations use {sampleDays.toFixed(1)} observed account-days and update every 30 seconds.</span>
        {unmodeled.length > 0 && <span>Unmodeled: {unmodeled.map((provider) => PROVIDERS[provider].label).join(" · ")}. Their tokens appear in demand trends, but they do not report a weekly limit.</span>}
      </section>
    </>
  );
}

type AccountAction = "enable" | "disable" | "resurrect" | "refresh";
type ArmedAccountAction = { accountID: string; kind: AccountAction } | null;

export function isArmedAccountAction(action: ArmedAccountAction, accountID: string, kind: AccountAction) {
  return action?.accountID === accountID && action.kind === kind;
}

function Accounts({ stats, adminAccounts, operatorToken, onUnlocked, onAccountsChanged }: {
  stats: PoolStats | null;
  adminAccounts: AdminAccount[];
  operatorToken: string;
  onUnlocked: (token: string, accounts: AdminAccount[]) => void;
  onAccountsChanged: () => Promise<void>;
}) {
  const [selected, setSelected] = useState<string | null>(() => queryValue("account"));
  const [query, setQuery] = useState("");
  const [attentionOnly, setAttentionOnly] = useState(() => queryValue("accounts") === "attention");
  const [mobileInspector, setMobileInspector] = useState(() => window.matchMedia("(max-width: 760px)").matches);
  const [unlocking, setUnlocking] = useState(false);
  const [contributing, setContributing] = useState(false);
  const [action, setAction] = useState<ArmedAccountAction>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: "success" | "error"; text: string } | null>(null);
  const inspectorRef = useRef<HTMLElement | null>(null);
  const closeRef = useRef<HTMLButtonElement | null>(null);
  const accountTriggerRef = useRef<HTMLButtonElement | null>(null);
  const previousOperatorToken = useRef(operatorToken);

  const closeInspector = useCallback(() => {
    updateURL({ account: null }, "replace");
    setSelected(null);
    window.requestAnimationFrame(() => accountTriggerRef.current?.focus());
  }, []);

  useEffect(() => { setAction(null); setMessage(null); }, [selected]);
  useEffect(() => {
    if (previousOperatorToken.current !== operatorToken) setSelected(null);
    previousOperatorToken.current = operatorToken;
  }, [operatorToken]);
  useEffect(() => updateURL({ account: selected }, "replace"), [selected]);
  useEffect(() => updateURL({ accounts: attentionOnly ? "attention" : null }, "replace"), [attentionOnly]);
  useEffect(() => {
    const restoreAccountState = () => {
      setSelected(queryValue("account"));
      setAttentionOnly(queryValue("accounts") === "attention");
    };
    window.addEventListener("popstate", restoreAccountState);
    return () => window.removeEventListener("popstate", restoreAccountState);
  }, []);
  useEffect(() => {
    const media = window.matchMedia("(max-width: 760px)");
    const update = () => setMobileInspector(media.matches);
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  useEffect(() => {
    if (!selected || !mobileInspector) return;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.requestAnimationFrame(() => closeRef.current?.focus());

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        closeInspector();
        return;
      }
      if (event.key !== "Tab" || !inspectorRef.current) return;

      const focusable = [...inspectorRef.current.querySelectorAll<HTMLElement>('button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])')];
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [closeInspector, mobileInspector, selected]);

  if (!stats) return <SignalSkeleton />;

  const needsAttention = (account: AccountStats) => account.status !== "healthy" || (account.secondary_window_available && account.secondary_window_used_pct >= 80);
  const normalizedQuery = query.trim().toLowerCase();
  const filteredAccounts = stats.accounts.filter((account) => {
    if (attentionOnly && !needsAttention(account)) return false;
    if (!normalizedQuery) return true;
    const provider = providerDisplay(account.type);
    return [provider.label, account.type, account.plan_type, account.id].some((value) => value?.toLowerCase().includes(normalizedQuery));
  });
  const attentionCount = stats.accounts.filter(needsAttention).length;
  const selectedAdmin = operatorToken ? adminAccounts.find((account) => account.id === selected) ?? null : null;
  const selectedAccount = stats.accounts.find((account) => {
    const adminMatch = operatorToken ? adminAccounts.find((candidate) => candidate.public_id === account.id) : null;
    return (adminMatch?.id ?? account.id) === selected;
  }) ?? null;
  const toggleAction: AccountAction | null = selectedAdmin ? selectedAdmin.disabled ? "enable" : "disable" : null;

  const perform = async (nextAction: AccountAction) => {
    if (!selectedAdmin) return;
    if (!isArmedAccountAction(action, selectedAdmin.id, nextAction)) {
      setAction({ accountID: selectedAdmin.id, kind: nextAction });
      return;
    }
    setBusy(true);
    try {
      await mutateAccount(selectedAdmin.id, nextAction);
      setMessage({ tone: "success", text: `${selectedAdmin.id} ${nextAction} complete` });
      setAction(null);
      await onAccountsChanged();
    } catch (cause) {
      setMessage({ tone: "error", text: cause instanceof Error ? cause.message : "Action failed" });
    } finally {
      setBusy(false);
    }
  };

  const reloadPool = async () => {
    setBusy(true);
    setMessage(null);
    try {
      await reloadAccounts();
      await onAccountsChanged();
      setMessage({ tone: "success", text: "Pool accounts reloaded" });
    } catch (cause) {
      setMessage({ tone: "error", text: cause instanceof Error ? cause.message : "Unable to reload pool accounts" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="signal-view accounts-view">
      <div className="view-title account-title">
        <h1>Accounts</h1>
        <div className="account-title-actions">
          <button className="contribute-button" onClick={() => setContributing(true)}>Add pool account</button>
          {!operatorToken && <button className="unlock-button" onClick={() => setUnlocking(true)}>Unlock controls</button>}
          {operatorToken && <button className="operator-badge" disabled={busy} onClick={reloadPool}>{busy ? "Reloading…" : "Reload pool"}</button>}
        </div>
      </div>
      {message && <div className={classNames("account-message", message.tone)} role="status" aria-live="polite">{message.text}</div>}
      <section className="account-filters" aria-label="Filter accounts">
        <label><span>Search accounts</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Provider, plan, or account ID" /></label>
        <div>
          <button className={!attentionOnly ? "active" : ""} aria-pressed={!attentionOnly} onClick={() => { updateURL({ accounts: null }, "push"); setAttentionOnly(false); }}>All <b>{stats.accounts.length}</b></button>
          <button className={attentionOnly ? "active" : ""} aria-pressed={attentionOnly} onClick={() => { updateURL({ accounts: "attention" }, "push"); setAttentionOnly(true); }}>Needs attention <b>{attentionCount}</b></button>
        </div>
      </section>
      <div className={classNames("accounts-layout", selected && "inspecting")}>
        <div className="account-table" role="list" aria-label="Provider accounts" aria-hidden={mobileInspector && Boolean(selected) ? true : undefined}>
          <div className="account-row account-head" aria-hidden="true">
            <span>Provider / plan / account</span><span>State</span><span>Weekly pace</span><span>Reset windows</span><span>24h burn</span><span>Return</span><span>Trend</span>
          </div>
          {filteredAccounts.length === 0 && <div className="empty-state">{stats.accounts.length === 0 ? "No provider accounts are connected." : "No accounts match this filter."}</div>}
          {filteredAccounts.map((account) => {
            const adminMatch = operatorToken ? adminAccounts.find((candidate) => candidate.public_id === account.id) : undefined;
            const rowID = adminMatch?.id ?? account.id;
            const provider = providerDisplay(account.type);
            return (
              <button
                className={classNames("account-row", selected === rowID && "selected")}
                key={account.id}
                onClick={(event) => { accountTriggerRef.current = event.currentTarget; updateURL({ account: rowID }, "push"); setSelected(rowID); }}
                style={{ "--provider": provider.color } as CSSProperties}
                aria-label={`Open ${provider.label} ${account.plan_type || "account"} details`}
              >
                <span className="account-identity"><i className="provider-mark" aria-hidden="true" /><b>{provider.label}</b><small><em>{account.plan_type || "unknown plan"}</em><span>{operatorToken && adminMatch ? adminMatch.id : account.id}</span></small></span>
                <span className={`state ${account.status}`} data-label="State">{account.status === "dead" ? "offline" : account.status}</span>
                <span className="account-pace" data-label="Weekly pace"><WeeklyPace account={account} /></span>
                <span className="account-windows" data-label="Reset windows">
                  <ResetWindow label="Primary" available={account.primary_window_available} used={account.primary_window_used_pct} resetMinutes={account.primary_reset_minutes} compact />
                  <ResetWindow label="Weekly" available={account.secondary_window_available} used={account.secondary_window_used_pct} resetMinutes={account.secondary_reset_minutes} compact />
                </span>
                <span data-label="24h burn">{formatTokens(accountThroughput(account))}</span>
                <strong data-label="Return">{account.subscription_spend ? `${account.roi.toFixed(2)}×` : "—"}</strong>
                <span className="account-spark" aria-hidden="true"><Sparkline data={[0, account.total_input_tokens, accountThroughput(account), account.total_output_tokens]} color={provider.dither} /></span>
              </button>
            );
          })}
        </div>
        {selected && (
          <aside
            ref={inspectorRef}
            className="account-inspector"
            role={mobileInspector ? "dialog" : "complementary"}
            aria-modal={mobileInspector ? true : undefined}
            aria-label={selectedAccount ? `Account details for ${selectedAccount.id}` : "Account details"}
          >
            <button ref={closeRef} className="inspector-close" onClick={closeInspector} aria-label="Close account details">Close</button>
            {selectedAccount ? (
              <>
                <span className="inspector-code">Account details</span>
                <h2 id="account-inspector-title">{selectedAccount.id}</h2>
                <div className="inspector-provider" style={{ color: providerDisplay(selectedAccount.type).color }}>{providerDisplay(selectedAccount.type).label} · {selectedAccount.plan_type}</div>
                <div className="account-admission">Added {formatAdmission(selectedAccount.account_added_at)} · Spend {money.format(selectedAccount.subscription_spend)}</div>
                <div className="inspector-windows" aria-label="Account usage reset windows">
                  <ResetWindow label="Primary window" available={selectedAccount.primary_window_available} used={selectedAccount.primary_window_used_pct} resetMinutes={selectedAccount.primary_reset_minutes} paceRatio={selectedAccount.primary_pace_ratio} showPace />
                  <ResetWindow label="Weekly window" available={selectedAccount.secondary_window_available} used={selectedAccount.secondary_window_used_pct} resetMinutes={selectedAccount.secondary_reset_minutes} paceRatio={selectedAccount.secondary_pace_ratio} showPace />
                </div>
                {selectedAccount.type === "codex" && (
                  <section className="inspector-reset-credits" aria-label="Banked usage resets">
                    <header><span>Banked usage resets</span><strong>{selectedAccount.reset_credits_known ? selectedAccount.reset_credits_available ?? 0 : "—"}</strong></header>
                    <div>{selectedAccount.reset_credits_known ? <ResetCreditExpirations account={selectedAccount} /> : <span>Reset credit data is not reported.</span>}</div>
                    <small>Expiration times use your local timezone.</small>
                  </section>
                )}
                <div className="inspector-metrics">
                  <Instrument label="24h burn" value={formatTokens(accountThroughput(selectedAccount))} accent />
                  <Instrument label="Cache hit rate" value={`${selectedAccount.cache_hit_rate_pct.toFixed(1)}%`} />
                  <Instrument label="API-equivalent value" value={money.format(selectedAccount.api_cost_estimate)} />
                  <Instrument label="Return on cost" value={selectedAccount.subscription_spend ? `${selectedAccount.roi.toFixed(2)}×` : "—"} />
                </div>
                {selectedAdmin ? (
                  <>
                    <span className="inspector-code operator-section">Operator controls · {selectedAdmin.id}</span>
                    <div className="inspector-metrics operator-metrics">
                      <Instrument label="Score" value={selectedAdmin.score.toFixed(2)} accent />
                      <Instrument label="Penalty" value={selectedAdmin.penalty.toFixed(1)} danger={selectedAdmin.penalty > 2} />
                      <Instrument label="In flight" value={String(selectedAdmin.inflight)} />
                      <Instrument label="Primary" value={selectedAdmin.is_primary ? "Yes" : "No"} />
                    </div>
                    <pre className="score-trace">{selectedAdmin.score_tooltip || "No score detail is available."}</pre>
                    <div className="operator-actions">
                      {toggleAction && <button disabled={busy} className={isArmedAccountAction(action, selectedAdmin.id, toggleAction) ? "confirm" : ""} onClick={() => perform(toggleAction)}>{isArmedAccountAction(action, selectedAdmin.id, toggleAction) ? `Confirm ${selectedAdmin.disabled ? "enable" : "disable"}` : selectedAdmin.disabled ? "Enable account" : "Disable account"}</button>}
                      <button disabled={busy || !selectedAdmin.dead} className={isArmedAccountAction(action, selectedAdmin.id, "resurrect") ? "confirm" : ""} onClick={() => perform("resurrect")}>{isArmedAccountAction(action, selectedAdmin.id, "resurrect") ? "Confirm restore" : "Restore offline account"}</button>
                      <button disabled={busy} className={isArmedAccountAction(action, selectedAdmin.id, "refresh") ? "confirm" : ""} onClick={() => perform("refresh")}>{isArmedAccountAction(action, selectedAdmin.id, "refresh") ? "Confirm refresh" : "Refresh credentials"}</button>
                    </div>
                  </>
                ) : (
                  <div className="locked-inspector"><b>Operator controls are locked</b><p>Usage windows and account economics remain visible. Unlock only when you need to change pool state.</p><button onClick={() => setUnlocking(true)}>Unlock controls</button></div>
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

type ContributableProvider = "codex" | "claude" | "antigravity" | "kimi" | "minimax" | "zai" | "xiaomi" | "grok" | "opencode_go";

const CONTRIBUTION_PROVIDERS: Array<{ id: ContributableProvider; label: string; mode: "oauth" | "key" | "json" }> = [
  { id: "codex", label: "Codex", mode: "oauth" },
  { id: "claude", label: "Claude", mode: "oauth" },
	  { id: "antigravity", label: "Google Antigravity", mode: "oauth" },
  { id: "kimi", label: "Kimi", mode: "key" },
  { id: "minimax", label: "MiniMax", mode: "key" },
  { id: "zai", label: "Z.ai", mode: "key" },
  { id: "xiaomi", label: "Xiaomi", mode: "key" },
  { id: "grok", label: "Grok", mode: "json" },
  { id: "opencode_go", label: "OpenCode Go", mode: "key" },
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
        await contributeAPIKey(provider as "kimi" | "minimax" | "zai" | "xiaomi" | "opencode_go", credential);
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
        <h2 id="contribution-title">Add a pool account</h2>
        <p>Other pool members will be able to use this account.</p>
        <div className="contribution-providers" aria-label="Provider">
          {CONTRIBUTION_PROVIDERS.map((candidate) => <button type="button" key={candidate.id} className={provider === candidate.id ? "active" : ""} disabled={busy} aria-pressed={provider === candidate.id} onClick={() => choose(candidate.id)}>{candidate.label}</button>)}
        </div>
        {selected.mode === "oauth" ? (
          <div className="contribution-oauth">
            {!oauth ? (
              <button type="button" className="oauth-launch" disabled={busy} onClick={startOAuth}>{busy ? "Opening…" : `Sign in to ${selected.label}`}</button>
            ) : (
              <>
                <a href={oauth.url} target="_blank" rel="noreferrer">Open sign-in page</a>
                <label className="contribution-field"><span>Authorization code or callback URL</span><input value={credential} onChange={(event) => setCredential(event.target.value)} autoFocus autoComplete="off" required /></label>
              </>
            )}
          </div>
        ) : selected.mode === "json" ? (
          <label className="contribution-field"><span>Grok auth JSON</span><textarea value={credential} onChange={(event) => setCredential(event.target.value)} autoFocus spellCheck={false} required /></label>
        ) : (
          <label className="contribution-field"><span>{selected.label} API key</span><input type="password" value={credential} onChange={(event) => setCredential(event.target.value)} autoFocus autoComplete="off" required /></label>
        )}
        {error && <div className="access-error" role="alert">{error}</div>}
        <div><button type="button" onClick={onClose}>Cancel</button>{(selected.mode !== "oauth" || oauth) && <button className="gold-button" disabled={busy}>{busy ? "Adding…" : "Add to pool"}</button>}</div>
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
        <h2 id="operator-title">Unlock operator controls</h2>
        <p>The admin token stays in this tab and is cleared when you lock operator controls or sign out.</p>
        <input type="password" value={token} onChange={(event) => setToken(event.target.value)} autoFocus aria-label="Admin token" required />
        {error && <div className="access-error" role="alert">{error}</div>}
        <div><button type="button" onClick={onClose}>Cancel</button><button className="gold-button" disabled={busy}>{busy ? "Verifying…" : "Unlock controls"}</button></div>
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
			<div className="view-title"><h1>Supported models</h1><p>Search the routing names accepted by the pool and see whether capacity is available now.</p></div>
			<div className="model-summary" aria-label="Model catalog summary">
				<Instrument label="Routing names" value={String(models.length)} note="canonical IDs and aliases" accent />
				<Instrument label="Available now" value={String(available)} note={`${models.length - available} waiting for capacity`} />
				<Instrument label="Providers" value={String(providers.length)} note="routing automatically" />
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
						<span className="model-route"><button onClick={() => copyID(model.id)}>{copied === model.id ? "COPIED" : model.id}</button><small>{model.name && model.name !== model.id ? model.name : "canonical"}{model.aliases?.length ? ` · ${model.aliases.join(" · ")}` : ""}</small></span>
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


function EmptyChart({ label }: { label: string }) {
  return <div className="empty-chart"><span>{label}</span><i aria-hidden="true" /></div>;
}

function SignalSkeleton() {
  return <div className="signal-skeleton" aria-label="Loading signal data"><i /><i /><i /><i /></div>;
}
