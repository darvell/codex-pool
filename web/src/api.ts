import type { AdminAccount, FriendSession, ModelCatalog, PoolStats, SignalAnalytics } from "./types";

const FRIEND_CODE_KEY = "friendCode";
const FRIEND_EMAIL_KEY = "friendEmail";
const FRIEND_SESSION_KEY = "friendSession";
const ADMIN_TOKEN_KEY = "operatorToken";

export const storedFriendCode = () => localStorage.getItem(FRIEND_CODE_KEY) ?? "";
export const storedFriendEmail = () => localStorage.getItem(FRIEND_EMAIL_KEY) ?? "";
export const storedFriendSession = (): FriendSession | null => {
  try {
    const raw = localStorage.getItem(FRIEND_SESSION_KEY);
    return raw ? (JSON.parse(raw) as FriendSession) : null;
  } catch {
    return null;
  }
};
export const storedAdminToken = () => sessionStorage.getItem(ADMIN_TOKEN_KEY) ?? "";

async function decode<T>(response: Response): Promise<T> {
  const data = (await response.json().catch(() => null)) as T | { error?: string } | null;
  if (!response.ok) {
    const message = data && typeof data === "object" && "error" in data ? data.error : null;
    throw new Error(message || `${response.status} ${response.statusText}`);
  }
  return data as T;
}

export async function claim(friendCode: string, email: string): Promise<FriendSession> {
  const response = await fetch("/api/friend/claim", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ friend_code: friendCode, user_email: email }),
  });
  const session = await decode<FriendSession>(response);
  localStorage.setItem(FRIEND_CODE_KEY, friendCode);
  localStorage.setItem(FRIEND_EMAIL_KEY, email);
  localStorage.setItem(FRIEND_SESSION_KEY, JSON.stringify(session));
  return session;
}

export function clearFriendSession() {
  localStorage.removeItem(FRIEND_CODE_KEY);
  localStorage.removeItem(FRIEND_EMAIL_KEY);
  localStorage.removeItem(FRIEND_SESSION_KEY);
  sessionStorage.removeItem(ADMIN_TOKEN_KEY);
}

function friendHeaders(): HeadersInit {
  return { "X-Friend-Code": storedFriendCode() };
}

export async function loadPoolStats(): Promise<PoolStats> {
  return decode(await fetch("/api/pool/stats", { headers: friendHeaders(), cache: "no-store" }));
}

export async function loadSignalAnalytics(): Promise<SignalAnalytics> {
  const signal = await decode<SignalAnalytics>(await fetch("/api/pool/signal?weeks=6", { headers: friendHeaders(), cache: "no-store" }));
  return {
    ...signal,
    economics: signal.economics ?? [],
    hourly: signal.hourly ?? [],
    origin_weekly: signal.origin_weekly ?? [],
    model_daily: signal.model_daily ?? [],
    quota_capacity: signal.quota_capacity ?? [],
    model_efficiency: signal.model_efficiency ?? [],
    reset_observations: signal.reset_observations ?? [],
    quota_generated_at: signal.quota_generated_at,
  };
}

export async function loadModelCatalog(): Promise<ModelCatalog> {
  const catalog = await decode<ModelCatalog>(await fetch("/api/pool/catalog", { headers: friendHeaders(), cache: "no-store" }));
  return { models: catalog.models ?? [] };
}

export async function loadLivePiModels(downloadToken: string): Promise<string> {
  const config = await decode<unknown>(await fetch(`/config/pi/${encodeURIComponent(downloadToken)}`, { cache: "no-store" }));
  return JSON.stringify(config, null, 2);
}

export async function loadLiveCuteCodeSettings(downloadToken: string): Promise<string> {
  const config = await decode<unknown>(await fetch(`/config/cute-code/${encodeURIComponent(downloadToken)}`, { cache: "no-store" }));
  return JSON.stringify(config, null, 2);
}

export async function unlockOperator(token: string): Promise<AdminAccount[]> {
  const accounts = await decode<AdminAccount[]>(await fetch("/admin/accounts", {
    headers: { "X-Admin-Token": token },
    cache: "no-store",
  }));
  sessionStorage.setItem(ADMIN_TOKEN_KEY, token);
  return accounts;
}

export function lockOperator() {
  sessionStorage.removeItem(ADMIN_TOKEN_KEY);
}

export async function loadAdminAccounts(): Promise<AdminAccount[]> {
  const token = storedAdminToken();
  if (!token) throw new Error("Operator controls are locked");
  return decode(await fetch("/admin/accounts", { headers: { "X-Admin-Token": token }, cache: "no-store" }));
}

export async function mutateAccount(accountID: string, action: "enable" | "disable" | "resurrect" | "refresh") {
  const token = storedAdminToken();
  if (!token) throw new Error("Operator controls are locked");
  return decode<Record<string, unknown>>(await fetch(`/admin/accounts/${encodeURIComponent(accountID)}/${action}`, {
    method: "POST",
    headers: { "X-Admin-Token": token },
  }));
}

export interface AccountContributionResult {
  success?: boolean;
  account_id?: string;
  oauth_url?: string;
  verifier?: string;
  state?: string;
	  session_id?: string;
	  status?: "pending" | "exchanging" | "complete" | "error";
	  error?: string;
}

export async function contributeAPIKey(provider: "kimi" | "minimax" | "zai" | "xiaomi", apiKey: string) {
  return decode<AccountContributionResult>(await fetch(`/api/pool/accounts/${provider}/add`, {
    method: "POST",
    headers: { ...friendHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ api_key: apiKey }),
  }));
}

export async function contributeGrok(authJSON: string) {
  return decode<AccountContributionResult>(await fetch("/api/pool/accounts/grok/add", {
    method: "POST",
    headers: { ...friendHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ auth_json: authJSON }),
  }));
}

export async function startAccountOAuth(provider: "codex" | "claude") {
  return decode<AccountContributionResult>(await fetch(`/api/pool/accounts/${provider}/add`, {
    method: "POST",
    headers: { ...friendHeaders(), "Content-Type": "application/json" },
    body: "{}",
  }));
}

export async function exchangeAccountOAuth(provider: "codex" | "claude", code: string, verifier: string) {
  return decode<AccountContributionResult>(await fetch(`/api/pool/accounts/${provider}/exchange`, {
    method: "POST",
    headers: { ...friendHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ code, verifier }),
  }));
}

export async function startAntigravityOAuth() {
  return decode<AccountContributionResult>(await fetch("/api/pool/accounts/antigravity/add", {
    method: "POST",
    headers: { ...friendHeaders(), "Content-Type": "application/json" },
    body: "{}",
  }));
}

export async function antigravityOAuthStatus(sessionID: string) {
  return decode<AccountContributionResult>(await fetch("/api/pool/accounts/antigravity/status", {
    method: "POST",
    headers: { ...friendHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: sessionID }),
  }));
}

export async function exchangeAntigravityOAuth(sessionID: string, value: string, state: string) {
  const trimmed = value.trim();
  const isCallback = /^https?:\/\//i.test(trimmed);
  return decode<AccountContributionResult>(await fetch("/api/pool/accounts/antigravity/exchange", {
    method: "POST",
    headers: { ...friendHeaders(), "Content-Type": "application/json" },
	    body: JSON.stringify({ session_id: sessionID, ...(isCallback ? { callback_url: trimmed } : { code: trimmed, state }) }),
  }));
}

export async function reloadAccounts() {
  const token = storedAdminToken();
  if (!token) throw new Error("Operator controls are locked");
  const response = await fetch("/admin/reload", { method: "POST", headers: { "X-Admin-Token": token } });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
}
