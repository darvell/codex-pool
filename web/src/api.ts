import type { AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON, RegistrationResponseJSON } from "@simplewebauthn/browser";
import type { AdminAccount, ClientCredential, ConsolePrincipal, FriendSession, GuestPass, ModelCatalog, PasskeyCredential, PassportAuditEntry, PassportPrincipal, PassportUsagePoint, PoolStats, SignalAnalytics } from "./types";

const FRIEND_SESSION_KEY = "friendSession";
const ADMIN_TOKEN_KEY = "operatorToken";

export const storedFriendSession = (): FriendSession | null => {
  try {
    const raw = localStorage.getItem(FRIEND_SESSION_KEY);
    return raw ? (JSON.parse(raw) as FriendSession) : null;
  } catch {
    return null;
  }
};
export const storedAdminToken = () => sessionStorage.getItem(ADMIN_TOKEN_KEY) ?? "";

function csrfToken() {
  return document.cookie.split("; ").find((part) => part.startsWith("pool_csrf="))?.split("=").slice(1).join("=") ?? "";
}

export async function loadAuthConfig(): Promise<{ legacy_signup: boolean; operator_exists: boolean }> {
  return decode(await fetch("/api/auth/config", { credentials: "same-origin" }));
}
export async function operatorBootstrap(username: string, email: string, password: string, displayName = ""): Promise<PassportPrincipal> {
  const result = await decode<{ principal: PassportPrincipal }>(await fetch("/api/setup/operator", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Admin-Token": "ui-bootstrap" }, credentials: "same-origin",
    body: JSON.stringify({ username, email, password, display_name: displayName }),
  }));
  return result.principal;
}
export async function passportLogin(email: string, password: string): Promise<PassportPrincipal> {
  const result = await decode<{ principal: PassportPrincipal }>(await fetch("/api/auth/login", {
    method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin",
    body: JSON.stringify({ email, password }),
  }));
  return result.principal;
}
export async function legacySignup(code: string, username: string, password: string, downloadToken = ""): Promise<PassportPrincipal> {
  const result = await decode<{ principal: PassportPrincipal }>(await fetch("/api/auth/signup", {
    method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin",
    body: JSON.stringify({ code, username, password, download_token: downloadToken }),
  }));
  return result.principal;
}
export async function beginPasskeyLogin(): Promise<{ challenge_id: string; options: PublicKeyCredentialRequestOptionsJSON }> {
  return decode(await fetch("/api/auth/passkey/begin", { method: "POST", credentials: "same-origin" }));
}
export async function finishPasskeyLogin(challengeID: string, credential: AuthenticationResponseJSON): Promise<PassportPrincipal> {
  const result = await decode<{ principal: PassportPrincipal }>(await fetch("/api/auth/passkey/finish", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-WebAuthn-Challenge": challengeID }, body: JSON.stringify(credential) }));
  return result.principal;
}
export async function beginPasskeyRegistration(password: string, label: string): Promise<{ challenge_id: string; options: PublicKeyCredentialCreationOptionsJSON }> {
  return decode(await fetch("/api/me/passkeys/register/begin", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() }, body: JSON.stringify({ password, label }) }));
}
export async function finishPasskeyRegistration(challengeID: string, credential: RegistrationResponseJSON): Promise<void> {
  await decode(await fetch("/api/me/passkeys/register/finish", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken(), "X-WebAuthn-Challenge": challengeID }, body: JSON.stringify(credential) }));
}
export async function loadPasskeys(): Promise<PasskeyCredential[]> {
  return decode(await fetch("/api/me/passkeys", { cache: "no-store", credentials: "same-origin" }));
}
export async function removePasskey(id: string): Promise<void> {
  await decode(await fetch(`/api/me/passkeys/${encodeURIComponent(id)}`, { method: "DELETE", credentials: "same-origin", headers: { "X-CSRF-Token": csrfToken() } }));
}
export async function loadPassportMe(): Promise<PassportPrincipal> {
  return decode(await fetch("/api/auth/me", { cache: "no-store", credentials: "same-origin" }));
}
export async function passportJoin(token: string, switchAccount = false): Promise<{ principal?: PassportPrincipal; switch_required?: boolean; current?: PassportPrincipal }> {
  return decode(await fetch("/api/auth/join", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token, switch: switchAccount }) }));
}
export async function redeemMemberRecovery(token: string, password: string): Promise<PassportPrincipal> {
  const result = await decode<{ principal: PassportPrincipal }>(await fetch("/api/auth/recover", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token, password }) }));
  return result.principal;
}
export async function passportLogout(): Promise<void> {
  await decode(await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrfToken() } }));
}
export async function updateMyProfile(nickname: string): Promise<PassportPrincipal> {
  return decode(await fetch("/api/me/profile", { method: "PATCH", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() }, body: JSON.stringify({ nickname }) }));
}
export async function uploadMyAvatar(file: File): Promise<{ avatar_url: string }> {
  return decode(await fetch("/api/me/avatar", { method: "PUT", credentials: "same-origin", headers: { "Content-Type": file.type || "application/octet-stream", "X-CSRF-Token": csrfToken() }, body: file }));
}
export async function loadMyClients(): Promise<ClientCredential[]> {
  return decode(await fetch("/api/me/clients", { cache: "no-store", credentials: "same-origin" }));
}
export async function createMyClient(label: string): Promise<ClientCredential & { setup_token: string }> {
  return decode(await fetch("/api/me/clients", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() }, body: JSON.stringify({ label }) }));
}
export async function rotateMyClient(id: string): Promise<ClientCredential & { setup_token: string }> {
  return decode(await fetch(`/api/me/clients/${encodeURIComponent(id)}/rotate`, { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrfToken() } }));
}
export async function revealMyClient(id: string): Promise<{ setup_token: string }> {
  return decode(await fetch(`/api/me/clients/${encodeURIComponent(id)}/reveal`, { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrfToken() } }));
}
export async function revokeMyClient(id: string): Promise<void> {
  await decode(await fetch(`/api/me/clients/${encodeURIComponent(id)}`, { method: "DELETE", credentials: "same-origin", headers: { "X-CSRF-Token": csrfToken() } }));
}
export async function loadPasses(): Promise<GuestPass[]> {
  return decode(await fetch("/api/passes", { cache: "no-store", credentials: "same-origin" }));
}
export async function createPass(note: string, displayName: string, expiresAt: string | null): Promise<{ principal: PassportPrincipal; link: string; setup_token: string }> {
  return decode(await fetch("/api/passes", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() }, body: JSON.stringify({ note, display_name: displayName, expires_at: expiresAt }) }));
}
export async function updatePass(id: string, note: string, displayName: string, expiresAt: string | null): Promise<PassportPrincipal> {
  return decode(await fetch(`/api/passes/${encodeURIComponent(id)}`, { method: "PATCH", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() }, body: JSON.stringify({ note, display_name: displayName, expires_at: expiresAt }) }));
}
export async function revokePass(id: string): Promise<void> {
  await decode(await fetch(`/api/passes/${encodeURIComponent(id)}`, { method: "DELETE", credentials: "same-origin", headers: { "X-CSRF-Token": csrfToken() } }));
}
export async function restorePass(id: string): Promise<void> {
  await decode(await fetch(`/api/passes/${encodeURIComponent(id)}/restore`, { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrfToken() } }));
}
export async function rotatePassLink(id: string): Promise<{ link: string }> {
  return decode(await fetch(`/api/passes/${encodeURIComponent(id)}/rotate`, { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrfToken() } }));
}
export async function loadMyUsage(hours = 168): Promise<{ hourly: PassportUsagePoint[]; excludes_passthrough: boolean }> {
  return decode(await fetch(`/api/me/usage?hours=${hours}`, { cache: "no-store", credentials: "same-origin" }));
}
export async function loadConsolePrincipals(hours = 168): Promise<{ principals: ConsolePrincipal[]; hours: number; excludes_passthrough: boolean }> {
  return decode(await fetch(`/api/console/principals?hours=${hours}`, { cache: "no-store", credentials: "same-origin" }));
}
export async function createMemberLink(email: string, displayName: string, purpose: "onboard" | "recover"): Promise<{ principal: PassportPrincipal; link: string; expires_at: string }> {
  return decode(await fetch("/api/console/members", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() }, body: JSON.stringify({ email, display_name: displayName, purpose }) }));
}
export async function loadConsolePrincipalUsage(id: string): Promise<{ principal: PassportPrincipal; hourly: PassportUsagePoint[]; excludes_passthrough: boolean }> {
  const result = await decode<{ principal: PassportPrincipal; hourly: PassportUsagePoint[] | null; excludes_passthrough: boolean }>(await fetch(`/api/console/principals/${encodeURIComponent(id)}/usage`, { cache: "no-store", credentials: "same-origin" }));
  return { ...result, hourly: result.hourly ?? [] };
}
export async function loadConsoleAudit(): Promise<PassportAuditEntry[]> {
  return decode(await fetch("/api/console/audit", { cache: "no-store", credentials: "same-origin" }));
}
export async function loadAnalyticsHealth(): Promise<{ health: { state: "CURRENT" | "LAGGING" | "FAULTED" | "GAP"; outbox_depth: number; oldest_outbox_at?: string; fault?: string; last_reconciliation?: { checked_at: string; clean: boolean; detail?: string } }; accounting_gaps: Array<{ started_at: string; ended_at?: string; reason: string }>; active_gap?: { started_at: string; reason: string } | null }> {
  return decode(await fetch("/api/console/analytics-health", { cache: "no-store", credentials: "same-origin" }));
}
export async function setPrincipalStatus(id: string, status: "active" | "suspended"): Promise<PassportPrincipal> {
  return decode(await fetch(`/api/principals/${encodeURIComponent(id)}`, { method: "PATCH", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() }, body: JSON.stringify({ status }) }));
}

async function decode<T>(response: Response): Promise<T> {
  const data = (await response.json().catch(() => null)) as T | { error?: string } | null;
  if (!response.ok) {
    const message = data && typeof data === "object" && "error" in data ? data.error : null;
    throw new Error(message || `${response.status} ${response.statusText}`);
  }
  return data as T;
}

export async function exchangeLegacySession(downloadToken: string): Promise<PassportPrincipal> {
  const result = await decode<{ principal: PassportPrincipal }>(await fetch("/api/auth/legacy", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ download_token: downloadToken }) }));
  return result.principal;
}

export function clearFriendSession() {
  localStorage.removeItem("friendCode");
  localStorage.removeItem("friendEmail");
  localStorage.removeItem(FRIEND_SESSION_KEY);
  sessionStorage.removeItem(ADMIN_TOKEN_KEY);
}

export async function loadPoolStats(): Promise<PoolStats> {
  return decode(await fetch("/api/pool/stats", { credentials: "same-origin", cache: "no-store" }));
}

export async function loadSignalAnalytics(): Promise<SignalAnalytics> {
  const signal = await decode<SignalAnalytics>(await fetch("/api/pool/signal?weeks=6", { credentials: "same-origin", cache: "no-store" }));
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
  const catalog = await decode<ModelCatalog>(await fetch("/api/pool/catalog", { credentials: "same-origin", cache: "no-store" }));
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
    credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
    body: JSON.stringify({ api_key: apiKey }),
  }));
}

export async function contributeGrok(authJSON: string) {
  return decode<AccountContributionResult>(await fetch("/api/pool/accounts/grok/add", {
    method: "POST",
    credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
    body: JSON.stringify({ auth_json: authJSON }),
  }));
}

export async function startAccountOAuth(provider: "codex" | "claude") {
  return decode<AccountContributionResult>(await fetch(`/api/pool/accounts/${provider}/add`, {
    method: "POST",
    credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
    body: "{}",
  }));
}

export async function exchangeAccountOAuth(provider: "codex" | "claude", code: string, verifier: string) {
  return decode<AccountContributionResult>(await fetch(`/api/pool/accounts/${provider}/exchange`, {
    method: "POST",
    credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
    body: JSON.stringify({ code, verifier }),
  }));
}

export async function startAntigravityOAuth() {
  return decode<AccountContributionResult>(await fetch("/api/pool/accounts/antigravity/add", {
    method: "POST",
    credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
    body: "{}",
  }));
}

export async function antigravityOAuthStatus(sessionID: string) {
  return decode<AccountContributionResult>(await fetch("/api/pool/accounts/antigravity/status", {
    method: "POST",
    credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
    body: JSON.stringify({ session_id: sessionID }),
  }));
}

export async function exchangeAntigravityOAuth(sessionID: string, value: string, state: string) {
  const trimmed = value.trim();
  const isCallback = /^https?:\/\//i.test(trimmed);
  return decode<AccountContributionResult>(await fetch("/api/pool/accounts/antigravity/exchange", {
    method: "POST",
    credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
	    body: JSON.stringify({ session_id: sessionID, ...(isCallback ? { callback_url: trimmed } : { code: trimmed, state }) }),
  }));
}

export async function reloadAccounts() {
  const token = storedAdminToken();
  if (!token) throw new Error("Operator controls are locked");
  const response = await fetch("/admin/reload", { method: "POST", headers: { "X-Admin-Token": token } });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
}
