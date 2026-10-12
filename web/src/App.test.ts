import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { JSDOM } from "jsdom";
import { AccessGate, isArmedAccountAction, OperatorAPIKeys, poolSurplus, providerDisplay, shouldShowPassFormOnLoad, viewFromSearch, watchVibeSession } from "./App";
import { createOperatorAPIToken, loadOperatorAPITokens, operatorBootstrap, replaceOperatorAPIToken, revokeOperatorAPIToken, startVibeLogin, vibeLoginStatus } from "./api";
import type { VibeLoginSession } from "./types";

describe("account action confirmation", () => {
  it("is scoped to both the account and action", () => {
    const armed = { accountID: "account-a", kind: "disable" as const };

    expect(isArmedAccountAction(armed, "account-a", "disable")).toBe(true);
    expect(isArmedAccountAction(armed, "account-b", "disable")).toBe(false);
    expect(isArmedAccountAction(armed, "account-a", "refresh")).toBe(false);
  });
});

describe("poolSurplus", () => {
  it("uses the same account totals shown beside it", () => {
    expect(poolSurplus({ total_api_cost: 5634, total_subscription_cost: 2064 })).toBe(3570);
  });
});

describe("guest pass form", () => {
  it("opens automatically only when the loaded pass list is empty", () => {
    expect(shouldShowPassFormOnLoad([])).toBe(true);
    expect(shouldShowPassFormOnLoad([{ id: "pass_1" } as never])).toBe(false);
  });
});

describe("viewFromSearch", () => {
  it("restores a valid workspace and rejects unknown values", () => {
    expect(viewFromSearch("?view=accounts")).toBe("accounts");
    expect(viewFromSearch("?view=operator-api")).toBe("operator-api");
    expect(viewFromSearch("?view=unknown")).toBe("pulse");
    expect(viewFromSearch("")).toBe("pulse");
  });
});

describe("providerDisplay", () => {
  it("defines display metadata for adverserial accounts returned by the pool API", () => {
    expect(providerDisplay("adverserial")).toEqual({
      label: "Adverserial",
      color: "#ff5454",
      dither: "red",
      glyph: "◬",
    });
  });

  it("defines display metadata for opencode_go accounts returned by the pool API", () => {
    expect(providerDisplay("opencode_go")).toEqual({
      label: "OpenCode Go",
      color: "#ffd23f",
      dither: "gold",
      glyph: "⬢",
    });
  });

  it("defines display metadata for mistral accounts returned by the pool API", () => {
    expect(providerDisplay("mistral")).toEqual({
      label: "Mistral API",
      color: "#fa5b30",
      dither: "orange",
      glyph: "✥",
    });
  });

  it("distinguishes Vibe subscription accounts from Mistral API accounts", () => {
    expect(providerDisplay("mistral_vibe")).toEqual({
      label: "Mistral Vibe",
      color: "#fa5b30",
      dither: "orange",
      glyph: "✥",
    });
  });

  it("falls back safely when the API returns a provider newer than the frontend", () => {
    expect(providerDisplay("future-provider")).toEqual({
      label: "Unknown",
      color: "#9c967f",
      dither: "grey",
      glyph: "·",
    });
  });
});

const vibeSession: VibeLoginSession = {
  session_id: "vibe-session",
  oauth_url: "https://auth.mistral.ai/sign-in",
  expires_at: "2026-10-07T12:01:00Z",
};

const jsonResponse = (data: unknown) => new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json" } });

function mockVibeBrowser() {
  vi.stubGlobal("document", { cookie: "other=value; pool_csrf=test-csrf" });
  vi.stubGlobal("window", {
    setInterval: globalThis.setInterval,
    clearInterval: globalThis.clearInterval,
    setTimeout: globalThis.setTimeout,
    clearTimeout: globalThis.clearTimeout,
  });
}

afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("operator API key requests", () => {
  it("uses browser credentials and CSRF without persisting the returned secret", async () => {
    mockVibeBrowser();
    const issued = { token: { id: "key-1", principal_id: "op", label: "diagnostics", scope: "read", status: "active", created_at: "2026-10-12T00:00:00Z", expires_at: "2027-01-10T00:00:00Z" }, secret: "poolop_key-1_secret" };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse([]))
      .mockResolvedValueOnce(jsonResponse(issued))
      .mockResolvedValueOnce(jsonResponse(issued))
      .mockResolvedValueOnce(jsonResponse({ success: true }));
    vi.stubGlobal("fetch", fetchMock);
    expect(await loadOperatorAPITokens()).toEqual([]);
    expect(await createOperatorAPIToken("diagnostics", "read")).toEqual(issued);
    expect(await replaceOperatorAPIToken("key-1")).toEqual(issued);
    await revokeOperatorAPIToken("key-1");
    expect(fetchMock.mock.calls).toEqual([
      ["/api/operator-tokens", { cache: "no-store", credentials: "same-origin" }],
      ["/api/operator-tokens", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": "test-csrf" }, body: JSON.stringify({ label: "diagnostics", scope: "read", expires_at: undefined }) }],
      ["/api/operator-tokens/key-1/replace", { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": "test-csrf" } }],
      ["/api/operator-tokens/key-1", { method: "DELETE", credentials: "same-origin", headers: { "X-CSRF-Token": "test-csrf" } }],
    ]);
  });
});

describe("Vibe contribution requests", () => {
  it("uses the hyphenated route, browser credentials and CSRF for start and status", async () => {
    mockVibeBrowser();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(vibeSession))
      .mockResolvedValueOnce(jsonResponse({ status: "pending" }));
    vi.stubGlobal("fetch", fetchMock);
    const controller = new AbortController();

    expect(await startVibeLogin(controller.signal)).toEqual(vibeSession);
    expect(await vibeLoginStatus(vibeSession.session_id, controller.signal)).toEqual({ status: "pending" });
    expect(fetchMock.mock.calls).toEqual([
      ["/api/pool/accounts/mistral-vibe/start", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": "test-csrf" },
        body: "{}", signal: controller.signal,
      }],
      ["/api/pool/accounts/mistral-vibe/status", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": "test-csrf" },
        body: JSON.stringify({ session_id: vibeSession.session_id }), signal: controller.signal,
      }],
    ]);
  });
});

describe("bounded Vibe sign-in polling", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-07T12:00:00Z"));
    mockVibeBrowser();
  });

  it("polls every three seconds and reports completion once", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ status: "pending" }))
      .mockResolvedValueOnce(jsonResponse({ status: "complete", account_id: "account-vibe" }));
    vi.stubGlobal("fetch", fetchMock);
    const complete = vi.fn();
    const error = vi.fn();
    watchVibeSession(vibeSession, complete, error);

    await vi.advanceTimersByTimeAsync(2999);
    expect(fetchMock).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(3000);
    expect(complete).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(60000);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(complete).toHaveBeenCalledTimes(1);
    expect(error).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not overlap slow status requests", async () => {
    let resolve!: (response: Response) => void;
    const fetchMock = vi.fn().mockImplementation(() => new Promise<Response>((done) => { resolve = done; }));
    vi.stubGlobal("fetch", fetchMock);
    const complete = vi.fn();
    const error = vi.fn();
    const stop = watchVibeSession(vibeSession, complete, error);

    await vi.advanceTimersByTimeAsync(9000);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    resolve(jsonResponse({ status: "pending" }));
    await vi.advanceTimersByTimeAsync(3000);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    stop();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("expires at the server deadline even while a request is stuck", async () => {
    let resolve!: (response: Response) => void;
    const fetchMock = vi.fn().mockImplementation(() => new Promise<Response>((done) => { resolve = done; }));
    vi.stubGlobal("fetch", fetchMock);
    const complete = vi.fn();
    const error = vi.fn();
    watchVibeSession({ ...vibeSession, expires_at: "2026-10-07T12:00:05Z" }, complete, error);

    await vi.advanceTimersByTimeAsync(5000);
    expect(error).toHaveBeenCalledExactlyOnceWith("Sign-in expired. Try again.");
    expect(fetchMock.mock.calls[0][1].signal.aborted).toBe(true);
    resolve(jsonResponse({ status: "complete" }));
    await vi.advanceTimersByTimeAsync(10000);
    expect(complete).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("cancels timers and ignores in-flight replies after cleanup", async () => {
    let resolve!: (response: Response) => void;
    const fetchMock = vi.fn().mockImplementation(() => new Promise<Response>((done) => { resolve = done; }));
    vi.stubGlobal("fetch", fetchMock);
    const complete = vi.fn();
    const error = vi.fn();
    const stop = watchVibeSession(vibeSession, complete, error);

    await vi.advanceTimersByTimeAsync(3000);
    stop();
    expect(fetchMock.mock.calls[0][1].signal.aborted).toBe(true);
    resolve(jsonResponse({ status: "complete" }));
    await vi.advanceTimersByTimeAsync(60000);
    expect(complete).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([
    ["expired", "Sign-in expired. Try again."],
    ["denied", "Sign-in denied. Try again."],
    ["error", "Couldn't finish sign-in. Try again."],
  ])("stops on %s and permits a fresh sign-in", async (status, message) => {
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse({ status })).mockResolvedValueOnce(jsonResponse({ status: "complete" }));
    vi.stubGlobal("fetch", fetchMock);
    const complete = vi.fn();
    const error = vi.fn();
    watchVibeSession(vibeSession, complete, error);
    await vi.advanceTimersByTimeAsync(3000);
    expect(error).toHaveBeenCalledExactlyOnceWith(message);
    expect(vi.getTimerCount()).toBe(0);

    watchVibeSession({ ...vibeSession, session_id: "retry-session" }, complete, error);
    await vi.advanceTimersByTimeAsync(3000);
    expect(complete).toHaveBeenCalledTimes(1);
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({ session_id: "retry-session" });
  });

  it("stops after a request failure and permits a fresh sign-in", async () => {
    const fetchMock = vi.fn().mockRejectedValueOnce(new TypeError("network failure"))
      .mockResolvedValueOnce(jsonResponse({ status: "complete" }));
    vi.stubGlobal("fetch", fetchMock);
    const complete = vi.fn();
    const error = vi.fn();
    watchVibeSession(vibeSession, complete, error);
    await vi.advanceTimersByTimeAsync(3000);
    expect(error).toHaveBeenCalledExactlyOnceWith("Couldn't check sign-in. Try again.");
    expect(vi.getTimerCount()).toBe(0);

    watchVibeSession({ ...vibeSession, session_id: "retry-session" }, complete, error);
    await vi.advanceTimersByTimeAsync(3000);
    expect(complete).toHaveBeenCalledTimes(1);
  });

  it.each(["2026-10-07T11:59:59Z", "not-a-date"])("does not poll a session with an invalid or past deadline (%s)", (expiresAt) => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const complete = vi.fn();
    const error = vi.fn();
    watchVibeSession({ ...vibeSession, expires_at: expiresAt }, complete, error);
    expect(error).toHaveBeenCalledExactlyOnceWith("Sign-in expired. Try again.");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe("OperatorAPIKeys lifecycle", () => {
  it("blocks double issue, preserves the one-time secret, and reports clipboard failure", async () => {
    const dom = new JSDOM("<!doctype html><div id='root'></div>", { url: "https://pool.example.test" });
    vi.stubGlobal("window", dom.window);
    vi.stubGlobal("document", dom.window.document);
    vi.stubGlobal("navigator", dom.window.navigator);
    Object.defineProperty(dom.window.document, "cookie", { value: "pool_csrf=test-csrf", configurable: true });
    Object.defineProperty(dom.window.navigator, "clipboard", { value: { writeText: vi.fn().mockRejectedValue(new Error("denied")) }, configurable: true });
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);

    let resolveIssue!: (response: Response) => void;
    const issued = { token: { id: "key-1", principal_id: "op", label: "diagnostics", scope: "read", status: "active", created_at: "2026-10-12T00:00:00Z", expires_at: "2027-01-10T00:00:00Z" }, secret: "poolop_key-1_once" };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse([]))
      .mockImplementationOnce(() => new Promise<Response>((resolve) => { resolveIssue = resolve; }))
      .mockResolvedValueOnce(jsonResponse([issued.token]));
    vi.stubGlobal("fetch", fetchMock);

    const container = dom.window.document.getElementById("root")!;
    const root = createRoot(container);
    await act(async () => { root.render(createElement(OperatorAPIKeys)); });
    const input = container.querySelector("input[placeholder='Pool diagnostics']") as HTMLInputElement;
    const form = input.closest("form")!;
    await act(async () => {
      input.value = "diagnostics";
      input.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
      form.dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true }));
      form.dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true }));
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    await act(async () => { resolveIssue(jsonResponse(issued)); });
    expect(container.textContent).toContain(issued.secret);
    expect((container.querySelector("button[type='submit']") as HTMLButtonElement).disabled).toBe(true);
    expect(container.textContent).toContain(`created ${new Date(issued.token.created_at).toLocaleDateString()}`);

    const copy = [...container.querySelectorAll("button")].find((button) => button.textContent === "Copy")!;
    await act(async () => { copy.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true })); });
    expect(container.textContent).toContain("Select and copy it manually");
    expect(container.textContent).toContain(issued.secret);
    await act(async () => { root.unmount(); });
  });
});

describe("operator bootstrap request", () => {
  it("bootstraps and then establishes a password-authenticated browser session", async () => {
    const dom = new JSDOM("<!doctype html><div id='root'></div>", { url: "https://pool.example.test" });
    vi.stubGlobal("window", dom.window);
    vi.stubGlobal("document", dom.window.document);
    vi.stubGlobal("navigator", dom.window.navigator);
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
    const principal = { id: "op", kind: "operator", status: "active", username: "operator", email: "op@example.test", display_name: "Operator", avatar_url: "", expires_at: null };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ legacy_signup: false, operator_exists: false }))
      .mockResolvedValueOnce(jsonResponse(principal))
      .mockResolvedValueOnce(jsonResponse({ principal, csrf: "fresh-csrf" }));
    vi.stubGlobal("fetch", fetchMock);
    const onAccess = vi.fn();
    const container = dom.window.document.getElementById("root")!;
    const root = createRoot(container);
    await act(async () => { root.render(createElement(AccessGate, { onAccess })); });
    const inputs = container.querySelectorAll("input");
    const values = ["op@example.test", "operator", "Operator", "long-enough-password"];
    await act(async () => {
      inputs.forEach((input, index) => {
        input.value = values[index];
        input.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
      });
    });
    await act(async () => {
      container.querySelector("form")!.dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true }));
    });
    expect(fetchMock.mock.calls.map((call) => call[0])).toEqual(["/api/auth/config", "/api/setup/operator", "/api/auth/login"]);
    expect(onAccess).toHaveBeenCalledWith(principal);
    await act(async () => { root.unmount(); });
  });

  it("uses the unauthenticated first-operator response shape without a bogus admin token", async () => {
    mockVibeBrowser();
    const principal = { id: "op", kind: "operator", status: "active", username: "operator", email: "op@example.test", display_name: "Operator", avatar_url: "", expires_at: null };
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse(principal));
    vi.stubGlobal("fetch", fetchMock);
    expect(await operatorBootstrap("operator", "op@example.test", "long-enough-password", "Operator")).toEqual(principal);
    expect(fetchMock).toHaveBeenCalledWith("/api/setup/operator", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ username: "operator", email: "op@example.test", password: "long-enough-password", display_name: "Operator" }),
    });
  });
});
