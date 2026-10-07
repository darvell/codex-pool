import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { isArmedAccountAction, poolSurplus, providerDisplay, shouldShowPassFormOnLoad, viewFromSearch, watchVibeSession } from "./App";
import { startVibeLogin, vibeLoginStatus } from "./api";
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
