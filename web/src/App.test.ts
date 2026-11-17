import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, createElement } from "react";
let createRoot: typeof import("react-dom/client")["createRoot"];
import { JSDOM } from "jsdom";
import { App, AccessGate, isArmedAccountAction, OperatorAPIKeys, poolSurplus, providerDisplay } from "./App";
import { watchVibeSession } from "./contributions";
import { viewFromSearch } from "./navigation";
import { createOperatorAPIToken, loadClientApiKey, loadFailureInsights, loadOperatorAPITokens, operatorBootstrap, replaceOperatorAPIToken, revokeOperatorAPIToken, startVibeLogin, vibeLoginStatus } from "./api";
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
  let dom: JSDOM;
  let root: ReturnType<typeof createRoot>;
  let container: HTMLElement;
  let passes: { id: string; note: string; display_name: string; status: string; clients: number; link: string }[];
  let finishLoad: (response: Response) => void;
  let fetchMock: ReturnType<typeof vi.fn>;

  const click = async (text: string) => {
    const button = [...container.querySelectorAll("button")].find((item) => item.textContent === text);
    expect(button, `button ${text}`).toBeDefined();
    await act(async () => { button!.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true })); });
  };

  beforeEach(async () => {
    dom = new JSDOM("<!doctype html><div id='root'></div>", { url: "https://pool.example.test/?view=passes" });
    vi.stubGlobal("window", dom.window);
    vi.stubGlobal("document", dom.window.document);
    vi.stubGlobal("navigator", dom.window.navigator);
    vi.stubGlobal("sessionStorage", dom.window.sessionStorage);
    vi.stubGlobal("localStorage", dom.window.localStorage);
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
    ({ createRoot } = await import("react-dom/client"));
    dom.window.confirm = vi.fn().mockReturnValue(true);
    passes = [];
    let initialLoad = true;
    fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === "/api/auth/me") return jsonResponse({ id: "member", kind: "member", status: "active", display_name: "Member" });
      if (url === "/api/passes" && init?.method === "POST") {
        passes = [{ id: "new-pass", ...JSON.parse(init.body as string), status: "active", clients: 0, link: "/join#new-pass" }];
        return jsonResponse({ ...passes[0], setup_token: "new-setup-token" });
      }
      if (url === "/api/passes") {
        if (initialLoad) {
          initialLoad = false;
          return new Promise<Response>((resolve) => { finishLoad = resolve; });
        }
        return jsonResponse(passes);
      }
      if (url.endsWith("/restore")) { passes = []; return jsonResponse({ success: true }); }
      if (url === "/api/pool/stats") return jsonResponse({ accounts: [], aggregate: {} });
      if (url === "/api/pool/catalog") return jsonResponse({ models: [] });
      if (url.startsWith("/api/pool/")) return jsonResponse({ hourly: [], economics: [], origin_weekly: [], groups: [] });
      throw new Error(`Unexpected request: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    container = dom.window.document.getElementById("root")!;
    root = createRoot(container);
    await act(async () => { root.render(createElement(App)); });
  });

  afterEach(async () => {
    await act(async () => { root.unmount(); });
    dom.window.close();
  });

  it("opens after the first empty load, respects Cancel, and stays closed after creating a pass", async () => {
    expect(container.textContent).toContain("Loading passes");
    expect(container.querySelector(".pass-form")).toBeNull();
    await act(async () => { finishLoad(jsonResponse([])); });
    expect(container.querySelector(".pass-form")).not.toBeNull();
    await click("Cancel");
    expect(container.querySelector(".pass-form")).toBeNull();
    await click("Create a pass");
    await act(async () => {
      const note = container.querySelector("textarea")!;
      const setter = Object.getOwnPropertyDescriptor(dom.window.HTMLTextAreaElement.prototype, "value")!.set!;
      setter.call(note, "Sam");
      note.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
      note.dispatchEvent(new dom.window.Event("change", { bubbles: true }));
    });
    await act(async () => { container.querySelector(".pass-form")!.dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true })); });
    expect(container.querySelector(".pass-form")).toBeNull();
    expect(container.querySelector(".pass-row")!.textContent).toContain("Sam");
    expect(container.querySelector(".setup-secret")!.textContent).toContain("https://pool.example.test/join#new-pass");
    expect(fetchMock.mock.calls.filter(([url, init]) => url === "/api/passes" && !init?.method)).toHaveLength(2);
  });

  it("keeps the form closed after a populated first load and a later empty refresh", async () => {
    passes = [{ id: "pass_1", note: "Sam", display_name: "Sam", status: "revoked", clients: 0, link: "/join#pass_1" }];
    await act(async () => { finishLoad(jsonResponse(passes)); });
    expect(container.querySelector(".pass-form")).toBeNull();
    expect(container.querySelector(".pass-row")!.textContent).toContain("Sam");
    await click("Restore");
    expect(container.querySelector(".pass-form")).toBeNull();
    expect(container.textContent).toContain("No passes yet.");
    expect(fetchMock.mock.calls.filter(([url, init]) => url === "/api/passes" && !init?.method)).toHaveLength(2);
    await click("Create a pass");
    expect(container.querySelector(".pass-form")).not.toBeNull();
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
  it.each([
    ["adverserial", "Adverserial"],
    ["opencode_go", "OpenCode Go"],
    ["mistral", "Mistral API"],
    ["mistral_vibe", "Mistral Vibe"],
  ])("labels %s accounts as %s", (provider, label) => {
    expect(providerDisplay(provider).label).toBe(label);
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

describe("failure insights requests", () => {
  it("loads the bounded seven-day grouped failure report", async () => {
    mockVibeBrowser();
    const response = { since: "2026-10-05T00:00:00Z", until: "2026-10-12T00:00:00Z", total: 2, groups: [{ account_id: "hashed-account", provider: "codex", error_class: "auth", error_domain: "http", error_code: "401", outcome: "terminal_failure", attempts: 2, last_seen_at: "2026-10-11T00:00:00Z" }] };
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(response));
    vi.stubGlobal("fetch", fetchMock);

    expect(await loadFailureInsights()).toEqual(response);
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith("/api/pool/failure-insights?hours=168&limit=100", { credentials: "same-origin", cache: "no-store" });
  });
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

describe("SDK client API key", () => {
  it("exchanges the setup token for the signed API credential without caching", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse({ access_token: "signed-client-key" }));
    vi.stubGlobal("fetch", fetchMock);
    const controller = new AbortController();

    expect(await loadClientApiKey("download/token", controller.signal)).toBe("signed-client-key");
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith("/config/claude/download%2Ftoken", {
      cache: "no-store", credentials: "same-origin", signal: controller.signal,
    });
  });

  it("does not return a setup token when the credential response is incomplete", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResponse({})));
    await expect(loadClientApiKey("download-token")).rejects.toThrow("Couldn't load the API key. Retry setup.");
  });

  it("rejects revoked setup tokens", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response("invalid or revoked token", { status: 404 })));
    await expect(loadClientApiKey("revoked-token")).rejects.toThrow();
  });
});

describe("Mine client API keys", () => {
  let dom: JSDOM;
  let root: ReturnType<typeof createRoot>;
  let container: HTMLElement;
  let fetchMock: ReturnType<typeof vi.fn>;
  let clients: { id: string; label: string; status: string }[];
  let config: (url: string, init?: RequestInit) => Promise<Response>;
  let clipboard: ReturnType<typeof vi.fn>;

  const click = async (text: string, scope: ParentNode = container) => {
    const button = [...scope.querySelectorAll("button")].find((item) => item.textContent === text);
    expect(button, `button ${text}`).toBeDefined();
    await act(async () => { button!.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true })); });
  };

  beforeEach(async () => {
    dom = new JSDOM("<!doctype html><div id='root'></div>", { url: "https://pool.example.test/?view=mine" });
    vi.stubGlobal("window", dom.window);
    vi.stubGlobal("document", dom.window.document);
    vi.stubGlobal("navigator", dom.window.navigator);
    vi.stubGlobal("sessionStorage", dom.window.sessionStorage);
    vi.stubGlobal("localStorage", dom.window.localStorage);
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
    ({ createRoot } = await import("react-dom/client"));
    clipboard = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(dom.window.navigator, "clipboard", { value: { writeText: clipboard }, configurable: true });
    dom.window.confirm = vi.fn().mockReturnValue(true);
    clients = [{ id: "laptop", label: "Work laptop", status: "active" }, { id: "server", label: "Home server", status: "active" }];
    config = async (url) => jsonResponse({ access_token: `signed-key-${url.split("/").pop()}` });
    fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === "/api/auth/me") return jsonResponse({ id: "guest", kind: "guest", status: "active", display_name: "Guest" });
      if (url.startsWith("/api/me/usage")) return jsonResponse({ hourly: [] });
      if (url === "/api/me/clients" && init?.method === "POST") {
        const client = { id: "new-client", label: "New client", status: "active" };
        clients = [...clients, client];
        return jsonResponse({ ...client, setup_token: "setup-new-client" });
      }
      if (url === "/api/me/clients") return jsonResponse(clients);
      if (url.endsWith("/reveal")) return jsonResponse({ setup_token: `setup-${url.split("/")[4]}` });
      if (url.endsWith("/rotate")) return jsonResponse({ ...clients[0], setup_token: "setup-replaced" });
      if (init?.method === "DELETE") {
        clients = clients.map((client) => client.id === url.split("/")[4] ? { ...client, status: "revoked" } : client);
        return jsonResponse({ success: true });
      }
      if (url.startsWith("/config/claude/")) return config(url, init);
      throw new Error(`Unexpected request: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    container = dom.window.document.getElementById("root")!;
    root = createRoot(container);
    await act(async () => { root.render(createElement(App)); });
  });

  afterEach(async () => {
    await act(async () => { root.unmount(); });
    dom.window.close();
  });

  it("reveals and copies the signed key by default, with base URL and model-list curl", async () => {
    await click("Show key");
    const credentials = container.querySelector(".client-api-key")!;
    expect(credentials.textContent).toContain("signed-key-setup-laptop");
    expect(credentials.textContent).toContain("https://pool.example.test/v1");
    expect(credentials.querySelector("pre")!.textContent).toBe('curl "https://pool.example.test/v1/models" \\\n  -H "Authorization: Bearer signed-key-setup-laptop"');
    await click("Copy key", credentials);
    expect(clipboard).toHaveBeenLastCalledWith("signed-key-setup-laptop");
    await click("Copy URL", credentials);
    expect(clipboard).toHaveBeenLastCalledWith("https://pool.example.test/v1");
    await click("CLI installers");
    expect(container.querySelector(".setup-secret")!.textContent).toContain("/setup/codex/setup-laptop");
    expect(container.querySelector(".client-api-key")).toBeNull();
    await click("Hide key");
    expect(container.querySelector(".setup-secret")).toBeNull();
    await click("Show key");
    expect(container.querySelector(".client-api-key")).not.toBeNull();
  });

  it("renders Astra onboarding examples in the OpenAI SDK setup", async () => {
    await click("Setup");
    await click("OpenAI SDK");
    const examples = [...container.querySelectorAll(".tool-detail pre")].map((item) => item.textContent);
    expect(examples).toHaveLength(3);
    expect(examples[0]).toContain('client.responses.create(model="gpt-6-astra"');
    expect(examples[1]).toContain('client.responses.create({ model: "gpt-6-astra"');
    expect(examples[2]).toContain('"model":"gpt-6-astra"');
    for (const example of examples) {
      expect(example).toContain("https://pool.example.test/v1");
      expect(example).toContain("signed-key-setup-laptop");
      expect(example).not.toMatch(/gpt-5\.6-(luna|sol)/);
    }
  });

  it("aborts hidden and superseded loads, ignores late keys, and retries failures", async () => {
    let finish!: (response: Response) => void;
    let signal!: AbortSignal;
    config = async (_url, init) => {
      signal = init!.signal!;
      return new Promise<Response>((resolve) => { finish = resolve; });
    };
    await click("Show key");
    expect(container.textContent).toContain("Loading API key");
    await click("Hide key");
    expect(signal.aborted).toBe(true);
    await act(async () => { finish(jsonResponse({ access_token: "late-hidden-key" })); });
    expect(container.textContent).not.toContain("late-hidden-key");

    await click("Show key");
    const oldSignal = signal;
    const oldFinish = finish;
    config = async () => { throw new TypeError("offline"); };
    await click("Show key", container.querySelectorAll(".client-card")[1]);
    expect(oldSignal.aborted).toBe(true);
    expect(container.textContent).toContain("Couldn't load the API key. Try again.");
    config = async () => jsonResponse({ access_token: "signed-server-key" });
    await click("Retry API key");
    expect(container.querySelector(".client-api-key")!.textContent).toContain("signed-server-key");
    await act(async () => { oldFinish(jsonResponse({ access_token: "late-laptop-key" })); });
    expect(container.textContent).not.toContain("late-laptop-key");
  });

  it("opens created and replaced keys directly, then clears revoked credentials", async () => {
    await click("Add client");
    await act(async () => { container.querySelector(".client-create")!.dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true })); });
    expect(container.querySelector(".client-api-key")!.textContent).toContain("signed-key-setup-new-client");
    await click("Show key");
    expect(container.querySelector(".client-api-key")!.textContent).toContain("signed-key-setup-laptop");
    await click("Replace key");
    expect(container.textContent).not.toContain("signed-key-setup-laptop");
    expect(container.querySelector(".client-api-key")!.textContent).toContain("signed-key-setup-replaced");
    await click("Revoke");
    expect(container.querySelector(".client-api-key")).toBeNull();
    expect(container.textContent).not.toContain("signed-key-setup-replaced");
    expect((container.querySelector(".client-card button") as HTMLButtonElement).disabled).toBe(true);
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
    ({ createRoot } = await import("react-dom/client"));

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
    ({ createRoot } = await import("react-dom/client"));
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
