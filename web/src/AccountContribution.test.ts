import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, createElement } from "react";
import type { Root } from "react-dom/client";
let createRoot: typeof import("react-dom/client")["createRoot"];
import { JSDOM } from "jsdom";
import { AccountContribution } from "./AccountContribution";

let root: Root;
let dom: JSDOM;
let added: ReturnType<typeof vi.fn<() => Promise<void>>>;
let popup: { opener: unknown; location: { replace: ReturnType<typeof vi.fn> }; close: ReturnType<typeof vi.fn> };
let fetcher: ReturnType<typeof vi.fn>;

beforeEach(async () => {
  dom = new JSDOM('<div id="root"></div>', { url: "https://pool.test" });
  vi.stubGlobal("window", dom.window);
  vi.stubGlobal("document", dom.window.document);
  vi.stubGlobal("navigator", dom.window.navigator);
  ({ createRoot } = await import("react-dom/client"));
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  popup = { opener: {}, location: { replace: vi.fn() }, close: vi.fn() };
  vi.spyOn(dom.window, "open").mockReturnValue(popup as unknown as Window);
  fetcher = vi.fn();
  vi.stubGlobal("fetch", fetcher);
  added = vi.fn<() => Promise<void>>().mockResolvedValue(undefined);
  root = createRoot(document.getElementById("root")!);
  await act(async () => { root.render(createElement(AccountContribution, { onClose: vi.fn(), onAdded: added })); });
});

afterEach(async () => {
  await act(async () => root.unmount());
  dom.window.close();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function click(label: string) {
  const button = [...document.querySelectorAll("button")].find(item => item.textContent === label);
  expect(button, label).toBeDefined();
  await act(async () => button!.click());
}

async function paste(value: string) {
  const input = document.querySelector<HTMLInputElement>(".contribution-field input")!;
  const setter = Object.getOwnPropertyDescriptor(dom.window.HTMLInputElement.prototype, "value")!.set!;
  await act(async () => {
    setter.call(input, value);
    input.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
    input.dispatchEvent(new dom.window.Event("change", { bubbles: true }));
  });
}

function response(body: unknown) {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

describe("account contribution", () => {
  it("opens the authorization tab before fetching and exchanges the selected provider's code", async () => {
    const events: string[] = [];
    vi.mocked(dom.window.open).mockImplementation(() => { events.push("open"); return popup as unknown as Window; });
    fetcher.mockImplementationOnce(async () => { events.push("fetch"); return response({ oauth_url: "https://claude.test/authorize", verifier: "test-verifier" }); });
    await click("Claude");
    await click("Sign in to Claude");
    expect(events).toEqual(["open", "fetch"]);
    expect(popup.opener).toBeNull();
    expect(popup.location.replace).toHaveBeenCalledWith("https://claude.test/authorize");
    await paste("https://callback.test/?code=test-code");
    fetcher.mockResolvedValueOnce(response({ success: true }));
    await act(async () => document.querySelector("form")!.dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true })));
    expect(fetcher).toHaveBeenLastCalledWith("/api/pool/accounts/claude/exchange", expect.objectContaining({ body: JSON.stringify({ code: "test-code", verifier: "test-verifier" }) }));
    expect(added).toHaveBeenCalledTimes(1);
  });

  it("accepts a matching Antigravity completion message once and ignores other sessions", async () => {
    fetcher.mockResolvedValueOnce(response({ oauth_url: "https://google.test/authorize", session_id: "test-google-session", state: "test-state" }));
    await click("Google Antigravity");
    await click("Sign in to Google Antigravity");
    expect(popup.opener).not.toBeNull();
    const complete = { type: "codex-pool-antigravity-oauth", status: "complete", session_id: "test-google-session" };
    await act(async () => {
      window.dispatchEvent(new dom.window.MessageEvent("message", { origin: "https://other.test", data: complete }));
      window.dispatchEvent(new dom.window.MessageEvent("message", { origin: "https://pool.test", data: { ...complete, session_id: "other-session" } }));
    });
    expect(added).not.toHaveBeenCalled();
    await act(async () => {
      window.dispatchEvent(new dom.window.MessageEvent("message", { origin: "https://pool.test", data: complete }));
      window.dispatchEvent(new dom.window.MessageEvent("message", { origin: "https://pool.test", data: complete }));
    });
    expect(added).toHaveBeenCalledTimes(1);
  });

  it("discards the old OAuth session when the provider changes", async () => {
    fetcher.mockResolvedValueOnce(response({ oauth_url: "https://codex.test/authorize", verifier: "test-verifier" }));
    await click("Sign in to Codex");
    expect(document.querySelector("a")?.getAttribute("href")).toBe("https://codex.test/authorize");
    await click("Claude");
    expect(document.querySelector("a")).toBeNull();
    expect(document.querySelector(".oauth-launch")?.textContent).toBe("Sign in to Claude");
  });
});
