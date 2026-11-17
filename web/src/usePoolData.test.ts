import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, createElement } from "react";
import type { Root } from "react-dom/client";
import { JSDOM } from "jsdom";
import { usePoolData } from "./usePoolData";

const operator = { id: "operator-test", kind: "operator", status: "active" } as const;
let root: Root;
let dom: JSDOM;
let fetcher: ReturnType<typeof vi.fn>;

function PoolDataView() {
  const data = usePoolData(operator);
  return createElement("div", null,
    createElement("button", { onClick: () => { void data.refresh(); } }, "Refresh"),
    createElement("button", { onClick: () => data.setQuotaWasteDays(90) }, "90 days"),
    createElement("pre", null, JSON.stringify({
      accounts: data.stats?.total_accounts,
      hours: data.signal?.hourly.length,
      models: data.models.map(model => model.id),
      quotaDays: data.quotaWaste?.days,
      error: data.error,
      failuresError: data.failureInsightsError,
      quotaError: data.quotaWasteError,
    })),
  );
}

beforeEach(async () => {
  dom = new JSDOM('<div id="root"></div>', { url: "https://pool.test" });
  vi.stubGlobal("window", dom.window);
  vi.stubGlobal("document", dom.window.document);
  vi.stubGlobal("navigator", dom.window.navigator);
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  fetcher = vi.fn();
  vi.stubGlobal("fetch", fetcher);
  const { createRoot } = await import("react-dom/client");
  root = createRoot(document.getElementById("root")!);
  await act(async () => root.render(createElement(PoolDataView)));
});

afterEach(async () => {
  await act(async () => root.unmount());
  dom.window.close();
  vi.unstubAllGlobals();
});

async function click(label: string) {
  const button = [...document.querySelectorAll("button")].find(item => item.textContent === label)!;
  await act(async () => button.click());
}

function displayed() {
  return JSON.parse(document.querySelector("pre")!.textContent!);
}

function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function coreResponse(path: string, generation: number) {
  if (path === "/api/pool/stats") { return response({ total_accounts: generation }); }
  if (path.startsWith("/api/pool/signal")) { return response({ hourly: Array(generation).fill({}) }); }
  if (path === "/api/pool/catalog") { return response({ models: [{ id: `model-${generation}` }] }); }
  if (path.startsWith("/api/pool/failure-insights")) { return response({ groups: [], total: generation }); }
  throw new Error(`Unexpected request ${path}`);
}

describe("pool data refresh", () => {
  it("commits required resources together and keeps optional failures separate", async () => {
    let generation = 1;
    let failSignal = false;
    let failQuota = false;
    const quotaCalls: string[] = [];
    fetcher.mockImplementation(async (path: string) => {
      if (path.startsWith("/api/pool/quota-waste")) {
        quotaCalls.push(path);
        return failQuota ? response({ error: "quota unavailable" }, 503) : response({ days: 30 });
      }
      if (path.startsWith("/api/pool/failure-insights")) { return response({ error: "failures unavailable" }, 503); }
      if (failSignal && path.startsWith("/api/pool/signal")) { return response({ error: "signal unavailable" }, 503); }
      return coreResponse(path, generation);
    });
    await click("Refresh");
    expect(displayed()).toEqual({ accounts: 1, hours: 1, models: ["model-1"], quotaDays: 30, error: "", failuresError: "failures unavailable", quotaError: "" });
    generation = 2;
    failSignal = true;
    await click("Refresh");
    expect(displayed()).toEqual({ accounts: 1, hours: 1, models: ["model-1"], quotaDays: 30, error: "signal unavailable", failuresError: "failures unavailable", quotaError: "" });
    expect(quotaCalls).toHaveLength(1);
    generation = 3;
    failSignal = false;
    failQuota = true;
    await click("Refresh");
    expect(displayed()).toEqual({ accounts: 3, hours: 3, models: ["model-3"], error: "", failuresError: "failures unavailable", quotaError: "quota unavailable" });
  });

  it("ignores a quota response from an older history window", async () => {
    let resolveOld!: (value: Response) => void;
    const older = new Promise<Response>(resolve => { resolveOld = resolve; });
    fetcher.mockImplementation(async (path: string) => {
      if (path === "/api/pool/quota-waste?days=30") { return older; }
      if (path === "/api/pool/quota-waste?days=90") { return response({ days: 90 }); }
      return coreResponse(path, 1);
    });
    await click("Refresh");
    expect(fetcher).toHaveBeenCalledWith("/api/pool/quota-waste?days=30", expect.anything());
    await click("90 days");
    await click("Refresh");
    expect(displayed().quotaDays).toBe(90);
    await act(async () => resolveOld(response({ days: 30 })));
    expect(displayed().quotaDays).toBe(90);
  });
});
