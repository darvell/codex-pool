import type { PassportPrincipal } from "./types";

type Role = PassportPrincipal["kind"];
type Workspace = { label: string; group: Partial<Record<Role, string>>; guestLabel?: string; query?: string };
const WORKSPACES = {
  pulse: { label: "Pool status", group: { operator: "Operate" } },
  insights: { label: "Insights", group: { operator: "Operate" }, query: "insight" },
  "quota-waste": { label: "Quota waste", group: { operator: "Operate" } },
  models: { label: "Models", group: { operator: "Operate" } },
  accounts: { label: "Accounts", group: { operator: "Manage" }, query: "accounts" },
  passes: { label: "Guest passes", group: { operator: "Manage", member: "Sharing" } },
  console: { label: "Members", group: { operator: "Manage" } },
  "operator-api": { label: "Operator API", group: { operator: "Manage" } },
  mine: { label: "Your usage", guestLabel: "Usage", group: { operator: "Personal", member: "Personal", guest: "Your access" } },
  setup: { label: "Setup", group: { operator: "Personal", member: "Personal", guest: "Your access" } },
} satisfies Record<string, Workspace>;
export type View = keyof typeof WORKSPACES;
type HistoryMode = "push" | "replace";

export function viewFromSearch(search: string): View {
  const candidate = new URLSearchParams(search).get("view");
  return candidate && Object.hasOwn(WORKSPACES, candidate) ? candidate as View : "pulse";
}

export function navigationGroups(role: Role) {
  const groups = new Map<string, Array<[View, string]>>();
  for (const [id, entry] of Object.entries(WORKSPACES) as Array<[View, Workspace]>) {
    const group = entry.group[role];
    if (!group) { continue; }
    const items = groups.get(group) ?? [];
    items.push([id, role === "guest" && entry.guestLabel ? entry.guestLabel : entry.label]);
    groups.set(group, items);
  }
  const order = role === "member" ? ["Personal", "Sharing"] : [...groups.keys()];
  return order.map(label => ({ label, items: groups.get(label)! }));
}

export function allowedViews(principal: PassportPrincipal): View[] {
  return navigationGroups(principal.kind).flatMap(group => group.items.map(([id]) => id));
}

export function queryValue(name: string) {
  return new URLSearchParams(window.location.search).get(name);
}

export function updateURL(changes: Record<string, string | null>, mode: HistoryMode = "replace") {
  const url = new URL(window.location.href);
  for (const [name, value] of Object.entries(changes)) {
    if (value) { url.searchParams.set(name, value); }
    else { url.searchParams.delete(name); }
  }
  window.history[`${mode}State`](null, "", `${url.pathname}${url.search}${url.hash}`);
}

export function viewChanges(view: View) {
  const changes: Record<string, string | null> = { account: null, member: null, view };
  for (const [id, entry] of Object.entries(WORKSPACES) as Array<[View, Workspace]>) {
    if (entry.query && view !== id) { changes[entry.query] = null; }
  }
  return changes;
}
