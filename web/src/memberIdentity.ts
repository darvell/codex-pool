import type { ConsolePrincipal } from "./types";

export function isUnclaimedLegacy(item: ConsolePrincipal): boolean {
  return item.source === "migrated_credential" && item.kind === "guest" && !item.username;
}

export function memberRole(item: ConsolePrincipal): string {
  if (isUnclaimedLegacy(item)) return "Unclaimed legacy";
  return item.kind === "operator" ? "Operator" : item.kind === "member" ? "Member" : "Guest";
}

export function memberName(item: ConsolePrincipal): string {
  if (item.display_name?.trim()) return item.display_name.trim();
  if (item.username?.trim()) return item.username.trim();
  if (isUnclaimedLegacy(item)) return item.email || `Legacy · ${item.id.slice(0, 8)}`;
  if (item.kind === "guest") return item.note || `Guest · ${item.id.slice(0, 8)}`;
  return item.email || `${memberRole(item)} · ${item.id.slice(0, 8)}`;
}

export function memberOrigin(item: ConsolePrincipal): string {
  switch (item.source) {
    case "migrated_credential": return "Migrated credential";
    case "legacy_code_signup": return "Pool-code signup";
    case "operator_invite": return "Operator invitation";
    case "guest_pass": return "Guest pass";
    case "operator_bootstrap": return "Operator bootstrap";
    default: return "Unknown";
  }
}
