import { describe, expect, it } from "vitest";
import type { ConsolePrincipal } from "./types";
import { isUnclaimedLegacy, memberName, memberOrigin, memberRole } from "./memberIdentity";
const base: ConsolePrincipal = { id: "abcdef123", kind: "guest", status: "active", note: "legacy: old@pool.local", source: "migrated_credential", email: "old@pool.local", created_at: "2025-01-01T00:00:00Z", billable_tokens: 100, request_count: 1, api_equivalent_cost_usd: 1 };
describe("console identities", () => {
  it("identifies unclaimed legacy without treating its note as its name", () => {
    expect(isUnclaimedLegacy(base)).toBe(true);
    expect(memberRole(base)).toBe("Unclaimed legacy");
    expect(memberName(base)).toBe("old@pool.local");
  });
  it("keeps migrated history visible after a claim or role change", () => {
    const claimed = { ...base, kind: "member" as const, username: "neon", display_name: "Neon" };
    expect(isUnclaimedLegacy(claimed)).toBe(false);
    expect(memberRole(claimed)).toBe("Member");
    expect(memberName(claimed)).toBe("Neon");
    expect(memberOrigin(claimed)).toBe("Migrated credential");
  });
  it("does not mistake a guest pass or unknown provenance for a migrated account", () => {
    expect(memberRole({ ...base, source: "guest_pass" })).toBe("Guest");
    expect(memberOrigin({ ...base, source: undefined })).toBe("Unknown");
  });
  it("prefers display name over username and generic internal notes", () => {
    expect(memberName({ ...base, kind: "member", source: "operator_invite", note: "member", display_name: "Ada", username: "ada" })).toBe("Ada");
  });
});
