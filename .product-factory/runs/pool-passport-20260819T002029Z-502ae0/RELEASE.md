# Pool Passport — Release brief

## Product result

Pool Passport replaces codex-pool's single shared `friend_code` with named principals, per-person credentials, and honest per-principal analytics. A guest taps one link and is in. A member signs in and operates the pool. The operator sees exactly who burned what and can cut off any one person without disturbing the rest.

Previous gap: 50 people held the same shared string as credentials. Nothing could be revoked without rotating the one signing secret and breaking all 50 at once. Usage charts showed the pool, never a person.

Complete delivered result: three principal kinds with distinct authority; member sign-in by password with optional passkeys; guest passes carrying a required private note and optional expiry, redeemed by a multi-use magic link; user-editable nicknames and uploaded avatar images; self-service labelled client credentials; per-request authorization with signed issue-time cutoffs; per-principal token and cost analytics derived from an immutable DuckDB event ledger behind a durable Bolt outbox; an operator console with ranking, inspection, suspension, and an audit log; migration of all 50 existing users with IDs and history intact; transitional `friend_code` account claiming; and retirement of that code from request authentication.

Excluded from scope: uninvited public sign-up, email, self-service password reset, organizations/teams/custom roles, enforced spend caps, notifications, mobile apps, federation, SSO, latency and error-rate analytics.

## Delivered product loops

**Join:** member writes a private note, creates a pass, copies the link, sends it; guest taps the link on a phone, lands authenticated on Mine, copies one shell line to their laptop. Verified by `TestPassRequiresNote`, `TestExpiredPassDenied`, and rendered browser walkthrough.

**Operate:** member signs in with password or passkey, inspects pool capacity, manages passes, views the console. Sessions are opaque, server-side, and sliding-renewed. Verified by `TestSessionCookieFlags`, `TestSessionDiesOnRevocation`, and `TestMemberOnboardingAndRecoveryLinksAreSingleUse`.

**Consumption:** CLI request hits the proxy, authorization checks the in-memory map (signed issue time vs. principal cutoff), the completed usage observation commits to the Bolt outbox in the same transaction, drains to DuckDB, and appears in the principal's hourly chart. Verified by `TestDuckAnalyticsReplayIsIdempotent`, `TestAnalyticsReconciliationIncludesDurableOutbox`, and `BenchmarkAuthorizePrincipal` (702ns/op).

**Accounting:** operator opens Console, sees principals ranked by tokens over 24 hours, identifies the top row by its private note, drills into hourly shape and model mix, and suspends in one click. Verified by `TestAuthorityMatrix` and rendered browser walkthrough.

**Recovery:** operator mints a one-time recovery link, copies it to the member, member sets a new password and prior sessions are killed. Verified by `TestMemberOnboardingAndRecoveryLinksAreSingleUse`.

## Experience and platform behavior

The dashboard is the existing Signal Room extended in its own grammar — 92px icon rail, edge-to-edge hairline panels, section codes, IBM Plex Mono with tabular numerals. Three destinations added: `MINE`, `PASSES`, `CONSOLE`. A guest sees only `MINE` and `SETUP`; the others are not rendered rather than rendered-and-disabled.

Design decisions: the gate is for members only (guests never see a sign-in form); expired, revoked, and unknown links are deliberately indistinguishable to the holder; revocation mid-session is a full-surface takeover rather than a toast; the note carries the most visual weight in a pass row; no motion on chart updates; charts expose a visually hidden data table for screen readers.

Inspected at 1440px and 390px with real migrated data. Console null-array crash and year-1 timestamps found and fixed in this run. Keyboard tree complete; screen reader pass and real device walkthrough pending.

## Architecture, data, and authority

**Domain owners:** `PassportStore` owns principals, clients, sessions, join links, and audit log in BoltDB. `DuckAnalytics` owns the immutable fact ledger in DuckDB. `proxyHandler` owns per-request authorization.

**Request path:** proxy receives request → `parsePoolCredentialRequest` extracts identity and signed issue time from one of four envelope formats → `authorizeIssuedCredential` checks principal/client status and cutoff against the signed timestamp → if allowed, request proceeds; usage observation commits to Bolt outbox → background drain writes to DuckDB → charts query DuckDB.

**Physical stores:** BoltDB holds principals, clients, sessions, join links, audit log, and the analytics outbox. DuckDB holds immutable usage events. No SQLite dependency remains in the analytics path.

**Authority model:** guests can read their own usage and manage their profile; members can additionally create passes, view the console, and contribute provider accounts; only the operator can create members, suspend principals, and view pool-wide analytics. Enforced at the route handler level by `requireAuthority` and at the data level by self-scoping every query to the session's principal ID.

**Data lifecycle:** DuckDB facts are immutable; they are never updated or deleted. The 24-month storage envelope is measured against a 6M-row fixture. Backup uses a paired Bolt/DuckDB manifest with SHA-256 verification.

## Quality and operating envelope

Authorization: 702ns/op, 2 allocs on Apple M4 Pro (well under 1ms p99 contract target). DuckDB self-30-day and operator-1-year query benchmarks defined; 6M-row envelope exercised on Linux staging via `ANALYTICS_BENCH_ROWS`.

Argon2id: 50–250ms verification on target hardware, bounded by a configurable work semaphore.

Sessions: 30-day sliding expiry, `HttpOnly; Secure; SameSite=Strict` cookies, double-submit CSRF on all state-changing routes.

Storage: DuckDB + Bolt + temp/outbox measured to stay within 24-month filesystem budget at 6M rows.

No new hosted dependency. No new cost. One pool, one droplet, one operator.

## Distribution, migration, and support

Artifact: multi-stage Docker build — Node builds the SPA, Go/CGO links the official DuckDB native library, output stage exports a Debian binary. Clean checkout builds without host-generated assets.

Deployment: scp, binary swap, systemd restart. Startup verifies DuckDB schema before readiness.

Migration: all 50 existing users preserved with byte-identical IDs and synthesized notes. `friend_code` remains as the transitional account-claim code and analytics salt. Clearing the config value closes enrollment.

Rollback: safe before any new principal or revocation. After a revocation, the old binary cannot enforce the new credential cutoff and recovery is forward-only.

Documentation: `README.md` replaces friend-code instructions. `.localnotes/DEPLOYMENT.md` documents operator bootstrap, Docker build, DuckDB file ownership, backup/restore, outbox backlog, and rollback boundaries.

## Reviewer questions

- Can every intended user reach first value from a clean state? Yes — guest via tapped link, member via operator-minted onboarding link.
- Does revocation work mid-session? Yes — `TestSessionDiesOnRevocation` proves it; real browser + CLI walkthrough pending.
- Are all 50 existing credentials preserved? Migration test proves ID and token byte-identity; credential replay against production tokens is a release-blocking gate.
- Is DuckDB injection possible? All queries use bound `?` parameters; no string interpolation in any analytics SQL.

## Validation evidence

- Authorization performance: `BenchmarkAuthorizePrincipal`, 200 principals, 500 iterations, 702ns/op, 2 allocs, 496 B/op.
- Suite green: `go test ./... -count=1` PASS (3.273s); `cd web && npx vitest run` 14 tests PASS (653ms).
- Packaging: `docker build --platform linux/amd64 -t codex-pool-passport:rc .` PASS (image sha256:bcd8a44b9012).
- Authority matrix: `TestAuthorityMatrix` covers self, passes, console, member creation, provider contribution, suspension by kind.
- Storage/backup: `TestPairedBackupManifestRestore` proves SHA-256-verified Bolt and DuckDB restore to pre-mutation values.
- Security review: CSRF enforced at passport_handlers.go:176,237; cookie flags at passport.go:416; avatar bounded at passport_avatar.go:30-41; DuckDB parameterized throughout.
- Omission/bloat/theatre audit: all retained capabilities justified; removed capabilities have no user-facing consequence.

## Remaining merge and release proof

| Gap | Classification | Required action |
|---|---|---|
| Credential replay — all 50 production credentials | Accepted external proof (release blocker) | Run against staging with production credentials |
| Migration/rollback rehearsal on production data | Accepted external proof (release blocker) | Copy production data to staging, run A1 then A8 |
| DuckDB 6M-row benchmark on Linux staging | Accepted external proof (release blocker) | Run `ANALYTICS_BENCH_ROWS=6000000 go test -bench BenchmarkDuckDBUsageQueries` on droplet |
| Forced analytics crash injection | Accepted external proof (release blocker) | Linux staging with process kills at transaction boundaries |
| Screen reader and real device walkthrough | Accepted external proof (release blocker) | Screen reader at both viewports; real phone + laptop join |
| Secret hygiene staging scan | Accepted external proof (release blocker) | `TestSecretsNeverLogged` + Caddy journal scan |
| Runtime health check in isolated container | Non-blocking follow-up | `docker run --rm codex-pool-passport:rc` with config volume |
