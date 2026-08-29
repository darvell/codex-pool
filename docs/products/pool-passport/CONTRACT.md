---
product: Pool Passport
contract_shape: dossier
release_target: complete-v1
status: approved
owner: Darvell
research_date: 2026-08-18
research_commit: 82d3104
base_commit: 82d3104
---

# Pool Passport

## Read this first

### Product thesis and complete result

codex-pool lends pooled AI capacity to a circle of friends. Today the entire access model is one shared string — `friend_code` — sent as a header and compared with `!=` at `router.go:259`. Everyone who holds it is equally powerful. Fifty people have credentials in their home directories and half of them are recorded as `friend-xxxx@pool.local`, so nobody can say who they are. Nothing can be revoked without rotating the one signing secret and breaking all fifty at once. The usage charts show the pool, never a person.

Pool Passport replaces that with named principals.

> Everyone who consumes pooled capacity is a named principal with a revocable credential and an honest usage record. A member signs in and operates the pool. A guest taps one link and is in, with a note recording who they are. Anyone can see exactly what pooled capacity they burned, by hour, provider, model, tokens, and dollars — and the operator can see it for everyone and cut off any single person without disturbing the rest. Bring-your-own-key passthrough stays outside pool accounting and is labelled as such.

The complete release: three principal kinds with distinct authority; member sign-in by password with optional passkeys; guest passes carrying a required private note and optional expiry, redeemed by a multi-use magic link; user-editable nicknames and uploaded avatar images that are normalized server-side and appear in analytics; self-service labelled client credentials for per-machine/per-context analytics and independent revocation; opaque server-side sessions; per-request authorization against live status and a per-principal credential issue-time cutoff; per-principal token and cost analytics derived from an immutable DuckDB event ledger, self-scoped for guests; a durable Bolt outbox that cannot silently drop facts; an operator console with ranking, inspection, suspension, analytics freshness, and an audit log; a measured 24-month storage envelope; migration of all fifty existing users with IDs and history intact; transitional account claiming with the former friend code; and retirement of that code from request authentication after origin analytics are preserved.

**Deferred essential capabilities:** None

### Complete-product standard

A new friend goes from a tapped link to a working CLI without creating an account or asking a question. A member signs in, operates the pool, and never re-enters a password. Every principal reads and exports their own pooled-capacity burn; bring-your-own-key traffic is reported only as an excluded aggregate. The operator names every principal, ranks them by consumption, and cuts any one off in a click while the other forty-nine keep working. Nothing that exists today stops working during the change, and the change can be rolled back.

### Users and product loops

**Darvell, operator.** Owns the droplet and `ADMIN_TOKEN`. Today he cannot tell who is burning his Claude quota.

**Members.** Trusted to run the pool: add provider accounts, watch capacity, mint passes. No such role exists today.

**Guests.** Being AI-pilled. Should answer nothing and install nothing to get started.

**Legacy users.** The fifty. Their existing CLI credentials keep working; on the web they use the former pool code once to choose a username and password. When the browser still has their old setup token, the account claim keeps the same principal ID and history.

Loops: **join** (member writes the note, creates, copies, sends; guest taps, lands authenticated, copies one shell line); **operate** (sign in, inspect, act, return); **consumption** (CLI request → authorize → durable outbox → DuckDB fact → visible on the dashboard); **accounting** (rank, notice an outlier, read their note, inspect, suspend); **analytics durability** (drain, idempotent commit, acknowledge, reconcile). Detail in `PRODUCT.md`.

### Scope frontier and category decisions

**In.** Three principal kinds. Password and optional passkey sign-in. Guest passes with private notes, optional expiry, revocation, multi-use links. Up to 20 self-service labelled client credentials per principal, with per-client stats, expiry, rotation, and revocation. Sessions. Per-request authorization with issue-time cutoffs. Per-principal token and cost series with charts and export. Operator console with audit log. Retention. Migration. Transitional friend-code account claiming followed by friend-code retirement.

**Out.** Uninvited public sign-up. Email of any kind. Self-service password reset. Organizations, teams, custom roles. Enforced spend caps. Notifications. Mobile apps. Federation. SSO. Latency and error-rate analytics.

Load-bearing category decisions:

- **Password reset — Exclude.** The server sends no email, so recovery is an operator-minted single-use link copied the same way a guest pass is. The sign-in screen says this instead of showing a dead link.
- **Spend caps — Adapt.** LiteLLM's headline feature. Here the operator gets ranked burn and one-click suspend: detection and a manual kill rather than an automatic one. Upstream quota already bounds real loss, and a hard cap would need a synchronous counter on the proxy hot path. The interface never shows a limit, because none exists.
- **Audit log — Include.** Several members hold destructive authority; "who revoked Dave" must be answerable.
- **Organizations — Exclude.** A second pool is a second deployment.

Full ledger in `PRODUCT.md`.

### Product topology and obligation summary

Eleven of thirteen obligation modules apply. **Collaboration or real-time state** does not: principals share capacity but never a document, presence, or ordered stream, and the dashboard polls. **Billing** does not: no money changes hands and no plan gates access; dollar figures attribute the operator's own subscription cost and are not a charge or a cap. The complete map with owners and proofs is in `PRODUCT.md`.

### Key experience decisions

The dashboard is the existing Signal Room, extended in its own grammar — 92px icon rail, edge-to-edge hairline panels, section codes, IBM Plex Mono with tabular numerals. Three destinations are added: `MINE`, `PASSES`, `CONSOLE`. A guest sees only `MINE` and `SETUP`; the others are not rendered rather than rendered-and-disabled, because a disabled control advertises capability a guest cannot have.

Decisions that shape behavior:

- **The gate is for members only.** Guests never see a sign-in form; the link is their credential.
- **Expired, revoked, and unknown links are deliberately indistinguishable** to the holder. Telling a stranger they were specifically revoked leaks a fact they should hear from a person.
- **Revocation mid-session is a full-surface takeover**, not a toast. A dashboard still rendering behind a dismissed notice would lie about authority.
- **The note carries the most visual weight in a pass row** — it is the only thing that identifies a human.
- **No motion on chart updates.** A moving chart on a 30-second poll is noise.
- **Charts expose a visually hidden data table**, because the existing kit renders to canvas and canvas is opaque to a screen reader.

**Experience checks:** Reference, Expectation, Glance, Surface, Dwell, Platform

Detail in `EXPERIENCE.md`.

### Key system decisions

**Extend the existing Bolt store; add no service.** Rejected Postgres (splits identity from the analytics it must join against, and adds a service to a single-binary deployment), hosted identity (a vendor and a network dependency for fifty users, and it cannot emit provider-native credential envelopes), and per-user friend codes (more shared secrets, still no sessions, revocation, notes, or expiry).

**The credential issue-time cutoff is the load-bearing mechanism.** Each of the four existing access envelopes already carries a signed issue time: JWT `iat`, Gemini OAuth `iat`, the Gemini API-key timestamp, and the Claude token timestamp. Migration sets each principal's cutoff to zero, so all fifty existing credentials keep working. Revocation advances one principal's cutoff, rotates their download token, and kills their sessions; every old credential for that principal fails while the other forty-nine are untouched. No envelope gains a field or changes shape — an earlier epoch proposal was rejected because the old Gemini API-key and Claude parsers require exactly three fields.

**Authorization is an in-memory map read.** It runs on every proxied request; a Bolt transaction there would slow all traffic.

**DuckDB is the canonical analytics ledger; Bolt is the durable handoff.** The current SQLite queue silently drops when full (`analytics_store.go:165-171`), while a new Bolt bucket for every chart would calcify future questions. Each completed usage observation and its pricing provenance first commits to an ordered Bolt outbox. One writer appends an explicit transaction to DuckDB and acknowledges only after commit; a stable event ID makes crash replay idempotent. Charts derive from immutable request facts rather than precomputed bucket families.

**Sessions are opaque, server-side, and stored as SHA-256 digests**, in an `HttpOnly; Secure; SameSite=Strict` cookie with a double-submit CSRF token. Join and recovery secrets live in URL fragments, are removed from history, and are POSTed same-origin, so they do not require a cross-site cookie or appear in Caddy logs. This replaces `localStorage` holding plaintext long-lived provider credentials.

**Migration preserves IDs byte-for-byte**, synthesizes a note for each of the fifty, freezes the analytics salt to the historical friend-code value, and never writes to `pool_users.json`. The old binary is a safe rollback only before any new principal or revocation; after that, it cannot enforce the new credential cutoff and recovery is forward-only.

Repairs carried along because they sit directly in the changed paths: `randomHex` ignoring `rand.Read`'s error and silently minting an all-zero token; four non-constant-time secret comparisons; two O(n²) bubble sorts on hot read paths; the fail-open branch that grants full access when nothing is configured; and `UserDailyUsage`'s hardcoded provider switch that silently loses ZAI, Xiaomi, Grok, and Adverserial tokens.

Detail in `SYSTEM.md`.

### Quality and operating envelope

Authorization adds under 1ms p99 per proxied request. DuckDB returns a 30-day per-principal view under 300ms p95 and a one-year operator view under 750ms against a 6M-row fixture. The durable outbox normally drains within 5 seconds, loses zero acknowledged facts across forced crashes, and makes backlog visible. Analytics storage is measured to keep at least 24 months below 70% filesystem use. Argon2id verification lands between 50ms and 250ms. All fifty credentials keep working. The initial dashboard payload stays under 400KB gzipped.

Envelope: one pool, one droplet, one operator, a handful of members, up to roughly 200 principals, the nine existing providers. No new hosted dependency and no new cost. Module changes: `go-webauthn/webauthn` v0.17.4; `golang.org/x/crypto` promoted for argon2id; and the official `github.com/duckdb/duckdb-go/v2` pinned to the selected DuckDB release. DuckDB changes packaging from a macOS cross-build to a pinned Linux Docker build with native bindings.

Targets, measurements, and mechanisms are in `SYSTEM.md`.

### Acceptance portfolio

Eleven scenarios, all release-blocking: clean deployment and migration; a guest going from tapped link to running CLI on real devices; member sign-in and passkey enrolment; the guest authority boundary enforced at the API rather than hidden in the interface; revocation landing mid-session with a live CLI and an open dashboard; the operator identifying and stopping a runaway; all fifty production credentials replaying green; the explicit rollback boundary; forced analytics crashes and a 6M-row storage/query envelope; paired Bolt/DuckDB backup restore; and accessibility at both viewports.

Full portfolio, proofs, and gates in `DELIVERY.md`.

### Contract index

| File | Owns |
|---|---|
| `CONTRACT.md` | Thesis, frontier, key decisions, review, approval |
| `PRODUCT.md` | Users, loops, capability ledger, lifecycle, obligation map, category expectations, scope frontier |
| `EXPERIENCE.md` | Surfaces, journeys, states, design rules, platform matrix, accessibility, experience checks |
| `SYSTEM.md` | Constraints, domain model, authority, topology, integrations, state, security, quality envelope, operations |
| `DELIVERY.md` | Risk retirement, slices, claim-to-proof map, acceptance portfolio, release gates |

## Review and approval

### Completeness review

Verdict: **Approve with findings resolved.**

Three findings changed the contract:

1. *The guest boundary was described only as an interface rule.* A guest not seeing the console is not the same as a guest being unable to read the endpoint behind it. Resolved by requiring self-usage endpoints to resolve their subject from the session and never from a parameter, and by adding `TestGuestCannotReadOtherPrincipal` and acceptance A4, which tests at the API.
2. *Rollback was asserted too broadly.* The old parsers do **not** ignore an added field in the Gemini API-key and Claude formats; they require exactly three parts. Resolved by rejecting the epoch design, using the signed timestamps already present in every format, leaving `pool_users.json` untouched, and stating the real boundary: old-binary rollback is safe only before a new principal or revocation.
3. *The first analytics design repeated the current mistake.* It proposed more Bolt rollups — hourly cost, daily model mix, 45-day downsampling — which made each future question another write schema and destroyed request-level optionality. The owner challenged this before approval. Resolved by making DuckDB the immutable analytical ledger, Bolt a durable outbox, and crash replay/reconciliation/backup consistency release-blocking.

### Adversarial review

Verdict: **Approve.**

*Omission attack.* Probed acquisition, first value, repeated use, recovery, trust, analytics truth, and operation. Findings incorporated: operator-delivered member recovery without email; private rather than guest-visible notes; fragment-delivered join/recovery secrets that avoid access logs and previews; step-up before passkey enrolment; global Argon2 work limits; explicit credential rotation; per-client credentials and analytics for the requested machine split; provider OAuth state bound to the initiating member; pricing and normalization provenance; partial-stream labelling; crash-safe outbox replay; paired-store backup; and a declared accounting-gap state after emergency storage is exhausted.

*Bloat attack.* Tried to remove each capability. The audit log survived because several members hold destructive authority. DuckDB replaced the model-day bucket and all new aggregate families: request-level facts answer the model question without predicting every future slice at write time. The durable outbox survived because direct DuckDB writes would put analytics availability on the proxy path, while an in-memory queue repeats today's silent-loss bug. Passkeys survived on the user's explicit request. Latency and error-rate analytics were removed — a real gap, but nobody asked, and it would thread new fields through twelve recording call sites.

*The sharpest surviving objection:* a multi-use join link is a bearer credential that will sit in a message thread forever, and a forwarded link is indistinguishable from the recipient using a new device. Single-use would break the phone-then-laptop case, which is the normal case. Accepted deliberately, and made noticeable rather than hidden: the pass row states the exposure, the console shows a distinct-origin count per pass, and revocation is one click.

### Theatre check

Verdict: **Pass.**

Removed during review: a `TestPasswordHashNotReversible` that would assert a property of argon2 rather than of this code; a per-principal health badge with nothing behind it; a "sessions by device type" panel answering no question anyone asked; a QR code when the real action is copy-and-send; a duplicate JSON export when the ordinary API is already JSON; and a proposed abstraction over the four credential formats, which would have added an interface to make four small parsers look uniform while making the cutoff check harder to read at each site.

Every remaining proof row names a specific wrong implementation it catches. Every quality target names a scenario and a consequence rather than a number chosen for looking rigorous.

### Open decisions and blockers

None.

### Approval

Approved by: Darvell
Date: 2026-08-18
Commit: b42cbc9
Conditions: Upgrade product toolchain to Go 1.25; pin go-webauthn v0.17.4 and x/crypto v0.52.0.
