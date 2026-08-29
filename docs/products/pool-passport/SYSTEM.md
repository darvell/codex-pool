# System — Pool Passport

Owner document for architecture, state, trust, quality, and operations.

## Constraints, evidence, and architecture decision

| Constraint | Evidence | Design consequence |
|---|---|---|
| Four provider credential envelopes are frozen | CLIs parse `sk-ant-oat01-pool-*`, `ya29.pool-*`, `AIzaSy-pool-*`, and an OAuth-shaped `auth.json`; deliberate per `pool_users.go:350-353,364-366,410-412,562-565` | Identity is replaced above the credential layer; mint and parse are untouched |
| 50 live credentials are in real people's home directories | Production `pool_users.json`, observed 2026-08-18 | Migration preserves IDs; no cutover invalidates a working credential |
| Usage history is keyed by `PoolUser.ID` | `storage.go:347` key `userID\|hour\|accountType`; `purgeNonPoolUsers` at `storage.go:1233` | Principal ID must equal the old ID byte-for-byte, and the principal store must feed the purge allowlist |
| Friend code is also the origin hash salt | `poolHashSalt` at `utils.go:58-64`, used at `main.go:1859,4605,4617,4803,4819` and `frontend.go:246,2226` | Salt is decoupled and frozen before the code is removed |
| Single Go binary, embedded stores, one droplet | systemd `codex-pool`, Caddy, port 14430, `/opt/codex-pool` | No external database, cache, or queue |
| `proxy.db` is 627MB because Bolt stores raw JSON requests plus overlapping aggregate families | Production observation; `storage.go:243-394` updates raw, account, user, daily, user-hourly, and global-hourly records in one request | Stop adding analytical dimensions to Bolt; retire redundant long-lived aggregates only after DuckDB reconciliation proves parity |
| SQLite analytics writes drop silently when the queue is full | `analytics_store.go:161-171` | Replace the queue with a durable Bolt outbox and replace SQLite with DuckDB as the canonical event ledger |
| DuckDB is an in-process analytical database, not a multi-process service | Official DuckDB concurrency contract: one read-write process; concurrent reads and appends inside it | The service exclusively owns the live file; one writer connection, bounded reader pool, no external CLI against the live database |
| DuckDB's official Go client uses native bindings | `github.com/duckdb/duckdb-go/v2` official installation and repository | Build the Linux release in a pinned Linux container; the current macOS `GOOS=linux` cross-build is retired |
| Authorization runs on every proxied request | `proxyRequest` at `main.go:1725` | Principal lookup must be an in-memory map read, not a Bolt transaction |

**Decision: use two embedded stores with one-way ownership.** Bolt owns principals, sessions, credentials, guest passes, audit, and a durable ordered analytics outbox. DuckDB owns immutable usage facts and every analytical query. The router enforces authority from Bolt; the dashboard never queries Bolt aggregates for analytics after cutover. Rejected: Postgres (adds a service to a single-droplet product); direct DuckDB writes on the proxy path (analytics failure would delay or lose live traffic); continued Bolt aggregate families (each future question becomes another durable bucket and write branch); and an external identity provider (network dependency and vendor, while still unable to emit provider-native envelopes).

## Domain model and invariants

```go
type PrincipalKind string // "operator" | "member" | "guest"
type PrincipalStatus string // "active" | "suspended" | "expired"
type ClientCredentialStatus string // "active" | "revoked" | "expired"

type Principal struct {
    ID           string          // preserved from PoolUser.ID on migration
    Kind         PrincipalKind
    Status       PrincipalStatus
    Note         string          // required, member/operator-only: who received this pass
    DisplayName     string     // optional nickname, visible in analytics
    AvatarUpdatedAt *time.Time // nil until a normalized avatar image exists
    Email           string     // members: normalized sign-in identity. guests: optional, informational.
    PasswordHash string          // argon2id, members only
    CredentialsValidAfter time.Time // credentials issued before this instant are invalid
    PlanType     string          // preserved; drives the Codex JWT claim
    ExpiresAt    *time.Time      // nil means no expiry
    CreatedBy    string          // principal ID of the creator; empty for migrated
    CreatedAt    time.Time
    LastSeenAt   time.Time
}

type ClientCredential struct {
    ID              string
    PrincipalID     string
    Label           string          // e.g. "MacBook"; user-chosen, not hardware-attested
    Status          ClientCredentialStatus
    ValidAfter      time.Time
    ExpiresAt       *time.Time
    DownloadDigest  [32]byte
    DownloadCiphertext []byte       // AEAD, re-copyable setup link
    CreatedAt       time.Time
    LastSeenAt      time.Time
}
```

Invariants, each with an enforcement point:

1. `Note` is non-empty for every principal. Enforced at the store's create and update boundary; migration synthesizes `"legacy: <email>"` so the invariant holds for all 50 from the first boot.
2. `ID` is immutable. The store exposes no rename.
3. `CredentialsValidAfter` only moves forward. Restore does not move it back, so credentials issued before a revocation stay dead.
4. Exactly one principal has `Kind == "operator"`. Enforced on role change; bootstrap creates it through an `ADMIN_TOKEN`-authenticated setup endpoint.
5. Member email is `TrimSpace`d, Unicode-normalized, and case-folded for uniqueness; the original display spelling is retained separately. It is a login handle assigned by the operator, not a claim that the mailbox was verified.
5. A principal is authorized iff `Status == "active"`, (`ExpiresAt == nil` or `ExpiresAt` is in the future), and the presented credential's signed issue time is not before `CredentialsValidAfter`.
6. A session is valid iff its principal is authorized and its own `ExpiresAt` is in the future. Sessions are deleted on revocation, but the live principal check is still authoritative.
7. Every pool credential resolves to both a principal and a client credential. Principal status/cutoff and client-credential status/cutoff/expiry must all authorize.
8. A principal may hold at most 20 active client credentials. Labels are required, private to the principal and members, and need not be unique.
9. Existing credentials without an embedded client ID map to the migrated `legacy-default` credential.
10. Usage records are never deleted by a status change. Only explicit deletion removes history.

### Credential issue-time cutoff — the mechanism that makes revocation real

Today a Codex JWT is valid for ten years (`pool_users.go:260`), the Claude and Gemini-API-key parsers read signed timestamps but never compare them to a principal-level cutoff, and the only kill switch is `PoolUser.Disabled`, which `proxyRequest` skips entirely when `h.poolUsers == nil` (`main.go:1758`). Rotating `POOL_JWT_SECRET` kills all 50 at once.

Every existing access-credential format already carries a signed issue time without changing its shape:

| Format | Existing issue time | Verified in |
|---|---|---|
| Codex JWT | `iat` claim | `validatePoolUserJWT` |
| Gemini OAuth `ya29.pool-*` | `iat` in the signed JSON payload | `isGeminiOAuthPoolToken` |
| Gemini API key `AIzaSy-pool-<uid>.<ts>.<sig>` | the existing timestamp segment | `isPoolGeminiAPIKey` |
| Claude `sk-ant-oat01-pool-<b64(uid.ts.sig)>` | the existing timestamp field | `parseClaudePoolToken` |

Migration sets `CredentialsValidAfter` to zero, so every one of the 50 existing credentials remains valid. Revocation sets it to `now`, rotates the download token, deletes browser sessions, and suspends the principal. Restore makes the principal active but does not lower the cutoff; the person must download fresh credentials. The other 49 are untouched.

Refresh tokens need a separate repair. The current `poolrt_<userID>_<random>` parser trusts any string with three underscore-separated parts and no signature (`handlers.go:435-450`). New refresh tokens retain the `poolrt_` prefix but carry a signed issue time. Legacy refresh tokens are accepted only while `CredentialsValidAfter` is zero; after the first revocation they can never mint fresh access credentials. The old binary still parses new refresh tokens because it only requires `len(parts) >= 3` and reads `parts[1]` as the user ID.

New client credentials reuse the existing identity slot inside each signed envelope as `<principalID>-c-<clientCredentialID>`: JWT `sub`, Gemini OAuth `user_id`, the Gemini API-key user segment, and the Claude token user field. This changes no prefixes, separator counts, or CLI-visible envelope shapes. Tokens without `-c-` are legacy and resolve to `legacy-default`. The parser returns principal ID, client credential ID, and signed issue time; authorization checks both records. Because an old binary would treat the composite as a nonexistent user ID, minting the first new client credential crosses the already-documented forward-only rollback boundary.

The Gemini API key comparison at `pool_users.go:513` moves from `!=` to `hmac.Equal`, as do the admin-token and friend-code comparisons at `router.go:216,247,259` before those paths are removed.

## Authority and trust boundaries

| Action | Guest | Member | Operator |
|---|---|---|---|
| Use the pool through a provider credential | Yes | Yes | Yes |
| Mint, label, rotate, and revoke own client credentials | Yes | Yes | Yes |
| Read own usage and export it | Yes | Yes | Yes |
| Read pool-wide analytics | No | Yes | Yes |
| Read another principal's usage | No | Yes | Yes |
| Create, note, expire, revoke a guest pass | No | Yes | Yes |
| Add or manage provider accounts | No | Yes | Yes |
| Create or suspend a member | No | No | Yes |
| Delete a principal or purge history | No | No | Yes |
| Change the operator role | No | No | Yes |
| Read raw client IPs | No | No | Yes |

Three trust boundaries:

**Browser to server.** An opaque 32-byte session token in a cookie: `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, 30-day sliding TTL. Join and recovery tokens live in the URL fragment (`/join#token`), which browsers do not send to Caddy, referrers, or link-preview bots; the same-origin page removes the fragment and POSTs it in the body before the session is set. Stored server-side as a SHA-256 digest, so a leaked database does not yield usable sessions. Every state-changing endpoint requires the double-submit CSRF token issued alongside the session; `SameSite=Strict` is defense in depth, not a replacement for request-bound CSRF validation.

**CLI to proxy.** The four envelopes stay byte-shape compatible. Their existing signed issue times are checked against the in-memory principal's `CredentialsValidAfter` on every request. Provider-credential passthrough (`main.go:1832-1840`) remains unauthenticated and has no per-request usage fact by explicit product decision. It uses the caller's own upstream capacity, not the pool's. A separate aggregate counter reports passthrough request volume; every pool token/cost total is labelled "excludes bring-your-own-key passthrough" so the boundary cannot be mistaken for complete attribution.

**Server to upstream provider.** Unchanged.

The fail-open branch at `router.go:239-242` — which grants full access when neither admin token nor friend code is configured — is replaced by an explicit `POOL_OPEN_MODE=1` opt-in for local development. Absent that variable, an unconfigured deployment denies rather than admits.

## Runtime and deployment topology

One Go process on one droplet behind Caddy. No change to the topology.

```
Caddy :443 (codex.ppflix.net, auto TLS)
  └─ codex-pool :14430
       ├─ router.go             session + principal authorization
       ├─ proxyRequest          per-request principal check → provider routing
       ├─ Bolt data/proxy.db    principals, sessions, links, passkeys, audit, analytics_outbox
       ├─ DuckDB data/usage.duckdb
       │    └─ immutable usage_events + schema/pricing metadata
       ├─ analytics writer      outbox → explicit DuckDB transaction → acknowledge
       ├─ analytics readers     bounded connection pool, cancellable SQL
       └─ embedded web/dist     React dashboard
```

Added in-process background work: one analytics writer, one lightweight reconciler, and the existing session/pass expiry work. The writer is the only DuckDB writer connection. Readers use separate connections inside the same process; no second process opens the live file read-write.

## Interface-to-system map

| Product transition | Operation | State change | Result | Proof seam |
|---|---|---|---|---|
| Member signs in | `POST /api/auth/login` | Session created | Cookie + CSRF token | `TestArgon2idLoginRoundTrip` |
| Legacy holder claims account | `POST /api/auth/signup` | Existing principal promoted when a legacy setup token is present; otherwise a named member is created | Cookie + CSRF token | `TestLegacySignupClaimsExistingPrincipal` |
| Member asserts passkey | `POST /api/auth/webauthn/login/{begin,finish}` | Session created; credential sign-count advanced | Cookie | `TestWebAuthnRegisterAndAssert` |
| Member enrols passkey | `POST /api/auth/webauthn/register/{begin,finish}` | Credential stored | Listed on Mine | `TestWebAuthnRegisterAndAssert` |
| Guest taps link | `GET /join#token` → `POST /api/auth/join` body | Fragment removed from history; session created; link `LastUsedAt` and origin count updated | Redirect to Mine | `TestJoinEstablishesSession`, `TestJoinTokenNotLogged` |
| Member creates a pass | `POST /api/passes` | Principal + link created; audit entry | Copyable URL | `TestPassRequiresNote` |
| Member edits a note | `PATCH /api/passes/{id}` | Note updated; audit entry | Row updates | `TestNoteEditAudited` |
| Member revokes a pass | `DELETE /api/passes/{id}` | Status suspended; issue-time cutoff advanced; download token rotated; sessions killed; audit entry | Row moves to SUSPENDED | `TestRevokedPrincipalDenied` |
| Principal mints a client credential | `POST /api/me/clients` | Client record + encrypted download token + audit | Labelled setup link | `TestClientCredentialLifecycle` |
| Principal rotates/revokes a client | `POST /api/me/clients/{id}/rotate` / `DELETE` | Client cutoff/status and download token change | Other clients unaffected | `TestCredentialRotation` |
| Anyone reads own usage | `GET /api/me/usage?window=&client=` | None | Self-scoped series, optionally partitioned by client credential | `TestSelfUsageScoping`, `TestPerClientAnalytics` |
| Anyone exports own usage | `GET /api/me/usage/export.csv` | None | CSV; the ordinary usage endpoint remains the JSON API | `TestSelfExportScoped` |
| Member reads the roster | `GET /api/principals?window=` | None | Ranked list with sparklines | `TestConsoleRequiresMember` |
| Member inspects a principal | `GET /api/principals/{id}/usage` | None | Full series | `TestGuestCannotReadOtherPrincipal` |
| Operator suspends a member | `POST /api/principals/{id}/suspend` | Status + issue-time cutoff + download-token rotation + sessions + audit | Row moves | `TestMemberCannotSuspendMember` |
| CLI sends a request | `proxyRequest` → `recordUsage` | Immutable fact and cost provenance committed to Bolt outbox | Completion is not blocked on DuckDB | `TestUsageOutboxCommitted` |
| Analytics writer drains | outbox worker | Batch inserted into DuckDB in one explicit transaction; outbox rows acknowledged after commit | Charts include the new facts | `TestOutboxCrashReplay` |
| Analytics reconciler runs | scheduled checker | Compares recent Bolt raw totals, outbox state, and DuckDB facts | Operator fault or clean checkpoint | `TestAnalyticsReconciliation` |

Removed: `POST /api/friend/claim`, the `X-Friend-Code` request-authority check, the operator-unlock probe against `/admin/accounts`, and the `friend_name`/`friend_tagline` config keys. `friend_code` survives temporarily as the enrollment secret for `POST /api/auth/signup` and as the one-time analytics-salt seed; it never authorizes ordinary API or provider traffic and is cleared after the migration window. `ADMIN_TOKEN` survives as the break-glass credential for the admin API and for bootstrapping the first operator.

The CLI-local routes that currently return before `proxyRequest` — `/api/codex/usage`, `/backend-api/wham/usage`, the Claude profile and usage routes, `/oauth/token`, `/config/*`, and the model-list paths — each resolve the presented pool credential or download token through the same `authorizePrincipal` function before answering. WebSocket upgrades already enter through `proxyRequest` and keep that check. Only the two deliberate no-op compatibility paths stay unauthenticated, because they return no pool data and perform no upstream work.

## External systems and integration lifecycle

**Nine upstream providers.** Routing and quota polling are unchanged. Account contribution moves from friend-code/admin-token gates to member sessions. Every OAuth/add flow creates a one-time, expiring state record bound to initiating principal, browser session, provider, redirect origin, and intended action; callback consumes it exactly once. API keys and OAuth tokens never return to the browser after submission. `AddedBy`, last actor, and every enable/disable/refresh/delete action are audited. All members may add, refresh, enable, and disable shared provider accounts; only the operator permanently deletes one.

**WebAuthn.** `github.com/go-webauthn/webauthn` v0.17.4, pinned. Minor upgrades are treated as breaking and gated on the passkey test. RP ID is the bare host; RP origin is the full `https://` origin; cross-origin ceremonies stay rejected. Browser half is `@simplewebauthn/browser`. Passkeys are discoverable credentials with user verification required, keyed to a random stable WebAuthn user handle rather than email. Enrolment, credential removal, and password change require a fresh password or passkey assertion within five minutes — an old stolen session cannot install a new authenticator. A member may hold several credentials; losing all falls back to password, and losing both falls back to an operator recovery link. Sign-counter regressions are recorded and denied when the authenticator supplies a meaningful counter; synced passkeys with zero counters are handled according to the library contract rather than falsely flagged as clones.

**Argon2id.** `golang.org/x/crypto/argon2` v0.52.0, pinned directly under the approved Go 1.25 toolchain. Parameters: 64MB memory, 3 iterations, 4 lanes, 16-byte salt, 32-byte key. Encoded in the standard PHC string so parameters can rise later without invalidating existing hashes.

**No email.** No SMTP client, no sending domain, no third-party mail API. Links are copied by a human.

## State, data, provenance, and lifecycle

New Bolt buckets in the existing `data/proxy.db`:

| Bucket | Key | Value | Lifecycle |
|---|---|---|---|
| `principals` | principal ID | `Principal` JSON, including nickname and avatar update timestamp | Until explicitly deleted |
| `passport_avatars` | principal ID | normalized 128×128 PNG, ETag, updated timestamp | Replaced on upload; deleted with principal |
| `sessions` | SHA-256 of the token | principal ID, created, expires, user agent, origin hash | Deleted at expiry, on sign-out, or on principal revocation |
| `client_credentials` | client credential ID | principal ID, label, status, cutoff, expiry, encrypted download token, last seen | Revocable independently; deleted with principal |
| `join_links` | SHA-256 of token | principal ID, AEAD-encrypted token, created by/at, last used, distinct-origin count | Deleted with principal; plaintext is decryptable only for authorized re-copy |
| `webauthn_creds` | principal ID + credential ID | public key, sign count, transports, AAGUID, created | Deleted with its principal or on removal |
| `audit` | timestamp + sequence | actor, action, subject, before, after | Retained indefinitely; small and append-only |
| `analytics_outbox` | monotonically increasing sequence | encoded immutable usage fact | Deleted only after the matching DuckDB transaction commits |
| `analytics_state` | fixed keys | next sequence, acknowledged sequence, reconciliation/checkpoint metadata | Retained |

DuckDB `data/usage.duckdb` owns:

```sql
CREATE TABLE usage_events (
    event_id UUID PRIMARY KEY,
    proxy_request_id VARCHAR NOT NULL,
    usage_sequence INTEGER NOT NULL,
    upstream_request_id VARCHAR,
    attempt_number INTEGER NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    principal_id VARCHAR NOT NULL,
    client_credential_id VARCHAR NOT NULL,
    origin_id VARCHAR,
    account_id VARCHAR NOT NULL,
    account_type VARCHAR NOT NULL,
    plan_type VARCHAR,
    model_reported VARCHAR,
    model_normalized VARCHAR,
    normalization_version VARCHAR NOT NULL,
    raw_usage_json JSON,
    input_tokens BIGINT NOT NULL,
    cache_read_tokens BIGINT NOT NULL,
    cache_creation_tokens BIGINT NOT NULL,
    output_tokens BIGINT NOT NULL,
    reasoning_tokens BIGINT NOT NULL,
    billable_tokens BIGINT NOT NULL,
    api_equivalent_cost_usd DECIMAL(18,9) NOT NULL,
    pricing_version VARCHAR NOT NULL,
    usage_completeness VARCHAR NOT NULL, -- complete | partial | estimated
    source VARCHAR NOT NULL,             -- live | bolt_import | sqlite_import
    source_grain VARCHAR NOT NULL        -- request | hour | day
);
```

`event_id` is generated once before the Bolt outbox commit and persisted inside the outbox value; replay never regenerates it. `proxy_request_id + usage_sequence` distinguishes several valid usage observations from one client request, while `attempt_number` distinguishes upstream retries. Queries count client requests with `COUNT(DISTINCT proxy_request_id)` and sum usage facts; a retry that produced no billable usage emits no fact, while a retry that did consume tokens is retained rather than hidden.

`raw_usage_json` contains only the sanitized provider usage/count block, never the request, prompt, response, tool arguments, credential, or provider headers. Together with `normalization_version`, it lets a corrected parser rebuild normalized columns without pretending the old normalization was right.

The fact table stores no prompt text, response text, raw credential, raw IP, or user-agent string. `PromptCacheKey` stays out: it is useful for routing diagnostics but creates a correlatable content-derived identifier with no approved dashboard question.

**Cost semantics and provenance.** `api_equivalent_cost_usd` is what those tokens would cost at the provider's metered API prices. It is not actual marginal spend: most pooled accounts are subscriptions. The interface always says **API-equivalent value**. Actual monthly subscription spend remains a separate account-level input and may support an ROI view, but is never allocated to people as if it were request cost. Ingestion stores the calculated value and `pricing_version`, a deterministic hash/version of the active model-price table. Historical value never changes when prices change. A separate reprice query may show current-price value, explicitly labelled, and never overwrites recorded value.

**Partial streams.** `usage_completeness` distinguishes complete provider usage from partial or estimated observations. The analytics total includes partial facts, but the interface exposes their count; an aborted Claude stream must not silently look exact.

The principal store keeps every principal in memory behind an `RWMutex`, backed by Bolt, so hot-path authorization is a map read. `pool_users.json` is read once at migration and then left untouched.

**Migration.** Recent request-grain rows from Bolt `usage_requests` and SQLite `request_costs` are deduplicated into `usage_events` using a deterministic event ID. Older `user_hourly_usage` history imports as `source_grain = 'hour'` with unavailable dimensions left null and `usage_completeness = 'estimated'`; the migration does not invent model, cache-creation, or cost detail that was never stored. Import counts and totals are reconciled before the dashboard switches reads.

**Retention.** Request-level DuckDB facts are retained indefinitely at the approved envelope. Bolt `usage_requests` keeps 30 days as a recovery/reconciliation source. Existing long-lived user/global hourly and daily buckets remain read-only through the migration window, then are deleted only after parity proof and a backup. Sessions expire normally; audit remains indefinite.

**Deletion.** Deleting a principal removes control-plane state immediately. Usage facts remain by default under the opaque principal ID for pool accounting; an explicit operator action can purge them from DuckDB and records that destructive act in audit. The confirmation names the rows, date range, and recorded cost being destroyed.

**Provenance.** Every audit entry records actor, action, subject, and before/after values. Every usage fact records source, source grain, completeness, and pricing version.

## Ordering, concurrency, background work, and convergence

Principal reads are an `RWMutex`-guarded map. Writes take the write lock, persist to Bolt in a transaction, then update the map — so a crash between the two leaves the durable store authoritative and the next boot reloads from it.

Revocation ordering matters: persist `Status = suspended`, advance `CredentialsValidAfter`, and rotate the download token in one Bolt transaction; then delete the principal's sessions. Persisting the cutoff first closes the window where a killed session or old download URL could mint fresh access credentials.

Usage observation and cost calculation stay on the existing synchronous Bolt transaction, but the durable result is one compact outbox fact rather than another set of aggregate mutations. The proxy response does not wait for DuckDB.

The analytics writer reads an ordered batch after the acknowledged sequence, opens an explicit DuckDB transaction, inserts every fact with `ON CONFLICT(event_id) DO NOTHING`, commits, then advances the acknowledged sequence and deletes those Bolt rows. A crash before DuckDB commit leaves the outbox untouched. A crash after commit but before acknowledgement replays the batch; `event_id` makes it a no-op. The Appender's default 204,800-row commit cadence is not relied on; batch boundaries are explicit and bounded by rows and time.

One writer connection serializes schema changes and appends. Reader requests use a small separate connection pool and a context deadline. Every dashboard query has a bounded time range, selects only required columns, and is cancellable when the browser navigates away. DuckDB memory and temp-directory settings are explicit so one expensive operator query cannot evict the proxy process or fill the root filesystem.

The reconciler compares, for a closed UTC hour, the recent raw Bolt requests, unacknowledged outbox, and DuckDB facts by request count and every token class. Any difference is a persistent operator fault with the first divergent event sequence; it is never auto-healed by rewriting facts from an aggregate.

No distributed state: one process owns both files. The only convergence boundary is the durable outbox, whose lag is measured in events and age.

## Security, privacy, and safety

**Secrets at rest.** Passwords are argon2id. Sessions and single-use recovery links are digest-only. Multi-use guest links need authorized re-copy, so Bolt stores both the SHA-256 lookup digest and an AEAD-encrypted token under a dedicated 32-byte `POOL_AUTH_ENCRYPTION_KEY` held in the systemd environment and backup secret store. Encryption uses a fresh nonce and associated data containing link ID and principal ID. Passkeys store only public keys. `POOL_JWT_SECRET` and `ADMIN_TOKEN` stay in the systemd environment.

**Randomness.** `randomHex` currently ignores the error from `rand.Read` (`pool_users.go:132-136`), which on failure would produce an all-zero token that is stored and treated as valid. It is changed to return an error; credential-creation handlers fail closed with 500. A randomness failure must not crash active proxy traffic and must not mint a credential.

**Constant-time comparison.** All secret comparisons use `hmac.Equal` or `subtle.ConstantTimeCompare`. This closes `router.go:216,247,259` and `pool_users.go:513`.

**Rate limiting and password-work isolation.** The existing per-IP `bruteForceTracker` covers sign-in, passkey assertion, and join redemption. Argon2 verification also runs behind a small global semaphore sized from measured RAM; excess attempts receive 429 before allocating 64MB each. This prevents a distributed set of source IPs from exhausting process memory. Unknown-email attempts execute one fixed dummy Argon2 hash so account discovery cannot use timing. The tracker remains in-memory and resets on restart; acceptable at this scale and stated.

**Link exposure.** A join link is a bearer credential in a URL. It will land in browser history and in the recipient's message thread. Mitigations: revocation is one click, the pass row states the exposure plainly, and the console shows a distinct-origin count per pass so a link being used from five places is visible. Not mitigated: a link forwarded to a third party is indistinguishable from the intended recipient using a new device. That is the accepted cost of the zero-friction promise, and the note plus origin count is what makes it noticeable.

**Client credentials and path-secret download tokens.** `/config/*` and `/setup/*` resolve to a client credential, not directly to a principal. Any signed-in principal may mint up to 20 credentials for themselves, each with a required label and optional expiry; members may inspect labels for pool accounting, while only the owner or operator may mint, rotate, or revoke them. The default guest onboarding creates one labelled `DEFAULT`; migration creates `LEGACY DEFAULT`. URL-path bearer secrets remain because setup commands embed them. Caddy is changed to redact the token-bearing path suffix and query values before access logging; application logs never print the URI for these route families. They resolve the download token to a principal and run the same live status, expiry, and issue-time-cutoff authorization before minting a config. Revocation or explicit **Rotate credentials** advances the credential cutoff and rotates the download token, so the old access credentials and setup URL stop working while principal identity, history, browser sessions, note, and role stay intact. Rotation returns one new copyable setup link and writes an audit entry.

**Note and export rendering.** Notes are private member/operator free text, max 300 Unicode scalar values, rendered as text. Audit redacts all credentials, link tokens, password hashes, OAuth codes, and provider secrets from before/after payloads. CSV exports protect against spreadsheet formula injection by prefixing cells beginning with `=`, `+`, `-`, or `@`, and use RFC 4180 quoting.

**Browser containment and caching.** Authenticated HTML, auth responses, setup material, and usage exports send `Cache-Control: no-store`. The dashboard self-hosts its fonts and runs under a strict CSP with no third-party scripts, `frame-ancestors 'none'`, restrictive `connect-src`, and WebAuthn allowed only for the same origin. Caddy retains HSTS; responses add `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and a restrictive Permissions Policy. No service worker caches authenticated data.

**Logging.** No password, session token, join/recovery token, provider credential, encrypted token plaintext, or password hash is ever logged. The existing debug logging that prints `credential_present=%v` (`router.go:212`) is the correct pattern and is extended, not replaced.

**DuckDB execution boundary.** The application exposes only predefined parameterized analytical queries; there is no SQL console or query-text API. Automatic extension installation/loading is disabled, external file and network access are disabled for the analytics connections, and migrations use compiled-in SQL. A dashboard parameter can select a time range, principal, provider, or model — never a table name, expression, path, or URL.

**Privacy.** Raw client IPs remain in `origin_metadata`, admin-only. The DuckDB ledger stores only salted `origin_id`, never raw IP. Guests see only their own data. The dashboard sends no telemetry anywhere.

## Performance, reliability, compatibility, and cost

| Dimension | Target or budget | Scenario and consequence | Measurement | Mechanism | Release proof |
|---|---|---|---|---|---|
| Authorization overhead | Under 1ms added p99 per proxied request | Every request pays it; a Bolt read here would add milliseconds to all traffic and users would feel the proxy get slower | Benchmark against the current path | In-memory principal map behind an RWMutex | `BenchmarkAuthorizePrincipal` |
| Usage query latency | Under 300ms p95 for a 30-day per-principal series and under 750ms for a one-year operator view at 6M facts | The console's core interaction; slower than this and ranking 50 principals feels broken | DuckDB queries against a 6M-row fixture on droplet-class hardware | Columnar fact table, bounded predicates, one writer and bounded readers | `BenchmarkDuckDBUsageQueries` |
| Analytics durability | Zero acknowledged event loss; outbox lag under 5s normally and under 5 minutes after restart | A dropped fact makes per-user accounting dishonest; unbounded lag makes the dashboard stale | Forced crashes before commit, after commit, and before acknowledgement | Bolt outbox + unique event ID + explicit DuckDB transactions | `TestOutboxCrashReplay` |
| Analytics storage growth | Measured and alarmed before 70% filesystem use; at least 24 months at the approved envelope on the current volume | Events are retained rather than lossy-downsampled, so disk capacity is an explicit budget | 6M-row fixture size plus production compression ratio | DuckDB columnar compression; no prompt/response payloads; operator metric and runbook | `TestAnalyticsStorageEnvelope` |
| Sign-in cost | Argon2id verification between 50ms and 250ms on the droplet's CPU | Too fast is brute-forceable; too slow lets 5 concurrent sign-ins stall the process | Timed on target hardware | 64MB / 3 iterations / 4 lanes, tuned against measurement | `TestArgon2idCostInBudget` |
| Credential compatibility | 100% of the 50 existing credentials keep working | Any regression is a person's CLI breaking with no warning and no self-service fix | Replay every production credential against a staging build | Zero issue-time cutoff and `legacy-default` client mapping on migration | Acceptance A8 |
| Dashboard payload | Under 400KB gzipped for the initial load | Loaded on phones over cellular when a guest taps a link | Built bundle size | Existing Vite build; no new chart library | Build gate |

Reliability: DuckDB unavailability does not block proxy traffic; facts accumulate durably in Bolt and the dashboard shows backlog age. The data directory carries a preallocated emergency reserve. At the warning threshold the service releases that reserve, raises a critical alert, and keeps recording during the grace window. If Bolt still cannot durably accept an event after the reserve is exhausted, pool traffic continues by explicit decision, and the process opens an in-memory accounting-gap interval. On recovery it durably records the interval's start/end and affected request count; every chart spanning it is labelled incomplete. It never silently drops and then presents complete totals. A Bolt write failure increments a fatal accounting metric. Session store loss forces re-authentication but destroys no usage facts.

Backup and restore treat Bolt and DuckDB as a pair. The service pauses the analytics writer, records the acknowledged outbox sequence, checkpoints DuckDB, snapshots both files plus a manifest, then resumes. Restore rejects a pair whose manifest sequences do not agree; replay from the retained outbox closes an allowed tail.

Compatibility: Go 1.25. Chrome, Safari, and Firefox current versions. WebAuthn degrades to password when unsupported. The official `github.com/duckdb/duckdb-go/v2` client is pinned to the selected DuckDB release; upgrades require migration and query replay tests.

Cost: no hosted dependency or paid service. The binary is larger and the build becomes CGO/Linux-container based.

## Accessibility support and platform contracts

Owned by `EXPERIENCE.md`. The system obligations: server-rendered error pages for join failures carry semantic markup and are usable without JavaScript, since a tapped link may land in an in-app browser with restricted scripting; every chart endpoint returns the values the visually hidden data table renders; and no state is conveyed to the client by color alone — status is a field, not a CSS class.

## Configuration, observability, administration, and support

**Configuration.** Removed: `friend_code`, `friend_name`, `friend_tagline`. Added: `analytics_salt` (frozen to the historical friend code), `session_ttl_days` (30), `duckdb_path` (`./data/usage.duckdb`), `analytics_batch_rows` (512), `analytics_flush_interval` (250ms), `analytics_query_timeout` (3s), `analytics_memory_limit` (measured default, capped below available RAM), `analytics_temp_directory` (separate bounded path), `analytics_outbox_warn_age` (30s), `analytics_emergency_reserve_bytes` (measured default), `POOL_AUTH_ENCRYPTION_KEY`, and `POOL_OPEN_MODE` (local development only). `admin_password` in `[pool_users]` is dead config today and is deleted.

**Observability.** New Prometheus metrics on the existing admin-only `/metrics`: authorization outcomes, sign-in failures, active sessions, join redemptions, passthrough requests, outbox depth and oldest age, DuckDB batch rows/duration/failures, duplicate replay count, reconciliation drift, query latency/timeouts, database bytes, temp-directory bytes, and incomplete-usage event count. The console shows analytics as CURRENT, LAGGING, or FAULTED rather than silently serving stale numbers.

**Administration.** The console is the primary surface. The admin API stays as break-glass and gains principal management. The audit log answers who changed what.

**Support.** The operator's diagnostic question is "why was this person denied", and the answer must not require reading code: the metrics distinguish suspended, expired, credential-too-old, unknown-credential, and malformed-credential outcomes, and the console shows the principal's status, expiry, and credential cutoff directly.

## Deployment, packaging, migration, update, rollback, and retirement

**Packaging.** Changed deliberately. A pinned multi-stage Linux Docker build compiles the React app, then builds the Go binary with the official `github.com/duckdb/duckdb-go/v2` native library and `CGO_ENABLED=1`. The output stage exports only the Linux binary. This also fixes the existing hazard where `web/dist` is gitignored but required by `go:embed`.

**Deployment.** `docker buildx build --platform linux/amd64 --output type=local` produces the binary; the existing scp, binary swap, and systemd restart remain. The release gate builds from a clean checkout, prints the linked DuckDB version, and starts the binary on Linux before upload.

**Migration.** On first boot the process detects an unmigrated store and, in one Bolt transaction:

1. Reads `data/pool_users.json`.
2. Creates a `Principal` per `PoolUser`, preserving `ID`, `Email`, `PlanType`, and `CreatedAt`; setting `Kind = "guest"`, status from `Disabled`, zero cutoff, no expiry, and `Note = "legacy: <email>"`. Creates one `legacy-default` client credential that preserves the old `Token` as its encrypted/download lookup token, so every existing setup URL and access credential keeps working.
3. Freezes `analytics_salt` to the current friend code value.
4. Creates the DuckDB schema and pricing-version record.
5. Imports recent request-grain history from Bolt and SQLite, then older aggregate history at its honest source grain; writes an import/reconciliation report.
6. Writes the identity and analytics migration markers and marks operator bootstrap as incomplete.

It is idempotent: unique event IDs, schema versions, and migration markers make a second run a no-op. It never writes to `pool_users.json`. The dashboard keeps reading the old aggregates until imported request counts and token classes reconcile; cutover is an explicit state transition, not "migration started successfully."

The process does **not** print a password. Until an operator exists, `/setup/operator` is the only dashboard route. It requires the existing `X-Admin-Token`, then accepts the operator's email and chosen password over TLS and creates the operator principal. A bootstrap status check is idempotent; after success the endpoint returns 404 so it cannot be reused as a second account-creation path.

**Rollback.** Before any post-cutover principal has been revoked, swap the previous binary back: `pool_users.json` is unmodified, so the old binary boots and serves the same 50 users. Credentials minted by the new binary keep their old byte shape, so the old parsers accept them. Cost fields in Bolt JSON are additive and ignored by the old binary.

Rollback after a security mutation is **not** safe: the old binary cannot enforce `CredentialsValidAfter`, cannot see new principals, and would accept a pre-revocation legacy credential again. Once a pass has been revoked or a new principal has been created, recovery is a forward fix or a compatibility build, not the pre-cutover binary. The deploy procedure records that boundary explicitly; it does not promise a rollback that reopens access.

**Retirement.** Not applicable; the pool continues.

**Post-release cleanup.** `templates/friend_landing.html` — 3989 lines, 211KB, embedded at `frontend.go:21` and read by no Go code — is deleted along with its embed entry and the assertion in `provider_xiaomi_test.go:482`.
