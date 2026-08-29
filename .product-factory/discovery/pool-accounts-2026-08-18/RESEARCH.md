# Research — pool-passport

Date: 2026-08-18. Commit: 82d3104.

## Repository evidence

- Auth and identity map: `config.go`, `router.go`, `pool_users.go`, `admin_pool_users.go`, `frontend.go`, `main.go`, `handlers.go`, `utils.go`, `brute_force.go`.
- Usage and analytics map: `usage.go`, `usage_tracking.go`, `storage.go`, `analytics_store.go`, `pricing.go`, `signal_analytics.go`, `frontend.go`.
- Interface map: `web/src/App.tsx`, `api.ts`, `types.ts`, `insights.ts`, `styles.css`, `components/dither-kit/*`, `templates/friend_landing.html`, `frontend.go`.
- Production data observed directly at `143.198.61.181` on 2026-08-18: 50 pool users, none disabled; 25 synthetic `pool.local` emails; `proxy.db` 627MB; `analytics.db` 57MB.

## External contracts

- `github.com/go-webauthn/webauthn`: latest release resolved as v0.17.4, published 2026-05-22. It is the community successor to Duo Labs, server-side only, v0-series, and requires deliberate upgrade review. Cross-origin ceremonies are rejected by default; Pool Passport does not enable them.
- Browser half: `@simplewebauthn/browser` is the established browser companion for serializing the WebAuthn API ceremonies.
- `golang.org/x/crypto/argon2`: v0.48.0 already exists in the current module graph and module cache, so password hashing does not add an unverified dependency name.

## Discriminating architecture review

The first contract used a credential epoch added to every signed envelope. Direct parser review falsified it:

- Gemini API keys are split and require `len(parts) == 3` (`pool_users.go:498-503`).
- Claude pool tokens decode and require `len(parts) == 3` (`pool_users.go:625-629`).
- Therefore adding a fourth field breaks both the current parser and any old binary used for rollback.

Replacement: every existing access credential already carries a signed issue time:

- Codex JWT: `iat` claim.
- Gemini OAuth: `iat` in signed JSON.
- Gemini API key: timestamp segment.
- Claude token: timestamp field.

A per-principal `CredentialsValidAfter` cutoff gives individual revocation with no envelope change. Migration uses a zero cutoff, so all existing credentials remain valid. Revocation advances the cutoff and rotates the download token. The existing unsigned `poolrt_<userID>_<random>` refresh token is separately replaced with a signed, timestamped format; legacy refresh is accepted only while the cutoff remains zero.

Direct route review found that `/api/codex/usage`, `/backend-api/wham/usage`, Claude profile/usage, `/oauth/token`, and `/config/*` return before `proxyRequest`; the contract now requires them to share the principal authorizer instead of assuming the proxy hot path covers them.

## Analytics architecture revision

The aggregate-bucket proposal was rejected after user review. It would have made each new question — user × hour, user × model × day, cost × provider — a new durable schema and write path.

Replacement:

- Bolt remains authoritative for principals, credentials, sessions, guest passes, and a durable ordered `analytics_outbox`.
- A completed usage observation is written once to that outbox in the existing synchronous usage transaction.
- A single writer drains batches into an immutable DuckDB `usage_events` table with a unique `event_id`, commits, then deletes the corresponding outbox sequence range. Crash replay is idempotent.
- Dashboard series are DuckDB SQL grouped by time, principal, provider, model, and cost. No permanent hourly/model rollup family.
- The existing SQLite `analytics.db` is migrated and retired after reconciliation; its lossy queue is not preserved.
- The official Go client supports `database/sql` and the Appender API. DuckDB supports concurrent readers and append writers within one process. The Appender's default 204,800-row commit interval is too large for this service, so explicit transactions bound each batch.
- The official Go driver uses native prebuilt DuckDB libraries. Linux releases are built in a pinned Linux Docker stage rather than cross-compiled with `CGO_ENABLED=0` from macOS.

## Product review findings incorporated

- Removed the QR code: the selected delivery is copy-and-send, and QR did not improve the normal iMessage/Discord handoff.
- Removed a duplicate JSON export: the ordinary API is already JSON; CSV is the human export.
- First-boot operator bootstrap no longer prints a password to logs. It is an `ADMIN_TOKEN`-authenticated setup page accepting the chosen password over TLS, then disappearing.
- Rollback is explicitly pre-mutation only. After a revocation or a new principal, the old binary cannot enforce the cutoff or see the new identity and must not be restored.
- Retention is release-blocking because the live Bolt database is already 627MB and hourly buckets are never pruned.
