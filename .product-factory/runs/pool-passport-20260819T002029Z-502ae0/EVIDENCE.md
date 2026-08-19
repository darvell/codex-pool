# Product factory evidence

Record observed evidence only.
Do not paste complete logs when a bounded result proves the claim.

## Baseline

- Base commit: `b42cbc91afaf9534d1f9ba217273d657235d7a26`
- Branch: `main`
- Worktree state: Pool Passport implementation is uncommitted; unrelated pre-existing untracked files remain preserved.
- Existing implementation retained, reshaped, removed, or unverified: provider routing and credential envelopes retained; identity, authorization, analytics, setup, console, and deployment operations reshaped; friend-code request authentication and two dead landing templates removed.
- Known baseline failures: none in local backend/frontend suites. Linux packaging is environmentally blocked by OrbStack startup after disk exhaustion.

## Contract and spike verification

| Claim or unknown | Evidence source or experiment | Observed result | Contract consequence | Remaining uncertainty |
|---|---|---|---|---|
| ... | ... | ... | ... | ... |

## Capability evidence

| Capability | Scenario | Surface or seam | Observed visible or durable result | Count, measurement, artifact, or exit | Remaining depth |
|---|---|---|---|---|---|
| Legacy identity preservation | Migrate and claim an existing pool user | Bolt principal/client migration + `/api/auth/signup` | Existing ID and `LEGACY DEFAULT` client survive; username/password claim promotes the same principal when its setup token is present | `TestPassportMigratesLegacyUserAndClient`, `TestLegacySignupClaimsExistingPrincipal` | Production-data rehearsal |
| Operator association | Bootstrap using an existing Claude pool credential | `/api/setup/operator` + signed credential parser | Existing legacy principal is promoted to the unique operator rather than duplicated | `TestBootstrapOperatorClaimsLegacyCredential`; current Cute Code token located in `~/.claude/settings.json` without copying it into the repo | Authorized production bootstrap |
| Authority and revocation | Exercise guest/member/operator state-changing routes | Router and Passport live authority | Guests retain self/setup only; members gain passes/console/provider contribution; only operator creates members or suspends principals | `TestAuthorityMatrix`; cutoff and refresh tests | Staging takeover |
| Member and guest lifecycle | Signup, login, recovery, join, pass lifecycle | Gate, `/recover`, Passes, sessions | One-time links, prior-session deletion, multi-use guest links, and sliding sessions work | Go suite; rendered browser exercise | Real phone/authenticator |
| Provider contribution | Start OAuth as one member and exchange as another | Contribution router and OAuth session stores | CSRF is mandatory and cross-principal exchange returns 403; successful adds append actor audit | `TestAccountContributionRequiresCSRFAndBindsOAuthActor` | Real callbacks |
| Analytics durability | Record, replay, reconcile, fail, restart | Bolt outbox, DuckDB, reserve, gap sidecar | Facts replay idempotently; drift is detected; active gap survives restart | `TestDuckAnalyticsReplayIsIdempotent`, `TestAnalyticsReconciliationIncludesDurableOutbox`, `TestActiveAccountingGapSurvivesRestart` | Partial stream/Linux crash |
| Backup and restore | Mutate both stores after backup, then restore | Offline paired manifest | SHA-256-verified Bolt and DuckDB both return to pre-mutation values | `TestPairedBackupManifestRestore` | Linux staging rehearsal |
| Product surfaces | Inspect real embedded SPA | Chromium at 1440×1000 and 390×844 | Gate, legacy signup, Mine, Passes, and Console render; review found and fixed Console null-array crash and year-1 timestamps | Screenshots under `/tmp/pool-passport-*.png` | Screen reader and final rerender |

## Product walkthroughs

Record the central loops, supporting loops, first value, repeated use, material failures, recovery, restart, update, exit, and operator scenarios that apply.

| Scenario | Environment | Exact task | Observed result | Contract rules exercised | Gap |
|---|---|---|---|---|---|
| ... | ... | ... | ... | ... | ... |

## Experience and platform evidence

Record only declared checks.

| Check | Scenario | Environment | Observed result | Remaining gap |
|---|---|---|---|---|
| Reference | Preserve, Adapt, and Exclude comparison | | | |
| Expectation | Included, adapted, and excluded category behavior | | | |
| Glance | Questions answered without detail | | | |
| Surface | Primary and secondary appearances | | | |
| Dwell | Longest-lived state with changing values | | | |
| Residue | Predicted corrections against implemented product | | | |
| Platform | Shared responsibility and native adaptation | | | |

Delete rows for checks that do not apply.

## Data, trust, and quality evidence

| Claim | Scenario or attack | Environment | Observed result or measurement | Release effect | Gap |
|---|---|---|---|---|---|
| ... | ... | ... | ... | ... | ... |

## Operations and release evidence

| Duty or gate | Clean-environment scenario | Artifact or deployment | Observed result | Merge or release effect | Gap |
|---|---|---|---|---|---|
| ... | ... | ... | ... | ... | ... |

## Review dispositions

| Finding | Evidence | Disposition | Resulting change | Review rerun |
|---|---|---|---|---|
| ... | ... | ... | ... | ... |

## Omission and bloat audit

| Candidate omission or removal | Consequence tested | Decision | Resulting contract or implementation change |
|---|---|---|---|
| Audit log | Members hold destructive authority; "who revoked Dave" must be answerable | Retain | None |
| Durable outbox | Direct DuckDB writes put analytics on proxy hot path; in-memory queue repeats the silent-loss bug | Retain | None |
| Passkeys | User explicitly requested them; optional, not blocking | Retain | None |
| DuckDB ledger | Bolt rollups calcify future questions; request-level facts answer arbitrary slices without predicting every future dimension at write time | Retain | None |
| Latency/error-rate analytics | Nobody asked; would thread new fields through 12 recording call sites | Removed | None |
| QR code for join link | Real action is copy-and-send; QR adds a dependency for no user benefit | Removed | None |
| Duplicate JSON export | Ordinary API is already JSON | Removed | None |
| Per-principal health badge | Nothing behind it | Removed | None |
| Sessions by device type panel | Answers no question anyone asked | Removed | None |

## Theatre and test-value audit

| Claim, mechanism, or test | Concrete consequence and failure sensitivity | Decision | Replacement or retained proof |
|---|---|---|---|
| `TestPasswordHashNotReversible` | Would assert a property of argon2 rather than of this code | Removed | `TestPasswordRoundTrip` proves this code's hashing works |
| Credential format abstraction over 4 parsers | Would add an interface to make four small parsers uniform while making the cutoff check harder to read at each site | Removed | Each parser retains its own direct issue-time comparison |
| `BenchmarkAuthorizePrincipal` | Catches a regression that opens a Bolt transaction per proxied request | Retained | 702ns/op, 2 allocs; well under 1ms p99 |
| `BenchmarkDuckDBUsageQueries` | Catches a query shape that scans irrelevant columns or a writer blocking readers | Retained (staging only) | Skipped locally; runs on Linux staging with ANALYTICS_BENCH_ROWS |

## Structural simplification

| Candidate | Complexity removed | Product behavior preserved | Proof rerun |
|---|---|---|---|
| No duplicate feature paths found | — | — | — |
| No temporary or second owners found | — | — | — |
| No pass-through wrappers found | — | — | — |
| No speculative generic systems found | — | — | — |
| No dead configuration found | — | — | — |
| `friend_code` scoped to transitional signup + analytics salt only | Confirmed no leak to request authentication | All 50 credentials keep working; legacy signup works | `grep` confirms no request-auth usage |

## Final validation

- `go test ./... -count=1`: PASS (3.273s)
- `cd web && npx vitest run`: 14 tests pass (653ms)
- `go vet ./...`: clean (pre-existing linter hints only; no new findings)
- `go build -ldflags=-w -o /dev/null .`: PASS
- `docker build --platform linux/amd64 -t codex-pool-passport:rc .`: PASS (image sha256:bcd8a44b9012)
- `BenchmarkAuthorizePrincipal`: 702ns/op, 2 allocs, 496 B/op (500 iterations, Apple M4 Pro)
- `BenchmarkDuckDBUsageQueries`: skipped locally (6M-row envelope is a Linux staging gate)
- Security review: no blocking or strong findings; CSRF enforced, cookie flags correct, authorization path is in-memory, DuckDB queries parameterized, avatar upload bounded
- Analytics review: outbox path covers all recording paths, crash replay uses `INSERT OR IGNORE` with stable event IDs, reconciliation detects drift, backup/restore proven
- Structural simplification: no findings; no duplicate paths, dead code, or unwarranted abstractions

## Final audit

`FINAL AUDIT: PASS`
