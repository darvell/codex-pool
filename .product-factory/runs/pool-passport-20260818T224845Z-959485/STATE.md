---
run_id: pool-passport-20260818T224845Z-959485
status: IN_PROGRESS
stage: CAPABILITY_COMPLETION
contract_dir: docs/products/pool-passport
contract_shape: DOSSIER
contract_sha256: 9e314dec3f29038345a56d484917317fd5ae9b07660ec0e4258a362e3fc702e4
base_commit: b42cbc91afaf9534d1f9ba217273d657235d7a26
research_commit: 82d3104
approver: Darvell
approved_at: 2026-08-18T22:48:45Z
current_slice: S3/S4 — Analytics durability and operator product
product_review_status: PENDING
system_review_status: PENDING
trust_review_status: PENDING
release_review_status: PENDING
omission_status: PENDING
bloat_status: PENDING
theatre_status: PENDING
simplification_status: PENDING
validation_status: PENDING
final_audit_status: PENDING
---

# Product factory state

## Approved contract

- Product: Pool Passport
- Contract directory: `docs/products/pool-passport`
- Shape: `DOSSIER`
- Contract SHA-256: `9e314dec3f29038345a56d484917317fd5ae9b07660ec0e4258a362e3fc702e4`
- Base commit: `b42cbc91afaf9534d1f9ba217273d657235d7a26`
- Research commit: `82d3104`
- Approver: Darvell
- Approval time: 2026-08-18T22:48:45Z

## Stage status

| Stage | Status | Evidence |
|---|---|---|
| Preflight and contract audit | Complete | Contract revalidated and frozen at `9e314dec...`; branch `main` at `b42cbc9`; baseline suites green; existing unrelated untracked files recorded and preserved. |
| Production spine | Complete | Real Bolt principal/session/client stores, legacy migration, durable Bolt analytics outbox, DuckDB writer/query path, login/join/client/self-usage endpoints, and native Linux build configuration are present. |
| Capability completion | In progress | S1 revocation and all-route authorization are next; later slices remain incomplete. |
| Integrated product and design convergence | Pending | |
| Trust, operations, and release hardening | Pending | |
| Independent implementation review | Pending | |
| Omission, bloat, theatre, and test-value audit | Pending | |
| Structural simplification | Pending | |
| Clean-environment acceptance and packaging | Pending | |
| Release brief and final contract audit | Pending | |

## Capability status

Populate this table from the approved capability ledger during preflight.

| Capability | Class | Status | Focused evidence | Remaining depth |
|---|---|---|---|---|
| Principals, migration, operator bootstrap | Core | Partial | `TestPassportMigratesLegacyUserAndClient`; bootstrap endpoint compiles | Migration marker/idempotency, unique operator invariant, production-shaped fixture |
| Guest passes and magic join | Core | Partial | Store and HTTP create/redeem path; required note enforced | Edit/expiry/revoke/restore/delete, origin count, join UI, audit coverage |
| Member password sessions | Core/Trust | Partial | Argon2 round trip; opaque Bolt sessions; CSRF cookies | Rate limiting, restart/revocation tests, sign-out, renewal, fresh-auth state |
| Optional WebAuthn | Trust | Not started | Dependency pinned | Registration, assertion, challenge persistence, recovery/removal |
| Nickname and uploaded avatar | Polish | Partial | Backend normalization/storage/profile endpoints compile | Image fixtures, frontend controls, analytics/roster rendering |
| Labelled client credentials | Core | Partial | Create/list and 20-active limit | Rename, expiry, rotate, revoke, setup delivery, last-seen updates |
| Per-request authorization and cutoffs | Trust | Partial | Composite principal/client authorization on proxy path | Signed issue-time enforcement in all envelopes and CLI-local routes; revocation transaction |
| DuckDB usage ledger and outbox | Core/Operate | Partial | `TestDuckAnalyticsOutboxDrain` | Crash replay, import, reconciliation, pricing/completeness provenance, gap state |
| Self and operator analytics | Core | Partial | Self hourly query and endpoint | Provider/model/cost charts, CSV, operator queries/ranking, freshness/completeness |
| Member provider-account operation | Operate | Partial | Member sessions accepted by legacy auth gate | Bind OAuth/action actor, audit every mutation, remove friend header dependency |
| Operator console and audit | Operate | Not started | Audit primitive exists | Roster, detail, lifecycle actions, durable before/after entries |
| Friend-code removal and salt preservation | Support | Not started | Compatibility path remains | Freeze independent salt, remove config/routes/UI/template, prove stable hashes |
| Backup, restore, diagnostics, packaging | Operate | Partial | Dockerfile and native dependency configuration compile locally | Paired manifest, reserve/gap behavior, metrics, clean Linux container proof |

## Slice status

Populate this table from the approved delivery contract during preflight.

| Slice | Status | Focused proof | Notes |
|---|---|---|---|
| S1 — Principals and revocation | In progress | Legacy migration test passes | Cutoffs, signed refresh tokens, CLI-local route coverage, lifecycle endpoints remain |
| S2 — Sessions, sign-in, and join | Partial | Password, encrypted pass/client, and suite tests pass | UI, rate limiting, session lifecycle, pass lifecycle, full audit remain |
| S3 — Durable analytical ledger | Partial | Outbox drain test passes | Crash/reconcile/import/gap/storage/performance proof remain |
| S4 — Analytical product, console, passkeys, and removal | Partial | Self hourly endpoint and frontend build pass | Most product surface, passkeys, operator analytics, friend-code removal remain |

## Release-gate status

Populate this table from the approved release gates during preflight.

| Gate | Merge or release effect | Status | Evidence or blocker |
|---|---|---|---|
| Suite green | Blocks merge | Green at current spine | `go test ./... -count=1`; web production build; 14 Vitest tests |
| Credential replay | Blocks release | Pending | Requires staging with the 50 production credentials |
| Migration and rollback rehearsal | Blocks release | Pending | Requires production-data copy and forward/rollback rehearsal |
| Authority matrix | Blocks release | Pending | Endpoint matrix and implementation incomplete |
| Performance | Blocks release | Pending | Authorization and 6M-row Linux benchmarks absent |
| Analytics durability | Blocks release | Pending | Crash, reconciliation, import, and partial-stream proofs absent |
| Storage and backup | Blocks release | Pending | Reserve/gap and paired restore absent |
| Packaging | Blocks release | Pending | Docker build/start not yet run |
| Rendered and accessibility review | Blocks release | Pending | New surfaces incomplete |
| Secret hygiene | Blocks release | Pending | Log-capture proof and journal scan absent |

## Material deviations

None.

## Open findings and blockers

None.

## Exact next action

Finish the operator console UI over the new ranked-principal/audit endpoints, then complete analytics crash replay/reconciliation/import/gap handling before removing the friend-code compatibility path.
