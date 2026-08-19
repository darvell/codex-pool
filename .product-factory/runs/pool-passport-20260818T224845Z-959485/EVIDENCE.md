# Product factory evidence

Record observed evidence only.
Do not paste complete logs when a bounded result proves the claim.

## Baseline

- Base commit: `b42cbc91afaf9534d1f9ba217273d657235d7a26`
- Branch: `main`
- Worktree state: Passport/DuckDB implementation is uncommitted; pre-existing unrelated untracked files `.tmp_claude_log_summary.py`, `2026-04-10-100144-local-command-caveatcaveat-the-messages-below.txt`, `codex-pool-test`, and two TypeScript build-info files are preserved.
- Existing implementation retained, reshaped, removed, or unverified: retained provider routing and credential envelope formats; reshaped identity, authorization, analytics storage, Docker build, and web gate; friend-code routes and legacy analytics remain pending removal; Linux packaging, production migration, browser experience, WebAuthn, and operational recovery remain unverified.
- Known baseline failures: none in local suites. `go test ./... -count=1` passed on August 18, 2026. `npm --prefix web run build` and `npm --prefix web test -- --run` passed; 2 files and 14 tests passed.

## Contract and spike verification

| Claim or unknown | Evidence source or experiment | Observed result | Contract consequence | Remaining uncertainty |
|---|---|---|---|---|
| ... | ... | ... | ... | ... |

## Capability evidence

| Capability | Scenario | Surface or seam | Observed visible or durable result | Count, measurement, artifact, or exit | Remaining depth |
|---|---|---|---|---|---|
| Credential revocation | Suspend and restore one guest after minting all four provider envelopes | Passport store and shared request credential parser | Principal and client cutoffs invalidate Codex JWT, Gemini OAuth, Gemini API-key, Claude, signed refresh, legacy refresh, browser sessions, and old setup token while fresh credentials pass | `TestCredentialCutoffInvalidatesEveryEnvelope`; `TestSignedAndLegacyRefreshCutoffs` repeated 20 times | Staging replay of 50 production credentials and endpoint authority matrix |
| Guest onboarding and pass lifecycle | Create, edit, copy, rotate, revoke, restore | `/join`, `/api/passes`, Passes UI | Fragment is removed before POST; account switching is explicit; pass note/expiry/link and client secrets are durable and audited | Go suite and web build pass | Real phone/laptop walkthrough and browser accessibility review |
| Profile and client self-service | Update nickname/avatar; mint/rotate/revoke labelled client | Mine UI and Passport Bolt buckets | Images are decoded, center-cropped, resized to 128×128 PNG; client cutoff and setup token rotate independently | Go suite and web build pass | Image fixture tests, setup one-liner walkthrough, last-seen update |
| Optional passkeys | Password step-up registration and discoverable login | go-webauthn v0.17.4 + SimpleWebAuthn Browser v13.3.0 | Challenges are one-time Bolt records; credential material is AEAD-encrypted; user verification and discoverable credentials are required; successful assertion creates the normal server session | Backend compiles; production dependency audit reports zero production vulnerabilities | Real authenticator ceremony, removal/list UI, full integration proof |
| Operator analytics backend | Rank principals, inspect one, read audit | DuckDB ranking query and member-scoped console APIs | 7-day ranking joins immutable facts to live profile metadata; detail stays principal scoped; audit reads newest first | Go suite compiles and passes | Console UI, freshness/fault state, CSV/model mix, operator actions |

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
| ... | ... | ... | ... |

## Theatre and test-value audit

| Claim, mechanism, or test | Concrete consequence and failure sensitivity | Decision | Replacement or retained proof |
|---|---|---|---|
| ... | ... | ... | ... |

## Structural simplification

| Candidate | Complexity removed | Product behavior preserved | Proof rerun |
|---|---|---|---|
| ... | ... | ... | ... |

## Final validation

Record exact commands, tasks, devices, platforms, viewports, workloads, artifacts, counts, measurements, exits, environment limits, and unproved claims.

## Final audit

`FINAL AUDIT: PENDING`
