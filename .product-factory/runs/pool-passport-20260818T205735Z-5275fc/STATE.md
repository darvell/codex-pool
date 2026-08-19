---
run_id: pool-passport-20260818T205735Z-5275fc
status: BLOCKED
stage: CONTRACT_REOPENED
contract_dir: docs/products/pool-passport
contract_shape: DOSSIER
contract_sha256: 507e992b974f62bf97e3853b370aad8ab88cc232521048a2591974bf021bd59a
base_commit: b42cbc91afaf9534d1f9ba217273d657235d7a26
research_commit: 82d3104
approver: Darvell
approved_at: 2026-08-18T20:57:35Z
current_slice: NONE
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
- Contract SHA-256: `507e992b974f62bf97e3853b370aad8ab88cc232521048a2591974bf021bd59a`
- Base commit: `b42cbc91afaf9534d1f9ba217273d657235d7a26`
- Research commit: `82d3104`
- Approver: Darvell
- Approval time: 2026-08-18T20:57:35Z

## Stage status

| Stage | Status | Evidence |
|---|---|---|
| Preflight and contract audit | Pending | |
| Production spine | Pending | |
| Capability completion | Pending | |
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

## Slice status

Populate this table from the approved delivery contract during preflight.

| Slice | Status | Focused proof | Notes |
|---|---|---|---|

## Release-gate status

Populate this table from the approved release gates during preflight.

| Gate | Merge or release effect | Status | Evidence or blocker |
|---|---|---|---|

## Material deviations

- Implementation preflight on 2026-08-18 falsified the frozen dependency claim: `go-webauthn v0.17.4` requires Go 1.25 and x/crypto v0.52.0, while the approved envelope and DuckDB driver use Go 1.24. The contract is reopened to pin v0.15.0, the newest verified Go 1.24-compatible release.

## Open findings and blockers

- Contract hash is intentionally invalid until Darvell reapproves the compatibility-only revision and a new run is initialized.

## Exact next action

Obtain explicit reapproval for WebAuthn v0.15.0, mark the contract approved, and initialize a replacement factory run.
