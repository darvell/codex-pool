# Quota Waste Insights

Quota Waste Insights measures **expired unused subscription quota**, not failed-request
or billable token waste. It records a bounded observation of each configured account
from the provider-owned usage snapshot every five minutes. The sampler makes no
upstream calls and continues when request-derived quota intelligence is disabled.

The operator-only endpoint is `GET /api/pool/quota-waste?days=30` (1–90 days). IDs
are one-way redactions; credentials, response bodies, and provider health error text
are never persisted or returned. Missing values remain missing, while an explicitly
reported zero is retained as zero. Idle, disabled, dead, and opaque accounts are
included so the report does not silently select only successful accounts.

## Semantics and support

Scheduled-reset primary and secondary windows retain provider reset timestamps and
are shown as nested constraints on the same consumption. Sliding, opaque, unmetered,
and display-only spend limits are not converted into invented token or dollar
entitlements. A closed-window unused percentage is only a bound after fresh observations with
source timestamps, continuity, and a confirmed reset; startup/restart gaps and
partial windows remain unknown. The current post-reset window shows used and
remaining state, never as expired waste. Token equivalents and dollar burn are therefore intentionally
absent unless a defensible provider mapping is added later.

Current snapshots support Codex-style primary/secondary windows and any provider
which exposes those fields through the existing usage machinery. Provider-specific
rolling/weekly/monthly windows are represented as opaque unless their existing
snapshot provides an explicit semantic identity. This is conservative by design.

## Candidates

A candidate removes one paid-seat identity, not one login. Repeated logins are grouped
using the existing subscription identity and manual subscription links; history is
never erased when an account is removed. Each candidate is an independent scenario,
not a shopping list. It requires compatible provider/plan evidence, fresh observations, and a 20% reserve
after redistribution. Health/review burden is reported and used as a tie-break only
after the load safety gate; it is never treated as safety evidence. The result is
labelled `modelled_safe`, not a peak-tested replay: review thresholds are not
predicted, and removing a problem account does not cure load-induced risk. Unknown
identity, capability, source-IP, or history is insufficient evidence rather than safe.

Known subscription rates and historical paid spend belong to economics; this report
never multiplies quota percentage by a bill or presents an unknown price as zero.

## Lifecycle, retention, backup, and migration

Raw observations are append-only and versioned in the existing AnalyticsStore SQLite
file. Rows are retained for 180 days and reads are bounded to at most 90 days. The
schema is created idempotently at startup, so existing analytics backups migrate by
opening the database. A restart creates an explicit coverage gap; it does not backfill
fabricated resets or restamp old samples. If the analytics store is unavailable, the
endpoint returns HTTP 503 rather than an empty success response.
