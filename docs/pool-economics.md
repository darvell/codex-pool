# Pool status economics

The status page compares **estimated API-equivalent value**, not revenue or money
saved, to subscription cost. The difference is **value above subscription
spend**, not profit: hosting, API-key bills, taxes, credits, and fees are not
included. Historical values use the request's stored price estimate; old
request-level records may have been repriced before this change. There is no
complete as-of-date price catalog for earlier usage, so the page does not claim
historically accurate published API prices.

Both headline and cumulative chart come from the same server-side calculation
(`economics.go`), including value from removed accounts. Historical spend is
30-day billing cycles anchored at account admission, not calendar months. On
first observation an account's **current plan price is backfilled as an
estimate** from its recorded `added_at` (or first usage if admission metadata
is unavailable). Later plan-price changes add a rate event and affect only
subsequent cycles. The sparse `subscription_rates` table persists after account
removal; absence from a pool snapshot closes its last rate. A removed account
that was never observed by this code has no rate history: its API value is
shown as uncovered, not silently treated as free. Zero/unknown-priced plans (including API-key accounts with separate bills) also
make the comparison incomplete unless an operator records the cost explicitly. List prices are **not proof of payment**.

The recent row uses API-equivalent value from the last 30 days and a prorated
allocation of the subscription cycle costs overlapping that period. It is a
run-rate comparison, not a cash-flow statement. The current monthly rate is
shown separately. A plan switch within a cycle takes effect at the next cycle
boundary; an operator can replace any cycle's estimated charge with an actual
invoice amount.

## Correcting rates and payments

`POST /admin/economics` uses the existing operator/admin authorization. Send
JSON with `kind` (`rate` or `payment`), `account_id` (the **real**, not hashed,
account ID), `effective_at` (UTC RFC3339 timestamp), `amount_usd`, and optional
`note`. For `rate`, give the date at which the new monthly rate took effect;
it splits an existing interval. A manual rate is not overwritten by automatic
plan detection; post another rate event when that price changes. For `payment`,
`effective_at` must be the precise cycle-start timestamp (account admission
plus an integer multiple of 30 days); the amount replaces that cycle's
estimate. Reposting the same payment corrects it. The schema has no background
polling: OAuth claims can indicate a tier, but not a charged amount, discount,
or invoice date. Do not send credentials or invoices in notes.

For example, an operator with an admin token can use:

```sh
curl -X POST http://127.0.0.1:8989/admin/economics \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"kind":"rate","account_id":"ACCOUNT_ID","effective_at":"2026-09-01T00:00:00Z","amount_usd":100,"note":"plan changed"}'
```

Keep `data/analytics.db` with its existing backup: both cost aggregates and
subscription events are needed to reconstruct the status page. Prices before
first observation, removal before first observation, and unreported payments
cannot be inferred automatically. Historical estimates can be refined as
Darvell supplies the account and billing history. The legacy per-account ROI
and provider-lane figures still use current-account estimates and should not
be read as the pool-wide audited ledger.
