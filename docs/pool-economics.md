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
30-day billing cycles anchored at the subscription's first recorded start, not
calendar months. Spend is counted per **subscription**, not per pool account:
re-logging into the same paid seat creates a new pool account, and all of
those accounts share one bill. Codex accounts are grouped automatically by
workspace and user ID from the login token; other providers can be grouped
with a `link` edit. On
first observation an account's **current plan price is backfilled as an
estimate** from its recorded `added_at` (or first usage if admission metadata
is unavailable). Later plan-price changes add a rate event and affect only
subsequent cycles. The sparse `subscription_rates` table persists after account
removal; absence from a pool snapshot closes its last rate. A cycle already billed
before removal still counts as paid for the full cycle; it is not refunded by
removing the account. A removed account
that was never observed by this code has no rate history until an operator
records it with a `history` edit: its API value is
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
JSON with `kind` (`rate`, `payment`, `history`, or `link`), `account_id` (the
**real**, not hashed, account ID), and the fields that kind needs. `note` is
optional for every kind.

- `rate`: `effective_at` (UTC RFC3339) is when the new monthly `amount_usd`
  took effect; it splits an existing interval. A manual rate is not
  overwritten by automatic plan detection; post another rate event when that
  price changes.
- `payment`: `effective_at` must be the precise cycle start of the account's
  subscription (its first recorded start plus an integer multiple of 30 days);
  `amount_usd` replaces that cycle's estimate. Reposting the same payment
  corrects it.
- `history`: records a finished interval, `effective_at` to `end_at`, during
  which the account used a paid subscription at `amount_usd` per month. Use it
  for accounts that left the pool before the ledger observed them. It requires
  `subscription_id`, a positive amount, and a past `end_at`, and it may not
  overlap another interval of the same account. Reposting the same account and
  `effective_at` corrects it.
- `link`: sets `subscription_id` on every interval of the account, so logins
  the pool cannot identify itself share one bill.

The schema has no background
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
