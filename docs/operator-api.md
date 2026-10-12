# Operator API

The Operator API gives automation access to the same operational facts used by the Signal Room without turning a model credential into an administrator credential. It is intended for diagnostics, inventory, accounting investigation, and explicitly authorized maintenance.

The deployed binary is authoritative. Given only a pool base URL and an operator token, begin at:

```bash
export POOL_URL=https://pool.example.com
export POOL_OPERATOR_TOKEN='poolop_…'
curl -fsS "$POOL_URL/api/operator/v1" \
  -H "Authorization: Bearer $POOL_OPERATOR_TOKEN"
```

The discovery response links `whoami`, the bundled OpenAPI 3.1 document, canonical models, the credential-free Pi export, and request accounting. `GET /api/operator/v1/openapi.json` describes all supported legacy dashboard/admin paths as well as the versioned endpoints; its `info.version` is the contract version bundled with that running binary. The checked-in [reference table](operator-api-reference.md) is rendered with `python3 scripts/render_operator_api_reference.py`, and tests enforce registry/spec/reference route parity.

## Credentials and permissions

Operator keys are opaque 256-bit bearer credentials. Passport stores only a SHA-256 digest. The full `poolop_<id>_<secret>` value is returned once when it is issued or replaced.

An operator creates and revokes keys under **Operator API** in the Signal Room. Key creation and replacement require a browser operator session authenticated by password or passkey during the last 15 minutes plus the normal CSRF token. Sessions obtained from setup, migration, join, or recovery links do not satisfy this step-up check. Defaults are 90 days for read-only keys and 30 days for read + write; a custom expiry up to 366 days may be selected.

- `operator.read` reads registered operational and accounting routes.
- `operator.write` includes read and may use only registered maintenance routes.
- New and unknown routes are denied by default. GET is not inherently safe.
- Operator keys cannot issue operator keys, change roles, recover accounts, reveal existing credentials, download personal configurations, or run inference.
- Model/user keys cannot use the Operator API.
- Suspending, deleting, expiring, or demoting a key's owner immediately removes its authority.

`ADMIN_TOKEN` and `X-Admin-Token` remain a separate break-glass mechanism. Do not use an operator key as `X-Admin-Token`.

## Dashboard and graph data

A read key can retrieve every current Signal Room backing series:

| View | API |
|---|---|
| Pool pulse and account quota/economics | `GET /api/pool/stats` |
| Signal Room graph bundle | `GET /api/pool/signal?weeks=6` |
| Member ranking | `GET /api/console/principals?hours=168` |
| Selected member history | `GET /api/console/principals/{id}/usage?hours=168` |
| Analytics lag and accounting gaps | `GET /api/console/analytics-health` |
| Global and legacy per-user time series | `/api/pool/hourly`, `/api/pool/users/{id}/daily`, `/api/pool/users/{id}/hourly` |
| Hashed origin demand | `GET /api/pool/origins` |
| Codex upstream daily surfaces | `GET /api/pool/daily-breakdown` |
| Models and current routing readiness | `GET /api/pool/catalog` |
| Sanitized provider inventory | `GET /admin/accounts` |

`signal` defaults to six weeks and caps `weeks` at 12. Its burn series covers 14 days and its model-mix series 42 days. `/api/pool/hourly` and legacy per-user hourly data cap at 168 hours; daily data caps at 90 days. Console analytics accept up to 366 days. These are the same handlers and aggregations used by the portal, not parallel reimplementations.

Provider inventory returned to an operator key uses public account IDs and omits raw upstream account identities, health-error bodies, and verification URLs. Guest-pass reads omit usable links. Audit reads omit free-form detail.

## Diagnose a cost calculation

Start with the graph series, narrow to a principal/model/provider, then page through request-grain facts:

```bash
curl -fsS "$POOL_URL/api/operator/v1/accounting/requests?limit=100&from=2026-10-01T00:00:00Z&to=2026-10-08T00:00:00Z&provider=codex" \
  -H "Authorization: Bearer $POOL_OPERATOR_TOKEN"
```

Follow `next_cursor` until it is empty. The endpoint caps pages at 200 rows, ranges at 366 days, and queries at three seconds. Records include recorded input, cache-read, cache-creation, output, reasoning and billable tokens; reported and normalized model IDs; the calculated API-equivalent cost; and the stored pricing/normalization versions. They never include prompts, responses, raw upstream payloads, upstream request IDs, raw account IDs, or credentials.

`pricing_provenance: "version_only"` means only the calculation-code version was retained. Historical rates and their source were not retained, so even a versioned row is not sufficient for exact rate reconstruction. `unavailable` includes legacy rows without even that version. Current manifest rates are hints about the running deployment, never substituted as historical evidence.

## Models and Pi

`GET /api/operator/v1/models` is the rich canonical manifest. It defaults to `catalog=full`. `supporting_accounts` describes configured support, while `available_now` is transient routing readiness; a paused, dead, or rate-limited supporting account does not remove its model. Request `catalog=configured` to keep models with at least one supporting account.

`GET /api/operator/v1/config/pi` defaults to `catalog=configured` and removes empty provider entries, so its portable configuration advertises only providers this deployment can support. Request `catalog=full` explicitly for the complete known catalog. Neither mode filters on temporary availability. The export is a real Pi `models.json` shape generated from the same catalog logic and never embeds a pool credential. Every provider uses Pi's environment-variable reference `CODEX_POOL_MODEL_API_KEY` (the variable name, not a secret). Supply a separate **model** credential when installing it:

```bash
export CODEX_POOL_MODEL_API_KEY='your-model-key-not-your-operator-key'
curl -fsS "$POOL_URL/api/operator/v1/config/pi" \
  -H "Authorization: Bearer $POOL_OPERATOR_TOKEN" > models.json
```

The pool must have `public_url` configured; request `Host` is deliberately not trusted for portable exports. Pi supports Responses and Messages. The current generator gives each provider entry one API protocol, so mixed-endpoint OpenCode Go models not assigned to that entry are omitted; the manifest reports the exact Pi provider key and API protocol for every included model.

Personal setup downloads such as `/config/pi/{downloadToken}` and `/config/cute-code/{downloadToken}` remain credential-bearing user workflows. They are deliberately outside operator-token authority.

## Writes and auditing

A write key may reload accounts, clear cooldowns, update economics, enable/disable/refresh/resurrect accounts using the public IDs from inventory, synchronize Antigravity models, issue or manage passes/invites, and change principal **status**. Automated member links are onboarding-only. Recovery links, password replacement, operator-role changes, and operator-key management remain browser-only.

Every token-authenticated write attempt is audited with the owner and token ID. Successful domain mutations also retain their ordinary audit event. Routine reads update `last_used_at` at most once per minute instead of flooding the audit log.

## Contract maintenance and verification

After changing a supported route or payload, update the bundled OpenAPI document and run:

```bash
python3 scripts/render_operator_api_reference.py
# Development-only tools; they are not required by the running pool.
python3 -m pip install jsonschema openapi-spec-validator
openapi-spec-validator docs/openapi/operator-v1.openapi.json
(cd web && npm ci && npm test && npm run build)
go test ./...
go vet ./...
```

Build the frontend before Go tests in a fresh checkout: the binary embeds `web/dist`. The Go response-conformance test invokes Python's `jsonschema` against actual handler responses; it skips explicitly if that development dependency is missing. Release validation must install it and run `go test -v -run TestOperatorOpenAPIConformsToRealResponses` to confirm the test passes rather than skips. The generated reference and route/capability parity are checked without that dependency.
