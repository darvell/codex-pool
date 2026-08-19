# Discovery notes — pool accounts, guest passes, observability

Run: pool-accounts-2026-08-18
Repo: /Users/pp/code/codex-pool @ 82d3104 (main)
Entry state: partial implementation. Treat repo as evidence, not definition.

## Request (verbatim intent)

1. Deprecate the friend-code system; move to real accounts.
2. Real accounts can mint **Guest Passes** for low-friction users. Guests still tracked.
3. Real pool members manage the pool (add accounts, operate). Guests get a magic link that "just takes them right in."
4. Real token usage over time (hours, etc.) per user; charts.
5. Legacy users attributed "per unique JWT token".
6. WebAuthn optional for login.
7. (added mid-run) Admin must be able to tag a guest pass with a note recording who it was handed to.

## What the recon changed about the problem statement

### The friend code is one global shared string, not a per-user credential
- `X-Friend-Code` header, plain `!=` compare against `cfg.friendCode` (`router.go:257-265`, non-constant-time at `:259`).
- Body-carried on the one public mint endpoint `POST /api/friend/claim` (`frontend.go:130-145`).
- **It is also the analytics hash salt** (`poolHashSalt`, `utils.go:58-64`) for every anonymous origin ID.
  Call sites: `main.go:1859,4605,4617,4803,4819`, `frontend.go:246,2226`.
  Consequence: removing/rotating it orphans all historical `origin_*` buckets. Migration required, or the salt must be decoupled from the code first.
- Fail-open: if `adminToken == "" && friendCode == ""`, `checkAdminOrFriendAuth` returns true (`router.go:239-242`). Local dev depends on this.

### Pool users already exist — this is largely a wiring + hardening job
- `PoolUser{ID,Token,Email,PlanType,CreatedAt,Disabled}` — `pool_users.go:17-25`.
- Persisted as a whole-file-rewrite JSON blob at `./data/pool_users.json` (`pool_users.go:67-77`). No transactions.
- No delete — `handlePoolUserDelete` only flips `Disabled` (`admin_pool_users.go:136-146`).
- Four credential envelopes, all HMAC-SHA256 from ONE secret `POOL_JWT_SECRET` (`pool_users.go:520-529`):
  | Format | Shape | Expiry |
  |---|---|---|
  | Codex JWT | HS256 `sub=pool\|<uid>` | **10 years** (`pool_users.go:260`) |
  | Gemini OAuth | `ya29.pool-<b64>_<b64>` | 1 year (`:369`) |
  | Gemini API key | `AIzaSy-pool-<uid>.<ts>.<sig16>` | **never checked** (`:493`) |
  | Claude | `sk-ant-oat01-pool-<b64>` | **never checked** (`:592`) |
- Two mint paths with different strength: admin `randomHex(16)/randomHex(32)` (`admin_pool_users.go:104-110`) vs friend self-claim `randomHex(8)/randomHex(16)` (`frontend.go:185-191`).
- Self-claim keys on email: same email returns the existing user (`frontend.go:181-183`). Email is unverified, defaults `guest@<host>` (`:163-177`). **Email is currently an unauthenticated account-takeover key.**

### "Legacy users per unique JWT" — the premise is already satisfied
Every persisted `UserID` IS a pool user ID. There is no anonymous/legacy usage bucket:
- unattributed provider-credential passthrough returns before any recording (`main.go:1832-1840`);
- no valid token → 401, nothing recorded (`main.go:1843-1846`);
- `storage.go:275` gates all user/daily/hourly writes on `UserID != ""`.
So legacy callers are existing `PoolUser` rows created via `/api/friend/claim`. They need naming/claiming, not a new identity axis.

### Hourly per-user token data already exists and is already persisted
- `bucketUserHourlyUsage` keyed `userID|YYYY-MM-DDTHH|accountType`, written every attributed request (`storage.go:341-368`).
- `UserHourlyUsage{Hour,AccountType,Input,Cached,Output,Reasoning,Billable,RequestCount}` (`storage.go:101-111`) — provider-generic, unlike the daily bucket.
- `GET /api/pool/users/:id/hourly` (≤168h) and `/daily` (≤90d) are routed and working (`router.go:507-522`, `frontend.go:2486-2551`).
- **The React app never calls them** (`web/src/api.ts` hits only `/stats`, `/signal`, `/catalog`). Every existing chart is driven by `signal.hourly` = `global_hourly_usage`.

## Real gaps for the observability half

Blocking:
- G1. No per-user series reaches the UI. Endpoint exists, client call does not.
- G2. Per-user analytics are gated by the *shared* friend code — any holder reads any user's full history. No endpoint authenticates a user's own pool token and returns that user's series. `/api/pool/whoami` reads pool tokens (`frontend.go:2229-2251`) but returns no usage.
- G3. `user_hourly_usage` / `global_hourly_usage` / `user_daily_usage` are **never pruned**. `prune()` touches only `usage_requests` and `origin_weekly_usage` (`storage.go:915-959`). Unbounded growth.

Data model:
- G4. No cost in any hourly bucket (`UserHourlyUsage` has no CostUSD).
- G5. No model dimension in per-user hourly or daily. Hourly keys accountType only; `daily_costs` has model but drops `user_id`.
- G6. Per-user cost destroyed at 30d: `runDailyRollup` groups without `user_id` (`analytics_store.go:531`) then deletes `request_costs` >30d (`:547-548`).
- G7. `UserDailyUsage` provider breakdown is a hardcoded 5-provider switch (`storage.go:320-331`). ZAI/Xiaomi/Grok/Adverserial land in totals but no column. Derive daily from hourly instead of extending the switch.
- G8. `CacheCreationTokens` is captured on `RequestUsage` and drives `calculateCost` (`pricing.go:290,297`) but is persisted **nowhere**. Cost is not reproducible from stored columns.
- G9. No latency/status/error dimension. `RequestUsage` (`pool.go:170-196`) has no duration field.

Fidelity:
- G10. SQLite analytics writes silently drop on queue-full (`analytics_store.go:165-171`); Bolt hourly is synchronous+lossless. **Bolt is the token source of truth**; SQLite undercounts cost under load.
- G11. All bucketing is UTC (`storage.go:303,341`). No timezone. Convert client-side; the stored UTC hour supports it.
- G12. Claude usage is stitched across `message_start`/`message_delta` by `claudeAccum` (`main.go:3040-3067`); aborted streams drop input tokens entirely. Systematic undercount.
- G13. `getUserHourlyUsage` (`storage.go:1337-1388`) and `getGlobalHourlyUsage` (`:1391`) both do a **O(n²) bubble sort** after a full/prefix scan. Global path runs on every `/api/pool/stats` and `/api/pool/signal`. With G3 (no pruning) this degrades forever.

## Frontend state

- **Live UI is the React "Signal Room"**: `web/dist` embedded (`frontend.go:24-25`), served at `/` and `/friend/*` when `friendCode != ""` (`frontend.go:46-57`).
- `templates/friend_landing.html` (3989 lines / 211KB) is embedded at `frontend.go:21` but **never read by any Go code**. Dead ballast. Only ref is `provider_xiaomi_test.go:482`.
- `App.tsx` = 1703 lines, single file, no router. Views: pulse | insights | usage | accounts | models | setup (`App.tsx:71`).
- Charts: vendored `dither-kit` (37 files, canvas, d3-scale/d3-shape only). Exports AreaChart, LineChart, BarChart, PieChart, RadarChart, Sparkline; stacked area/bar supported. No heatmap (hand-rolled CSS grid at `App.tsx:1070`), no scatter, no table primitives.
- `aggregateHourly` (`App.tsx:535-547`) already pivots `[{hour,account_type,...}]` → one row per hour, column per provider. Exactly the shape a per-user version needs.
- Client "session" is `localStorage.{friendCode,friendEmail,friendSession}` + `sessionStorage.operatorToken`. `friendSession` holds **plaintext long-lived provider credentials** (`types.ts:3-14`).
- Build hazard: `web/dist` is gitignored (`.gitignore:44`) yet required by `go:embed`. Dockerfile has no Node stage. `.air.toml` watches only `.go`.

## Design language (live, `web/src/styles.css:4-34`)

Dark amber-gold instrument console. `--void:#070706`, `--console:#0b0b09`, `--rule:#40351b`, `--gold:#d5a638`, `--gold-hot:#ffda63`, `--ink:#f3ecd6`, `--muted:#9c967f`, `--danger:#ff5b4d`, `--success:#57e67b`.
Type: IBM Plex Sans Condensed body, IBM Plex Mono for all data (tabular-nums, .06–.08em tracking, .57–.66rem), Cormorant Garamond display.
Layout: 48px sticky command rail; `grid-template-columns: 92px minmax(0,1fr)`; max-width 1780px; panels tile edge-to-edge on shared 1px hairlines, no radius, no shadows. Panel header = `[code | title | dither block]`, codes like `A.10`, `C.20`.
Effects: fixed fractal-noise overlay `opacity:.19 / soft-light`; CRT scanlines; halftone radial-gradient dot textures; active nav `inset 3px 0 0 --gold-hot`.
Accessibility is real: skip link, role=table/row on hand-rolled tables, aria-labels on charts, :focus-visible in gold-hot.
Copy voice is arch: "PRIVATE FREQUENCY", "SIGNAL INTERRUPTED //", "The charts are nosy."

## Absent primitives (must be built)

No cookies set anywhere in the server (only outbound Codex fingerprint replay, `codex_fingerprint.go:158-189`).
No session store, no login endpoint, no password hashing (no bcrypt/argon2/scrypt), no CSRF, no `crypto/subtle`.
No email/SMTP anywhere. No magic link, no invite mechanism.
No WebAuthn dependency.

Reusable: `randomHex` (`pool_users.go:132`, **ignores rand.Read error**), `hmacSign` (`:155`), `signJWT` (`:138`), `validatePoolUserJWT` (`:162`), `hashUserIP` (`:240`), `bruteForceTracker` (`brute_force.go:23-116`, 5 attempts / 30min / per-IP, **in-memory only**), `getClientIP` (`utils.go:32-56`), `respondJSON` (`utils.go:77`).

## Load-bearing constraints any replacement must respect

1. **CLI credential shapes are frozen.** Codex/Claude/Gemini/Grok CLIs must keep receiving `sk-ant-oat01-*`, `ya29.*`, `AIzaSy*`, and an OAuth-shaped `auth.json`. Deliberate, documented at `pool_users.go:350-353,364-366,410-412,562-565`. New auth must still emit these envelopes.
2. **Credentials are stateless and self-authenticating; there is no revocation list.** Only kill switch is `PoolUser.Disabled`, checked *only if* `h.poolUsers != nil` (`main.go:1758,1782,1800,1818`). A leaked Codex JWT is valid 10 years.
3. **One symmetric secret gates all four formats.** Rotating `POOL_JWT_SECRET` invalidates everything at once.
4. Header names are the API contract: `X-Admin-Token`, `X-Friend-Code`. Query-string secrets are rejected and test-locked (`friend_account_routes_test.go:10-28`).
5. `/config/*` and `/setup/*` are **URL-path bearer secrets with no auth check** (`router.go:696-700`). They land in Caddy access logs and browser history by construction.
6. `purgeAnonymousUsers` treats `PoolUserStore.List()` as the authoritative allowlist (`handlers.go:261-269`). Any new identity store MUST feed that set or admin purge deletes real users' history.
7. Deployment is a single Go binary + BoltDB + SQLite on one droplet (root@143.198.61.181, systemd `codex-pool`, Caddy TLS at codex.ppflix.net, port 14430). No k8s, no external DB, no message queue.

## Non-constant-time secret comparisons found (fix in scope)

`router.go:216` (admin token), `router.go:247`, `router.go:259` (friend code), `pool_users.go:513` (Gemini API key).
JWT and Claude paths correctly use `hmac.Equal`.
