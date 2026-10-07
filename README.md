<p align="center">
  <img src="logo.png" alt="codex-pool" width="400">
</p>

<h1 align="center">codex-pool</h1>

<p align="center">
  <strong>Pool your accounts. Share with friends. Never swap credentials again.</strong>
</p>

---

A reverse proxy that distributes coding-agent sessions across pooled provider accounts. Got three Codex accounts? Five Claude logins? The proxy spreads your usage across all of them automatically - no manual switching, no juggling auth files. Google subscription accounts use the Antigravity sign-in flow; Gemini remains the API-key provider.

The setup dashboard configures **Codex CLI**, **Claude Code**, **Gemini CLI**, **Grok Build**, **Pi**, and **Cute Code**. Grok Build runs through the proxy without its own login and can select the other pool models; Pi merges pool providers into its existing `models.json`.

For browser, mobile, or CLI speech-to-speech agents, see [Realtime voice agents through codex-pool](docs/realtime-voice-agent.md). It uses a pooled ephemeral secret followed by a direct WebRTC session.

---

## Why

You hit rate limits. You have multiple accounts. Swapping credentials is annoying.

Or maybe you want to pool accounts with friends - everyone throws their accounts into the pot, everyone benefits from the combined capacity.

**codex-pool** handles it:
- Distributes sessions across all your accounts for each service
- Routes to whichever account has capacity
- Pins conversations to the same account (ensures standard cached token performance)
- Auto-refreshes tokens before they expire
- Proxies WebSocket upgrades (including Codex Responses WS and realtime `/ws` flows)
- Tracks usage so you can see who's burning through quota

---

## Quick Start

### 1. Add your accounts

```bash
mkdir -p pool/codex pool/claude pool/gemini pool/antigravity pool/opencode_go pool/mistral

# Codex accounts
cp ~/.codex/auth.json pool/codex/work.json
cp ~/backup/.codex/auth.json pool/codex/personal.json

# Claude accounts
cp ~/.claude/credentials.json pool/claude/main.json

# Gemini accounts
cp ~/.gemini/oauth_creds.json pool/gemini/main.json

# OpenCode Go subscription (API key from https://opencode.ai/auth)
cat > pool/opencode_go/main.json <<'EOF'
{"api_key": "sk-..."}
EOF
chmod 600 pool/opencode_go/main.json

# Mistral paid API key (from https://console.mistral.ai)
cat > pool/mistral/main.json <<'EOF'
{"api_key": "..."}
EOF
chmod 600 pool/mistral/main.json
```

Structure:
```
pool/
├── codex/
│   ├── work.json
│   └── personal.json
├── claude/
│   └── main.json
└── gemini/
    └── main.json
```

### 2. Run it

```bash
go build && ./codex-pool
```

### 3. Point your CLI

**Codex** - `~/.codex/config.toml`:
```toml
model_provider = "codex-pool"
chatgpt_base_url = "http://127.0.0.1:8989/backend-api"

[model_providers.codex-pool]
name = "OpenAI via codex-pool proxy"
base_url = "http://127.0.0.1:8989/v1"
wire_api = "responses"
requires_openai_auth = true
```

**Claude Code**:
```bash
export ANTHROPIC_BASE_URL="http://127.0.0.1:8989"
export ANTHROPIC_API_KEY="pool"
```

**Gemini CLI**:
```bash
export CODE_ASSIST_ENDPOINT="http://127.0.0.1:8989"
```

**Google Antigravity account**: open the dashboard, choose "Contribute an account", then press "Google Antigravity". The popup completes the callback automatically. Pasting the callback URL remains available when popups are blocked.

The sign-in flow uses Antigravity's shipped Google OAuth client and its fixed `http://localhost:51121/oauth-callback` redirect, matching CLIProxyAPI and VibeProxy. When the pool runs on the same machine as the browser, the popup completes on its own. For a remote pool, paste the failed localhost callback URL into the contribution dialog; the state and PKCE verifier are still checked before exchange.

`ANTIGRAVITY_OAUTH_CLIENT_ID`, `ANTIGRAVITY_OAUTH_CLIENT_SECRET`, and `ANTIGRAVITY_OAUTH_REDIRECT_URI` remain available for tests or a separately registered Google OAuth client. `ANTIGRAVITY_CLIENT_VERSION` overrides the Antigravity client version used in upstream requests. `UPSTREAM_ANTIGRAVITY_BASE`, `UPSTREAM_ANTIGRAVITY_DAILY_BASE`, and `UPSTREAM_ANTIGRAVITY_ONBOARD_BASE` override the production, generation, and onboarding Cloud Code Assist hosts.

---

## Pool Passport

Members sign in with a username or email and may add a passkey. Members and operators can create revocable guest passes whose magic links open the pool directly. Each principal can keep separately labelled client credentials and inspect token usage over time; operators can manage principals, provider accounts, passes, audit events, and analytics health from the Signal Room. Pulse ranks the ten heaviest pool users over the last seven days by billable tokens and links into Members; the roster shows display names with roles, distinguishes unclaimed migrated credentials, and filters account categories without removing them from pool-wide totals. Hashed origin analytics remain available in Insights for IP-based demand analysis.

Existing pool-user IDs and credentials migrate into guest principals. During the migration window, the former `friend_code` lets an existing holder choose a username and password; when the browser still has its old setup token, Passport claims the same principal ID and preserves its history. The code never authorizes ordinary API or provider requests. Clear it after migration to disable further account claims while the independently persisted analytics salt keeps historical origin hashes stable.

Pool status economics now compare full tracked API-equivalent history with a
sparse subscription-rate/payment ledger and show a separate last-30-days
run-rate view. Backfilled rates are estimates, not invoices; see
[Pool status economics](docs/pool-economics.md) for coverage, corrections, and
pricing limitations.

---

## Configuration

```toml
listen_addr = "127.0.0.1:8989"
pool_dir = "pool"
db_path = "./data/proxy.db"
public_url = "https://pool.example.com"

# Migration-only salt seed. Remove only after Passport has persisted analytics_salt.
friend_code = "former-secret"

[pool_users]
jwt_secret = "32-char-secret-for-existing-tokens"
storage_path = "./data/pool_users.json"
```

Set `POOL_AUTH_ENCRYPTION_KEY` to a stable 32-byte secret (hex or base64) before starting Passport. `ADMIN_TOKEN` remains the break-glass operator credential.

Environment variable `PROXY_MAX_INMEM_BODY_BYTES` controls how large a request body can be before the proxy streams it directly (no retries). Default is 16777216 (16 MiB).

### Model capability discovery

Authenticated clients can query `GET /api/pool/models` for the pool's model catalog, current account availability, and provider capabilities. The response includes a `schema_version`; clients should ignore fields they do not understand and treat an unknown schema version as unsupported.

Models with provider-hosted web search advertise both `capabilities.web_search` and a declarative `native_tools.web_search` route:

```json
{
  "id": "grok-4.5",
  "provider": "grok",
  "capabilities": { "web_search": true },
  "native_tools": {
    "web_search": {
      "protocol": "openai-responses",
      "endpoint": "/v1/responses",
      "tool_type": "web_search"
    }
  },
  "available_now": true
}
```

Native-tool endpoints are same-origin relative paths. The `native_tools` map key is also the wire tool name for protocols that require one; `tool_type` is the provider-specific type value. Capability means the model and protocol support the tool, while `available_now` separately reports whether an account can currently be routed. The catalog never includes account credentials.

---

## Credential Formats

**Codex** - `pool/codex/*.json`
```json
{"tokens": {"access_token": "...", "refresh_token": "...", "account_id": "acct_..."}}
```

**Claude** - `pool/claude/*.json`
```json
{"claudeAiOauth": {"accessToken": "...", "refreshToken": "...", "expiresAt": 1234567890000}}
```

**Gemini** - `pool/gemini/*.json`
```json
{"access_token": "ya29...", "refresh_token": "1//...", "expiry_date": 1234567890000}
```

**Antigravity** - `pool/antigravity/*.json`
```json
{"type":"antigravity","access_token":"ya29...","refresh_token":"1//...","email":"person@example.com","project_id":"project-id","expiry_date":1234567890000}
```

**OpenCode Go** - `pool/opencode_go/*.json`
```json
{"api_key": "sk-..."}
```

OpenCode Go models are namespaced as `opencode-go/<model-id>` (e.g. `opencode-go/longcat-2.0`), matching OpenCode's own config convention. Bare IDs also route to Go unless another provider already claims them (`kimi-k3` is Go-only; bare `mimo-v2.5-pro` stays on Xiaomi, bare `grok-4.6` stays on Grok). Go quota (rolling/weekly/monthly from `GET /zen/go/v1/usage`) is polled every 15 minutes; the weekly window drives routing score. Configure a different endpoint with `UPSTREAM_OPENCODE_GO_BASE`.

**Mistral** - `pool/mistral/*.json`
```json
{"api_key": "..."}
```

Mistral is an ordinary paid API-key account, like Kimi/MiniMax/Z.ai/Xiaomi. Each key's chat-capable catalog is discovered from `GET /v1/models` and refreshed on the same 15-minute poll as other dynamic providers; models that don't advertise `capabilities.completion_chat` (embeddings, moderation, OCR, etc.) are filtered out. Public model IDs are always namespaced `mistral/<upstream-id>` (e.g. `mistral/mistral-large-latest`) — bare IDs are never claimed, since Mistral's catalog can overlap other pools. A small set of well-known chat models ships pre-pinned so Pi/Cute Code configs are useful before the first discovery poll completes; routing itself still requires a key that has actually advertised the model.

Pi sees Mistral as `pool-mistral`, an `openai-completions` provider at `/v1`. This provider key avoids overriding Pi's built-in `mistral` catalog. Pi 0.87.1's historically named `mistral-conversations` adapter also uses Chat Completions, but it is not selected by the generated pool configuration: its model-specific controls recognize bare upstream IDs, whereas the pool requires namespaced IDs, and its native structured-content stream differs from the pool's generic OpenAI stream.

Mistral reasoning models return structured `thinking` content blocks. The pool exposes their text as `reasoning_content` for generic OpenAI clients, then restores assistant `reasoning_content`, `reasoning`, and `reasoning_text` strings to native thinking blocks when clients replay history. Existing text, structured content, tool calls, and tool-result IDs are retained. Forwarding a generic assistant reasoning field unchanged causes Mistral to reject the post-tool continuation with HTTP 422 (`extra_forbidden`), even though the initial request and tool call succeed.

Cute Code's own `openai` protocol speaks the Responses API, which this Mistral backend does not implement, so Mistral is exported to Cute Code as an `anthropic` Messages adapter instead. The pool translates `/v1/messages` requests to Chat Completions and back. This shared Messages translator currently omits historical Anthropic thinking blocks; the OpenAI reasoning-replay fix does not change that separate limitation.

Reasoning effort is read from whichever carrier the client sent (`reasoning_effort`, `reasoning.effort`, `thinking.effort`/`budget_tokens`) and collapsed to the two-value enum Mistral's API accepts: `low`/`minimal` becomes `none`, and `medium`/`high`/`max` all become `high`, matching Mistral's own Vibe CLI. Usage is parsed from `usage.prompt_tokens`/`completion_tokens`/`prompt_tokens_details.cached_tokens` on buffered and streamed responses, including a usage-only terminal chunk. Rate-limit headers reflect short per-minute windows and are not monthly quota. 429s cool the requesting key; 402s apply a heavy penalty and rotate to another key without being marked permanently dead unless the body indicates a deactivated workspace. Configure another endpoint with `UPSTREAM_MISTRAL_BASE` (default `https://api.mistral.ai`).

For acceptance, use an isolated pool and client configuration with only the test key and harmless read fixture. Test **reasoning → tool call → tool result → final answer as one complete sequence** at medium thinking; separate text, reasoning, and tool tests do not establish continuation compatibility. The October 7, 2026 fix passed this sequence with Pi 0.87.1 on `mistral/mistral-large-4`, `mistral/mistral-medium-latest`, `mistral/mistral-small-latest`, and `mistral/magistral-medium-latest`, and with Cute Code's Messages path on Medium Latest. Those are small-request canaries, not proof of maximum context, output limits, or independent-workspace failover. Repeat the canaries after deploying the fix before enabling models in downstream clients.


Antigravity model names come from Google's live `fetchAvailableModels` response. Use `antigravity/<model-id>` to force this provider. `/api/pool/models`, `/v1/models`, `/v1beta/models`, Pi, Cute Code, and the Codex catalog consume the same registry. Temporary quota exhaustion changes `available_now` without removing a supported model from the catalog.

### Antigravity routing and failover

Each account attempt tries the daily generation host first. The production host is used as a fallback for daily transport errors, 404s, 429s, and 5xx responses; other daily responses remain authoritative for that attempt. If the host pair ends in a transport failure, authentication failure after one token refresh, a 429, or a 5xx response, the request rotates to another eligible account. Non-retryable request errors such as 400 stop immediately, and streaming responses are never replayed after bytes have been committed downstream.

Routing reserves an account before releasing the scheduler lock, favors usable quota headroom, and spreads equal candidates. Conversation affinity is recorded only after an upstream 2xx response. Native function-call replay is scoped to the pool user/origin while remaining independent of the selected account, so ordinary account failover can preserve a turn without sharing signed state between users.

Live 429s normally cool only the requested model. They become family-wide only when Google's error identifies a known shared quota bucket; authoritative quota polling can independently mark the Gemini or Claude/GPT family exhausted. The proxy honors both `Retry-After` forms and Google retry metadata, using the later precise deadline. If otherwise-usable accounts are all temporarily cooling or quota-exhausted, the response is 429 with the earliest pool-wide `Retry-After`; 503 means there is no currently usable supply for a non-quota reason. Public diagnostics contain aggregate exclusion reasons, not account identities or credential data.

Model inventory, quota snapshots, verification health, and active cooldowns are persisted in each Antigravity account JSON. `model_rate_limits`, `model_backoff_levels`, and `account_cooldown_until` are proxy-managed compatibility fields. Account reload stages the full model registry before publishing it with the account set, and late quota polls from an older pool generation are discarded rather than overwriting refreshed credentials.

---

## Disclaimer

This pools credentials you own. Using multiple accounts or sharing access may violate terms of service. If something goes sideways, that's on you.

---

## License

MIT
