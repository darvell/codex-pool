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

<p align="center">
  <img src="screenshots/analytics-dashboard.png" alt="Pool Analytics" width="700">
</p>

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

## Screenshots

### Setup Dashboard

<p align="center">
  <img src="screenshots/local-mode.png" alt="Local Mode" width="700">
</p>

### Friends Mode
Share your pool with others using a friend code.

<p align="center">
  <img src="screenshots/friends-mode-login.png" alt="Friends Mode" width="500">
</p>

---

## Quick Start

### 1. Add your accounts

```bash
mkdir -p pool/codex pool/claude pool/gemini pool/antigravity

# Codex accounts
cp ~/.codex/auth.json pool/codex/work.json
cp ~/backup/.codex/auth.json pool/codex/personal.json

# Claude accounts
cp ~/.claude/credentials.json pool/claude/main.json

# Gemini accounts
cp ~/.gemini/oauth_creds.json pool/gemini/main.json
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

## Friends Mode

Pool accounts with friends. Set a code, share the URL:

```toml
# config.toml
friend_code = "secret-code"
friend_name = "YourName"
```

They log in, get setup instructions, start using the pool. You see everyone's usage in analytics.

---

## Configuration

```toml
listen_addr = "127.0.0.1:8989"
pool_dir = "pool"

# Friends mode
friend_code = "your-secret"
friend_name = "YourName"

# Multi-user tracking
[pool_users]
admin_password = "admin"
jwt_secret = "32-char-secret-for-jwt-tokens!!"
```

Environment variable `PROXY_MAX_INMEM_BODY_BYTES` controls how large a request body can be before the proxy streams it directly (no retries). Default is 16777216 (16 MiB).

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

Antigravity model names come from Google's live `fetchAvailableModels` response. Use `antigravity/<model-id>` to force this provider. `/api/pool/models`, `/v1/models`, `/v1beta/models`, Pi, Cute Code, and the Codex catalog consume the same registry. Temporary quota exhaustion changes `available_now` without removing a supported model from the catalog.

---

## Disclaimer

This pools credentials you own. Using multiple accounts or sharing access may violate terms of service. If something goes sideways, that's on you.

---

## License

MIT
