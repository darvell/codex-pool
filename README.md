# codex-pool

**Pool multiple AI accounts. Distribute the load. Never hit rate limits again.**

A reverse proxy that combines your Codex, Claude, and Gemini accounts into a single endpoint. The proxy automatically routes requests to whichever account has the most available capacity, so you can keep coding while your rate limits recover.

<p align="center">
  <img src="screenshots/analytics-dashboard.png" alt="Pool Analytics" width="700">
</p>

---

## The Problem

You're deep in a coding session. The AI is on fire, refactoring your entire codebase. Then:

```
Rate limit exceeded. Please wait 2 hours.
```

You have a Pro subscription. Maybe even Max. Doesn't matter. The limit doesn't care about your deadlines.

## The Solution

What if you had multiple accounts and the system automatically picked whichever one had capacity?

**That's codex-pool.**

Drop your credential files in a folder. Point your CLI at the proxy. Done. The proxy handles everything:
- Routes to the account with most available quota
- Keeps conversations pinned to the same account (no context loss)
- Refreshes OAuth tokens before they expire
- Retries failed requests on different accounts
- Tracks usage across all accounts

Works with **Codex CLI**, **Claude Code**, and **Gemini CLI**.

---

## Screenshots

### Setup Dashboard
One-liner setup for each CLI. Copy, paste, code.

<p align="center">
  <img src="screenshots/local-mode.png" alt="Local Mode" width="700">
</p>

### Friends Mode
Share your pool with others using a friend code. Optional, but fun.

<p align="center">
  <img src="screenshots/friends-mode-login.png" alt="Friends Mode" width="500">
</p>

---

## Quick Start

### 1. Add your accounts

```bash
mkdir -p pool

# Codex - copy your auth file
cp ~/.codex/auth.json pool/work.json
cp ~/another-account/.codex/auth.json pool/personal.json

# Claude - copy oauth or use API key
cp ~/.claude.ai/claude_session.json pool/claude_main.json

# Gemini - copy oauth creds
cp ~/.gemini/oauth_creds.json pool/gemini_main.json
```

File naming:
- `*.json` = Codex account
- `claude_*.json` = Claude account
- `gemini_*.json` = Gemini account

### 2. Run it

```bash
go build && ./codex-pool
```

Proxy starts at `http://127.0.0.1:8989`

### 3. Point your CLI

**Codex CLI** - add to `~/.codex/config.toml`:
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

---

## Friends Mode

Want to share your pool? Set a friend code:

```toml
# config.toml
friend_code = "secret-code-here"
friend_name = "YourName"
friend_tagline = "For the few who know, the pool awaits."
```

Friends visit your URL, enter the code, and get setup instructions. You can track everyone's usage in the analytics dashboard.

---

## Configuration

All options via `config.toml` or environment variables:

```toml
listen_addr = "127.0.0.1:8989"
pool_dir = "pool"
db_path = "./data/proxy.db"
debug = false

# Friends mode (optional)
friend_code = "your-secret"
friend_name = "YourName"

# Multi-user tracking (optional)
[pool_users]
admin_password = "admin"
jwt_secret = "32-char-secret-for-jwt-tokens!!"
```

| Env Variable | Default | Description |
|--------------|---------|-------------|
| `PROXY_LISTEN_ADDR` | `127.0.0.1:8989` | Listen address |
| `POOL_DIR` | `./pool` | Credentials directory |
| `FRIEND_CODE` | - | Enable friends mode |

---

## Credential Formats

**Codex** - `pool/*.json` (standard auth.json from `~/.codex/`)
```json
{"tokens": {"access_token": "...", "refresh_token": "...", "account_id": "acct_..."}}
```

**Claude** - `pool/claude_*.json`
```json
{"claudeAiOauth": {"accessToken": "...", "refreshToken": "...", "expiresAt": 1234567890000}}
```
Or API key: `{"api_key": "sk-ant-...", "plan_type": "max"}`

**Gemini** - `pool/gemini_*.json`
```json
{"access_token": "ya29...", "refresh_token": "1//...", "expiry_date": 1234567890000}
```

---

## How It Works

```
┌─────────────┐     ┌─────────────┐     ┌──────────────────────────────┐
│  Codex CLI  │     │             │     │  Account 1 (Pro)    [85%]   │
├─────────────┤────>│             │────>│  Account 2 (Max)    [20%]   │
│ Claude Code │     │ codex-pool  │     │  Account 3 (Plus)   [60%]   │
├─────────────┤────>│             │────>│  Account 4 (Team)   [45%]   │
│ Gemini CLI  │     │             │     │  ...                        │
└─────────────┘     └─────────────┘     └──────────────────────────────┘
                           │
                    Routes to account
                    with most capacity
```

1. Load credential files on startup
2. Probe each account for current usage/limits
3. Route each request to the account with most headroom
4. Pin conversations to same account (context continuity)
5. Auto-refresh OAuth tokens before expiry
6. Retry failures on different accounts

---

## Disclaimer

This tool pools credentials you already own. Using multiple accounts may violate terms of service. If you share your pool with others and something goes sideways, that's on you. The authors assume no responsibility for account suspensions, bans, or stern emails from legal departments.

Use responsibly. Or don't. Your call.

---

## License

MIT
