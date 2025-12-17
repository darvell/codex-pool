# Codex Pool Proxy

Local-only reverse proxy that load-balances traffic across multiple accounts for:
- **Codex CLI** (OpenAI/ChatGPT)
- **Gemini CLI** (Google)

The proxy:
- Loads credentials from `./pool/` directory
- Picks an account per request (sticky by conversation when present)
- Automatically refreshes tokens before they expire
- Retries failed requests on different accounts

## Codex Setup

### 1. Add Codex auth files

Copy your Codex `auth.json` files into `./pool/`:

```bash
mkdir -p pool
cp ~/.codex/auth.json pool/account1.json
cp /path/to/other/auth.json pool/account2.json
```

### 2. Run the proxy

```bash
go run .
# or
go build -o codex-pool && ./codex-pool
```

### 3. Configure Codex CLI

Add to `~/.codex/config.toml`:

```toml
model_provider = "codex-pool"
chatgpt_base_url = "http://127.0.0.1:8989/backend-api"

[model_providers.codex-pool]
name = "OpenAI via codex-pool proxy"
base_url = "http://127.0.0.1:8989/v1"
wire_api = "responses"
requires_openai_auth = true
```

## Gemini Setup

### 1. Add Gemini auth files

Copy your Gemini OAuth credentials into `./pool/` with `gemini_` prefix:

```bash
cp ~/.gemini/oauth_creds.json pool/gemini_account1.json
```

The file format is:
```json
{
  "access_token": "ya29...",
  "refresh_token": "1//...",
  "expiry_date": 1234567890000
}
```

### 2. Run the proxy

```bash
go run .
```

### 3. Configure Gemini CLI

Set the `CODE_ASSIST_ENDPOINT` environment variable:

```bash
export CODE_ASSIST_ENDPOINT=http://127.0.0.1:8989
gemini
```

Or add to your shell profile:
```bash
echo 'export CODE_ASSIST_ENDPOINT=http://127.0.0.1:8989' >> ~/.bashrc
```

## Pool Users (Multi-User Mode)

Enable multiple users to share the pool without giving them real account credentials.

### Setup

Set these environment variables:

```bash
export POOL_ADMIN_PASSWORD=your-secret-password
export POOL_JWT_SECRET=32-character-secret-for-signing-tokens
```

### Create Users

1. Visit `http://localhost:8989/admin/pool-users` (enter password when prompted)
2. Click "Create New User"
3. Enter email and plan type
4. Share the generated curl commands with the user:

```bash
# For Codex CLI
curl http://PROXY:8989/config/codex/TOKEN > ~/.codex/auth.json

# For Gemini CLI
curl http://PROXY:8989/config/gemini/TOKEN > ~/.gemini/oauth_creds.json
```

Users still need to configure their CLI to point to the proxy (see setup sections above).

## Endpoints

- `GET /healthz` — health status, account counts, recent errors
- `GET /metrics` — Prometheus-style counters
- `GET /admin/accounts` — debug view of all account states (shows type: codex/gemini)
- `POST /admin/reload` — reload accounts from disk
- `GET /admin/pool-users` — manage pool users (password protected)
- `GET /config/codex/<token>` — download Codex auth.json for pool user
- `GET /config/gemini/<token>` — download Gemini oauth_creds.json for pool user

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_LISTEN_ADDR` | `127.0.0.1:8989` | Listen address |
| `POOL_DIR` | `./pool` | Directory containing credential files |
| `PROXY_DB_PATH` | `./data/proxy.db` | BoltDB path for usage tracking |
| `PROXY_MAX_ATTEMPTS` | `3` | Retry attempts across accounts |
| `PROXY_DISABLE_REFRESH` | `0` | Set to `1` to disable token refresh |
| `PROXY_DEBUG` | `0` | Enable debug logging |
| `POOL_ADMIN_PASSWORD` | (none) | Password for pool user admin UI |
| `POOL_JWT_SECRET` | (none) | Secret for signing pool user tokens |
| `POOL_USERS_PATH` | `./data/pool_users.json` | Path to pool users database |

## File Naming Convention

- `*.json` (without `gemini_` prefix) → Codex accounts
- `gemini_*.json` → Gemini accounts
