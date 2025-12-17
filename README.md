# Codex Pool Proxy

Local-only reverse proxy that load-balances Codex/ChatGPT traffic across multiple ChatGPT accounts.

The proxy:
- Loads a directory of Codex `auth.json` files (one per account)
- Picks an account per request (sticky by `conversation_id` when present)
- **Always overwrites** upstream auth (`Authorization: Bearer …` and `ChatGPT-Account-ID`) based on the selected account
- Automatically refreshes tokens before they expire
- Retries failed requests on different accounts

## Setup

### 1. Add auth.json files to the pool

Copy your `auth.json` files into `./pool/`:

```bash
mkdir -p pool
cp ~/.codex/auth.json pool/account1.json
# Add more accounts as needed
cp /path/to/other/auth.json pool/account2.json
```

Each file should have the standard Codex auth format with `tokens.access_token`, `tokens.refresh_token`, and `tokens.id_token`.

### 2. Run the proxy

```bash
go run .
# or build it
go build -o codex-pool && ./codex-pool
```

The proxy listens on `127.0.0.1:8989` by default.

### 3. Configure Codex CLI

Add this to your `~/.codex/config.toml`:

```toml
model_provider = "codex-pool"
chatgpt_base_url = "http://127.0.0.1:8989/backend-api"

[model_providers.codex-pool]
name = "OpenAI via codex-pool proxy"
base_url = "http://127.0.0.1:8989/v1"
wire_api = "responses"
requires_openai_auth = true
```

That's it. Codex will now route all requests through the proxy.

## Endpoints

- `GET /healthz` — health status, account count, recent errors
- `GET /metrics` — Prometheus-style counters
- `GET /admin/accounts` — debug view of all account states
- `POST /admin/reload` — reload accounts from disk without restarting

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_LISTEN_ADDR` | `127.0.0.1:8989` | Listen address |
| `POOL_DIR` | `./pool` | Directory containing auth.json files |
| `PROXY_DB_PATH` | `./data/proxy.db` | BoltDB path for usage tracking |
| `PROXY_MAX_ATTEMPTS` | `3` | Retry attempts across accounts |
| `PROXY_USAGE_REFRESH_SECONDS` | `300` | Usage polling interval |
| `PROXY_DISABLE_REFRESH` | `0` | Set to `1` to disable token refresh |
| `PROXY_DEBUG` | `0` | Enable debug logging |
