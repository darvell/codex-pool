# Threat Model -- codex-pool

## Assets

| Asset | Location | Priority |
|-------|----------|----------|
| OAuth tokens (Codex, Claude, Gemini) | `pool/*.json` files, in-memory `Account` structs | Critical |
| Pool user JWT secret | `config.toml` / `POOL_JWT_SECRET` env | Critical |
| Admin token | `config.toml` / `ADMIN_TOKEN` env / systemd env | Critical |
| Friend code | `config.toml` / `FRIEND_CODE` env | High |
| Pool user tokens | `data/pool_users.json` | High |
| BoltDB usage store | `data/proxy.db` | Medium |
| SQLite analytics store | `data/analytics.db` | Medium |
| Upstream API credentials (refresh tokens) | In-memory + JSON files | Critical |
| User IP addresses | Hashed in BoltDB, raw in origin metadata | Medium |
| Request/response bodies | In-memory, optional Claude trace dir | High |

## Trust Boundaries

```
Trust Boundaries:
  +-- Internet <-> Caddy reverse proxy (TLS termination)
  +-- Caddy <-> codex-pool proxy (127.0.0.1:14430)
  +-- Client (Codex CLI / Claude Code) <-> Pool proxy (auth boundary)
  +-- Pool proxy <-> Upstream APIs (OpenAI, Anthropic, Google, Kimi, MiniMax, Z.ai)
  +-- Friend/public routes <-> Admin routes (privilege boundary)
  +-- Pool user auth <-> Account selection (authorization boundary)
  +-- OAuth callback <-> Authenticated admin routes (unauthenticated callback)
  +-- Config/setup download (token-based) <-> Admin management (admin-token-based)
```

## STRIDE Threat Matrix

| Threat | Asset / Boundary | Risk | Example |
|--------|-----------------|------|---------|
| **Spoofing** | Admin auth | High | Admin token in query param visible in logs/referer |
| **Spoofing** | Friend code auth | Medium | Friend code brute-forceable (single static string) |
| **Spoofing** | Pool user JWT | Medium | JWT signed with potentially weak secret ("bigfarts" in sample) |
| **Spoofing** | Client IP | Medium | X-Forwarded-For / CF-Connecting-IP spoofable without Caddy/CF validation |
| **Tampering** | Request body | Low | Request bodies proxied verbatim; model routing based on body inspection |
| **Tampering** | OAuth state | Medium | PKCE verifier passed as OAuth `state` param -- used for session lookup |
| **Repudiation** | API usage | Medium | No per-request audit log linking user to account used |
| **Repudiation** | Admin actions | High | Admin operations logged to stdout only, no persistent audit trail |
| **Info Disclosure** | Debug mode | High | Debug logging can print admin tokens, request details |
| **Info Disclosure** | Claude trace | High | Trace dir captures full request/response bodies with optional secrets |
| **Info Disclosure** | Error responses | Medium | Some error paths include internal details (refresh token errors) |
| **Info Disclosure** | Pool stats API | Medium | Accessible with friend code -- exposes account IDs, plan types, usage |
| **DoS** | No rate limiting on proxy | High | No per-user rate limiting on proxied requests; only upstream limits |
| **DoS** | Brute force tracker | Low | Per-IP only; shared proxy IPs could lock out legitimate users |
| **DoS** | WebSocket relay | Medium | No message size/count limits on WS relay |
| **EoP** | OAuth callback | Critical | `/admin/claude/callback` has NO authentication |
| **EoP** | Friend code -> admin | Medium | Friend auth grants access to account management (add accounts, see tokens) |
| **EoP** | Config download | High | Token in URL path; if leaked, grants full pool user credentials |
