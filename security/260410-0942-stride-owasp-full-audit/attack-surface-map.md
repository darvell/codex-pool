# Attack Surface Map -- codex-pool

## Entry Points

```
Attack Surface:
  +-- Unauthenticated
  |   +-- GET /                              -> Landing page (harmless)
  |   +-- GET /healthz                       -> Health check (info disclosure: uptime)
  |   +-- GET /status                        -> Status page (may leak account info)
  |   +-- GET /friend/:code                  -> Landing with pre-filled code
  |   +-- GET /admin/claude/callback         -> OAuth redirect (NO AUTH)
  |   +-- POST /oauth/token                  -> Fake OAuth token endpoint
  |   +-- GET /og-image.png, /hero.png       -> Static images
  |
  +-- Token-in-URL Auth (pool user token)
  |   +-- GET /setup/codex/:token            -> Setup script (leaks proxy URL)
  |   +-- GET /setup/gemini/:token           -> Setup script
  |   +-- GET /setup/claude/:token           -> Setup script
  |   +-- GET /config/codex/:token           -> Full credential download
  |   +-- GET /config/gemini/:token          -> Full credential download
  |   +-- GET /config/claude/:token          -> Full credential download
  |   +-- GET /config/pi/:token              -> Full credential download
  |
  +-- Friend Code Auth
  |   +-- POST /api/friend/claim             -> Create pool user account
  |   +-- GET /api/pool/stats                -> Pool statistics
  |   +-- GET /api/pool/users                -> User list
  |   +-- GET /api/pool/origins              -> Origin tracking data
  |   +-- GET /api/pool/daily-breakdown      -> Usage breakdown
  |   +-- GET /api/pool/hourly               -> Hourly usage
  |   +-- GET /api/pool/users/:id/daily      -> Per-user usage
  |   +-- GET /api/pool/users/:id/hourly     -> Per-user usage
  |   +-- POST /admin/claude/add             -> Start Claude OAuth flow
  |   +-- POST /admin/claude/exchange         -> Exchange OAuth code
  |   +-- POST /admin/claude/:id/refresh      -> Refresh Claude tokens
  |   +-- * /admin/codex/*                   -> Codex account management
  |   +-- * /admin/kimi/*                    -> Kimi account management
  |   +-- * /admin/minimax/*                 -> MiniMax account management
  |   +-- * /admin/zai/*                     -> Z.ai account management
  |
  +-- Admin Token Auth
  |   +-- POST /admin/reload                 -> Hot-reload accounts
  |   +-- GET /admin/accounts                -> All account details + tokens
  |   +-- GET /admin/origins                 -> Origin details
  |   +-- GET /admin/tokens                  -> Token capacity analysis
  |   +-- POST /admin/clear-rate-limits      -> Clear rate limits
  |   +-- POST /admin/purge-anonymous        -> Purge anonymous usage
  |   +-- POST /admin/accounts/:id/resurrect -> Resurrect dead account
  |   +-- POST /admin/accounts/:id/refresh   -> Force token refresh
  |   +-- GET /metrics                       -> Prometheus metrics
  |   +-- * /admin/pool-users/*              -> Pool user CRUD
  |
  +-- Pool User JWT / Bearer Auth (proxied requests)
  |   +-- * /v1/*                            -> Proxied to upstream
  |   +-- * /responses/*                     -> Proxied to upstream
  |   +-- * /ws/*                            -> WebSocket proxy
  |   +-- * /backend-api/*                   -> Proxied to upstream
  |   +-- * (default)                        -> Proxied to upstream
```

## Data Flows

```
Data Flows:
  +-- Client request -> body inspection (model extraction) -> provider selection
  |   -> account selection (tiered scoring) -> auth header rewrite -> upstream API
  |   -> response stream (SSE/WS) -> usage parsing -> client
  |
  +-- Friend code claim -> pool user creation -> JWT generation -> credential download
  |
  +-- OAuth flow -> redirect to Anthropic -> callback (unauthenticated) -> code exchange
  |   -> token storage in pool/*.json -> account available for proxying
  |
  +-- Token refresh -> refresh proxy (optional) -> upstream auth server -> token update
  |   -> persist to JSON file
  |
  +-- Usage tracking -> BoltDB write (per-account, per-user, per-origin)
  |   -> SQLite analytics (daily rollup) -> cost estimation
```

## Abuse Paths

```
Abuse Paths:
  +-- Friend code brute force -> unlimited pool user creation -> credential theft
  +-- Leaked config URL (/config/*/:token) -> full account credentials
  +-- OAuth callback manipulation -> potential session fixation (see findings)
  +-- Admin token in query string -> referer leak -> admin access
  +-- IP-based brute force ban -> shared IP lockout (DoS against legitimate users)
  +-- No per-user proxy rate limiting -> single user exhausts all accounts
  +-- Debug mode logging -> admin token appears in server logs
  +-- Claude trace dir -> request/response bodies captured to disk
```
