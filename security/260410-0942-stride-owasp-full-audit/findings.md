# Findings -- codex-pool Security Audit

## [CRITICAL] Finding 1: Refresh Token Forgery Allows Account Impersonation

- **OWASP:** A07 -- Identification and Authentication Failures
- **STRIDE:** Spoofing
- **Location:** `handlers.go:347-386`
- **Confidence:** Confirmed

**Description:** The `/oauth/token` endpoint accepts refresh tokens of the format `poolrt_<user_id>_<random>` but only validates the user ID portion. The random suffix is never checked against a stored value. Any attacker who knows a valid pool user ID can forge a refresh token and receive full credentials (access token, new refresh token, ID token) for that user.

**Attack Scenario:**
1. Attacker obtains friend code (guessable or leaked)
2. Calls `GET /api/pool/users?code=<friend_code>` to enumerate user IDs
3. POSTs to `/oauth/token` with body `{"refresh_token": "poolrt_<victim_user_id>_anything"}`
4. Receives valid pool credentials for the victim user
5. Uses credentials to proxy requests as that user

**Code Evidence:**
```go
// handlers.go:347-354
func (h *proxyHandler) handlePoolUserRefresh(w http.ResponseWriter, refreshToken string) {
    parts := strings.Split(refreshToken, "_")
    if len(parts) < 3 {
        respondJSONError(w, http.StatusBadRequest, "invalid refresh token")
        return
    }
    userID := parts[1]  // Only extracts user ID, never validates the random part
    // ... proceeds to generate new credentials for this user
```

**Mitigation:**
```go
// Store the refresh token hash when generating it
func (h *proxyHandler) handlePoolUserRefresh(w http.ResponseWriter, refreshToken string) {
    user := h.poolUsers.GetByRefreshToken(refreshToken) // Look up by full token
    if user == nil {
        respondJSONError(w, http.StatusUnauthorized, "invalid refresh token")
        return
    }
    // ... continue with validated user
```

**References:** CWE-287 (Improper Authentication)

---

## [HIGH] Finding 2: Admin Token Exposed in Query Parameters and Debug Logs

- **OWASP:** A02 -- Cryptographic Failures / A05 -- Security Misconfiguration
- **STRIDE:** Information Disclosure
- **Location:** `router.go:26-28` (query param), `router.go:31-33` (debug log)
- **Confidence:** Confirmed

**Description:** Admin tokens are accepted via `?admin_token=` query parameters, which appear in browser history, HTTP referer headers, server logs, and CDN/proxy logs. Additionally, when debug mode is enabled, both the provided and configured admin tokens are logged in plaintext.

**Code Evidence:**
```go
// router.go:26-28 - query param acceptance
token := r.Header.Get("X-Admin-Token")
if token == "" {
    token = r.URL.Query().Get("admin_token")
}

// router.go:31-33 - debug logging of actual admin token
if h.cfg.debug.Load() {
    log.Printf("admin auth: provided=%q configured=%q", token, h.cfg.adminToken)
}
```

**Mitigation:** Remove query parameter support for admin token. Only accept via `X-Admin-Token` header. Never log the configured admin token value.

---

## [HIGH] Finding 3: Friend Code Grants Excessive Account Management Privileges

- **OWASP:** A01 -- Broken Access Control
- **STRIDE:** Elevation of Privilege
- **Location:** `router.go:307-350`
- **Confidence:** Confirmed

**Description:** The friend code was designed for viewing pool statistics, but it also grants access to account management operations: adding Claude/Codex accounts, exchanging OAuth codes, refreshing tokens, and viewing account lists across all providers. These are administrative operations that should require the admin token.

**Code Evidence:**
```go
// router.go:307-315 - friend code grants Claude admin access
if strings.HasPrefix(r.URL.Path, "/admin/claude") {
    if r.URL.Path != "/admin/claude/callback" {
        if !h.checkAdminOrFriendAuth(w, r) { // Friend code OR admin token
            return
        }
    }
    h.serveClaudeAdmin(w, r)
```

**Mitigation:** Use `checkAdminAuth` (not `checkAdminOrFriendAuth`) for all account management routes under `/admin/claude`, `/admin/codex`, `/admin/kimi`, `/admin/minimax`, `/admin/zai`. Reserve friend code auth for read-only stats endpoints.

---

## [HIGH] Finding 4: Claude Pool Tokens Never Expire

- **OWASP:** A07 -- Identification and Authentication Failures
- **STRIDE:** Spoofing
- **Location:** `pool_users.go:589-601` (generation), `pool_users.go:605-637` (validation)
- **Confidence:** Confirmed

**Description:** Pool-generated Claude tokens (`sk-ant-oat01-pool-*`) embed a timestamp but the validation function (`parseClaudePoolToken`) never checks expiry. These tokens are valid forever. Codex pool tokens expire in 10 years. A leaked pool token grants permanent access with no way to revoke it short of rotating the JWT secret (which invalidates all users).

**Code Evidence:**
```go
// pool_users.go:589-601 - timestamp included but no expiry
func generateClaudePoolToken(secret, userID string) string {
    now := time.Now().Unix()
    payload := fmt.Sprintf("%s.%d", userID, now)
    // ... signs but sets no expiry

// pool_users.go:605-637 - no expiry check in validation
func parseClaudePoolToken(secret, token string) (string, bool) {
    // ... validates signature only, never checks timestamp age
```

**Mitigation:** Add expiry validation to `parseClaudePoolToken`. Reject tokens older than a configurable TTL (e.g., 30 days). Add a `"exp"` field to the token payload.

---

## [MEDIUM] Finding 5: PKCE Verifier Leaked as OAuth State Parameter

- **OWASP:** A07 -- Identification and Authentication Failures
- **STRIDE:** Spoofing
- **Location:** `claude_auth.go:78-79`
- **Confidence:** Likely

**Description:** The PKCE code verifier is passed as the OAuth `state` parameter. The state parameter is visible in the redirect URL (browser address bar, history, logs). While the actual token exchange requires the verifier separately and is protected by friend auth, exposing the verifier weakens the PKCE guarantee.

**Code Evidence:**
```go
q.Set("state", pkce.Verifier) // Verifier should be kept secret
```

**Mitigation:** Use a random nonce as the state parameter. Keep the verifier server-side only.

---

## [MEDIUM] Finding 6: No Per-User Rate Limiting on Proxy Requests

- **OWASP:** A04 -- Insecure Design
- **STRIDE:** Denial of Service
- **Location:** `main.go:673-900` (proxyRequest function)
- **Confidence:** Confirmed

**Description:** Once authenticated, a pool user can make unlimited requests. There is no per-user request rate limit or token budget. A single user can exhaust all pool accounts' rate limits, denying service to other users. The only mitigation is upstream provider rate limits, which apply per-account, not per-user.

**Mitigation:** Implement per-user-ID request rate limiting (e.g., token bucket) before account selection.

---

## [MEDIUM] Finding 7: Raw IP Addresses Stored in BoltDB

- **OWASP:** A09 -- Security Logging and Monitoring Failures
- **STRIDE:** Information Disclosure
- **Location:** `storage.go:403-430`
- **Confidence:** Confirmed

**Description:** The `recordOriginMetadata` function stores raw client IP addresses alongside hashed origin IDs in BoltDB. This defeats the purpose of IP hashing and creates a PII exposure if the database file is exfiltrated.

**Code Evidence:**
```go
meta.RawIP = rawIP  // Plaintext IP stored in persistent database
```

**Mitigation:** Remove raw IP storage from persistent database. If IP attribution is needed for admin, store only in memory with auto-expiration.

---

## [MEDIUM] Finding 8: Missing Security Headers

- **OWASP:** A05 -- Security Misconfiguration
- **STRIDE:** Information Disclosure
- **Location:** All HTTP handlers (no global middleware)
- **Confidence:** Confirmed

**Description:** No security headers are set on any response. Missing: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy. HTML pages at `/` and `/status` are vulnerable to clickjacking and MIME sniffing attacks.

**Mitigation:** Add a middleware that sets security headers on all responses.

---

## [MEDIUM] Finding 9: JSON Body Decoding Without Size Limits

- **OWASP:** A04 -- Insecure Design
- **STRIDE:** Denial of Service
- **Location:** `frontend.go:103`, `admin_pool_users.go:84`, `admin_claude.go:308`, etc.
- **Confidence:** Confirmed

**Description:** Multiple admin and friend endpoints decode JSON from `r.Body` using `json.NewDecoder(r.Body).Decode(...)` without wrapping the body in `io.LimitReader`. An attacker could send an arbitrarily large body to consume server memory.

**Mitigation:** Wrap `r.Body` in `io.LimitReader(r.Body, maxBodySize)` for all JSON decode calls.

---

## [MEDIUM] Finding 10: Config Download Token in URL Path

- **OWASP:** A02 -- Cryptographic Failures
- **STRIDE:** Information Disclosure
- **Location:** `admin_pool_users.go:128-131`
- **Confidence:** Confirmed

**Description:** Pool user config download URLs (`/config/codex/<token>`) include the authentication token directly in the URL path. These URLs appear in browser history, server logs, CDN logs, and can leak via HTTP Referer headers. The token grants full credential download.

**Mitigation:** Use a short-lived, single-use download code instead of the persistent pool user token.

---

## [MEDIUM] Finding 11: Open Stats When No Auth Configured

- **OWASP:** A01 -- Broken Access Control
- **STRIDE:** Elevation of Privilege
- **Location:** `router.go:58-61`
- **Confidence:** Confirmed

**Description:** If neither admin token nor friend code is configured, `checkAdminOrFriendAuth` returns `true` for all requests. This makes all pool stats, user lists, and provider account management endpoints publicly accessible.

**Code Evidence:**
```go
if h.cfg.adminToken == "" && h.cfg.friendCode == "" {
    return true
}
```

**Mitigation:** Default to denying access when no auth is configured, or at minimum log a prominent warning.

---

## [LOW] Finding 12: Weak JWT Secret in Sample Configuration

- **OWASP:** A02 -- Cryptographic Failures
- **STRIDE:** Spoofing
- **Location:** `config.toml:19`
- **Confidence:** Confirmed (config file is local, not in git)

**Description:** The config file contains `jwt_secret = "bigfarts"` -- a trivially guessable secret. While the config file is not committed to git, if deployed with this value, an attacker can forge pool user JWTs.

**Mitigation:** Generate a random secret on first run if not configured. Validate minimum secret length (e.g., 32 characters).

---

## [LOW] Finding 13: X-Forwarded-For Spoofable When Not Behind Proxy

- **OWASP:** A01 -- Broken Access Control
- **STRIDE:** Spoofing
- **Location:** `utils.go:30-53`
- **Confidence:** Possible

**Description:** IP extraction trusts proxy headers (CF-Connecting-IP, X-Forwarded-For, X-Real-IP) without validation. If accessed directly (not through Cloudflare/Caddy), these headers can be forged. The server binds to `0.0.0.0:14430`, potentially allowing direct connections.

**Mitigation:** Only trust proxy headers when running behind a known proxy. Validate the immediate connection comes from a trusted proxy IP.

---

## [LOW] Finding 14: TOCTOU Race in Friend Claim User Creation

- **OWASP:** A04 -- Insecure Design
- **STRIDE:** Tampering
- **Location:** `frontend.go:149-163`
- **Confidence:** Confirmed

**Description:** The friend claim flow checks for an existing user by email, then creates a new one if not found. Concurrent requests with the same email could create duplicate users due to a time-of-check-time-of-use race.

**Mitigation:** Add a uniqueness check in `PoolUserStore.Create`, or use a `sync.Map`-based lock per email.

---

## [LOW] Finding 15: Refresh Proxy Credentials in Plaintext Config

- **OWASP:** A02 -- Cryptographic Failures
- **STRIDE:** Information Disclosure
- **Location:** `config.toml:8`
- **Confidence:** Confirmed (local config only)

**Description:** The refresh proxy URL contains plaintext credentials: `http://pool-nflx_us:cravetest@proxy-us.cravenet.com:7070`. While this file is not in git, it's stored in plaintext on disk.

**Mitigation:** Use environment variables for proxy credentials rather than embedding in the URL.

---

## [INFO] Finding 16: OAuth Callback Endpoint Unauthenticated By Design

- **OWASP:** N/A
- **STRIDE:** N/A
- **Location:** `router.go:307-311`, `admin_claude.go:344-352`
- **Confidence:** N/A

**Description:** The `/admin/claude/callback` endpoint accepts unauthenticated GET requests. This is by design -- it's an OAuth redirect target. The endpoint only echoes query parameters; the actual token exchange requires friend auth and the PKCE verifier. No security impact.

---

## [INFO] Finding 17: `alg:none` JWT in Fake OAuth Response

- **OWASP:** A08 -- Software and Data Integrity Failures
- **STRIDE:** Tampering
- **Location:** `handlers.go:336-337`
- **Confidence:** Confirmed (no practical impact)

**Description:** The fake OAuth token endpoint generates a JWT with `"alg":"none"` for local Codex CLI compatibility. This token is never validated -- the proxy always replaces auth headers before forwarding upstream. No security impact unless a component is added that trusts these tokens.
