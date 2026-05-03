# Recommendations -- codex-pool Security Audit

## Priority 1 -- Critical (Fix Immediately)

### 1. Validate Refresh Tokens Against Stored Values
**Finding:** [Refresh Token Forgery](./findings.md#critical-finding-1-refresh-token-forgery-allows-account-impersonation)
**Effort:** 30 minutes

Store issued refresh tokens and validate the full token on refresh requests, not just the user ID prefix.

```go
// Option A: Store refresh token hash in PoolUser struct
type PoolUser struct {
    // ... existing fields
    RefreshTokenHash string `json:"refresh_token_hash,omitempty"`
}

// In handlePoolUserRefresh:
func (h *proxyHandler) handlePoolUserRefresh(w http.ResponseWriter, refreshToken string) {
    // Hash the provided refresh token and look up by hash
    hash := sha256Hash(refreshToken)
    user := h.poolUsers.GetByRefreshTokenHash(hash)
    if user == nil {
        respondJSONError(w, http.StatusUnauthorized, "invalid refresh token")
        return
    }
    // ... continue
}
```

```go
// Option B: HMAC-sign refresh tokens so they're self-validating
func generateRefreshToken(secret, userID string) string {
    nonce := randomHex(16)
    payload := fmt.Sprintf("poolrt_%s_%s", userID, nonce)
    sig := hmacSign(secret, []byte(payload))
    return payload + "_" + base64.RawURLEncoding.EncodeToString(sig)[:16]
}
```

## Priority 2 -- High (Fix This Sprint)

### 2. Remove Admin Token from Query Parameters
**Finding:** [Admin Token Exposure](./findings.md#high-finding-2-admin-token-exposed-in-query-parameters-and-debug-logs)
**Effort:** 10 minutes

```go
// router.go - Only accept admin token via header
token := r.Header.Get("X-Admin-Token")
// Remove: token = r.URL.Query().Get("admin_token")
```

Also remove debug logging of the configured admin token:
```go
if h.cfg.debug.Load() {
    log.Printf("admin auth: attempt from %s (valid=%v)", ip, token == h.cfg.adminToken)
}
```

### 3. Separate Friend Auth from Admin Account Management
**Finding:** [Friend Code Privileges](./findings.md#high-finding-3-friend-code-grants-excessive-account-management-privileges)
**Effort:** 15 minutes

```go
// router.go - Use checkAdminAuth for account management
if strings.HasPrefix(r.URL.Path, "/admin/claude") {
    if r.URL.Path == "/admin/claude/callback" {
        // OAuth callback - no auth needed
    } else if r.URL.Path == "/admin/claude" && r.Method == http.MethodGet {
        // List accounts - friend auth OK (read-only)
        if !h.checkAdminOrFriendAuth(w, r) { return }
    } else {
        // All mutations (add, exchange, refresh) - admin only
        if !h.checkAdminAuth(w, r) { return }
    }
    h.serveClaudeAdmin(w, r)
}
```

### 4. Add Expiry to Claude Pool Tokens
**Finding:** [Token Never Expires](./findings.md#high-finding-4-claude-pool-tokens-never-expire)
**Effort:** 15 minutes

```go
func parseClaudePoolToken(secret, token string) (string, bool) {
    // ... existing signature validation ...

    // Add expiry check
    timestampStr := parts[1]
    if ts, err := strconv.ParseInt(timestampStr, 10, 64); err == nil {
        age := time.Since(time.Unix(ts, 0))
        if age > 30*24*time.Hour { // 30 day TTL
            return "", false
        }
    }
    return userID, true
}
```

## Priority 3 -- Medium (Plan for Next Sprint)

### 5. Add Per-User Rate Limiting
**Finding:** [No User Rate Limits](./findings.md#medium-finding-6-no-per-user-rate-limiting-on-proxy-requests)
**Effort:** 1-2 hours

Implement a token bucket or sliding window rate limiter keyed by user ID before account selection in `proxyRequest()`.

### 6. Add Security Headers Middleware
**Finding:** [Missing Headers](./findings.md#medium-finding-8-missing-security-headers)
**Effort:** 15 minutes

```go
func securityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("Referrer-Policy", "no-referrer")
        next.ServeHTTP(w, r)
    })
}
```

### 7. Limit JSON Body Size on Admin Endpoints
**Finding:** [Unbounded JSON Decode](./findings.md#medium-finding-9-json-body-decoding-without-size-limits)
**Effort:** 10 minutes

```go
r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
```

### 8. Remove Raw IP from Persistent Storage
**Finding:** [Raw IP Storage](./findings.md#medium-finding-7-raw-ip-addresses-stored-in-boltdb)
**Effort:** 20 minutes

Store only the hashed origin ID in BoltDB. Keep raw IPs in memory with TTL for real-time admin use.

### 9. Fix PKCE State Parameter
**Finding:** [Verifier as State](./findings.md#medium-finding-5-pkce-verifier-leaked-as-oauth-state-parameter)
**Effort:** 10 minutes

```go
state := randomHex(16) // Use random nonce, not verifier
q.Set("state", state)
// Store mapping: state -> session (instead of verifier -> session)
```

### 10. Use Short-Lived Config Download Tokens
**Finding:** [Token in URL](./findings.md#medium-finding-10-config-download-token-in-url-path)
**Effort:** 30 minutes

Generate a short-lived, single-use download code instead of using the persistent pool user token in the URL.

## Priority 4 -- Low (Nice to Have)

### 11. Enforce Minimum JWT Secret Length
Validate that `jwt_secret` is at least 32 characters on startup. Generate a random secret if not configured.

### 12. Remove Unused utls Dependency
`go mod edit -droprequire github.com/refraction-networking/utls && go mod tidy`

### 13. Add Body Size Limit to Friend Claim
Wrap `r.Body` in `io.LimitReader` or `http.MaxBytesReader` for the `/api/friend/claim` endpoint.

### 14. Add Duplicate User Check to Friend Claim
Use a mutex or compare-and-swap to prevent race condition in user creation.
