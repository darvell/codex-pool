# OWASP Top 10 Coverage -- codex-pool Security Audit

| ID | Category | Tested | Findings | Status |
|----|----------|--------|----------|--------|
| A01 | Broken Access Control | Yes | 3 | Issues found |
| A02 | Cryptographic Failures | Yes | 4 | Issues found |
| A03 | Injection | Yes | 0 | Clean (no command injection, no SQL, no template injection) |
| A04 | Insecure Design | Yes | 3 | Issues found |
| A05 | Security Misconfiguration | Yes | 2 | Issues found |
| A06 | Vulnerable and Outdated Components | Yes | 0 | Unable to verify (govulncheck not installed) |
| A07 | Identification and Authentication Failures | Yes | 3 | Issues found |
| A08 | Software and Data Integrity Failures | Yes | 1 | Info only |
| A09 | Security Logging and Monitoring Failures | Yes | 1 | Issues found |
| A10 | Server-Side Request Forgery | Yes | 0 | Clean (all upstream URLs are hardcoded) |

## Per-Category Details

### A01 -- Broken Access Control

**Checks performed:**
- [x] IDOR on parameterized routes
- [x] Missing authorization middleware on protected routes
- [x] Horizontal privilege escalation
- [x] Vertical privilege escalation
- [x] Directory traversal on file operations (N/A -- no file operations from user input)
- [x] CORS misconfiguration (no CORS headers set at all)
- [x] Missing function-level access control

**Findings:**
- Finding 3: Friend code grants account management privileges (vertical escalation)
- Finding 11: Open stats when no auth configured
- Finding 13: X-Forwarded-For spoofable

### A02 -- Cryptographic Failures

**Checks performed:**
- [x] Sensitive data in plaintext
- [x] Weak hashing algorithms
- [x] Hardcoded secrets/API keys
- [x] Missing encryption at rest
- [x] Weak random number generation
- [x] Exposed config with secrets

**Findings:**
- Finding 2: Admin token in query parameters
- Finding 10: Config download token in URL path
- Finding 12: Weak JWT secret in sample config
- Finding 15: Refresh proxy credentials in plaintext

### A03 -- Injection

**Checks performed:**
- [x] SQL/NoSQL injection (N/A -- uses BoltDB k/v, no SQL)
- [x] Command injection (no exec.Command usage found)
- [x] XSS (templates use Go html/template with auto-escaping)
- [x] Template injection (embedded templates, no user-supplied templates)
- [x] Path injection in file operations (no user-supplied paths used in file operations)
- [x] Header injection (proxy removes hop-by-hop headers)

**Result:** Clean. No injection vectors found.

### A04 -- Insecure Design

**Checks performed:**
- [x] Missing rate limiting on sensitive endpoints
- [x] No account lockout after failed login
- [x] Predictable resource identifiers
- [x] Race conditions
- [x] Missing CSRF protection
- [x] Insecure direct object references

**Findings:**
- Finding 6: No per-user rate limiting on proxy requests
- Finding 9: JSON body decoding without size limits
- Finding 14: TOCTOU race in friend claim

### A05 -- Security Misconfiguration

**Checks performed:**
- [x] Debug mode in production
- [x] Verbose error messages
- [x] Missing security headers
- [x] Unnecessary HTTP methods
- [x] Stack traces in error responses

**Findings:**
- Finding 2: Debug mode logs admin tokens
- Finding 8: Missing security headers

### A06 -- Vulnerable and Outdated Components

**Checks performed:**
- [ ] Known CVEs in dependencies (govulncheck not available)
- [x] Outdated frameworks (Go 1.24.1, all deps appear current)
- [x] Unmaintained dependencies (none identified)
- [x] Disabled-but-compiled code (utls library compiled but disabled)

**Result:** Unable to perform automated vulnerability scan. Manual review shows dependencies appear current.

### A07 -- Identification and Authentication Failures

**Checks performed:**
- [x] Weak password policies (N/A -- no passwords, token-based auth)
- [x] Session fixation vulnerabilities
- [x] JWT vulnerabilities
- [x] Token expiry validation
- [x] Session invalidation

**Findings:**
- Finding 1: Refresh token forgery (CRITICAL)
- Finding 4: Claude pool tokens never expire
- Finding 5: PKCE verifier leaked as OAuth state

### A08 -- Software and Data Integrity Failures

**Checks performed:**
- [x] Missing integrity checks on CI/CD
- [x] Unsigned or unverified updates
- [x] Insecure deserialization (JSON only, no arbitrary deserialization)
- [x] Missing CSP or SRI

**Findings:**
- Finding 17: `alg:none` JWT (Info, no practical impact)

### A09 -- Security Logging and Monitoring Failures

**Checks performed:**
- [x] Missing audit logs for security events
- [x] Logging of failed auth attempts (brute force tracker logs these)
- [x] Sensitive data in logs
- [x] Missing alerting
- [x] Log injection

**Findings:**
- Finding 7: Raw IP addresses stored in persistent database

### A10 -- Server-Side Request Forgery

**Checks performed:**
- [x] Unvalidated URLs in server-side requests
- [x] DNS rebinding
- [x] Missing allowlist for external service calls
- [x] Proxy/redirect endpoints without validation

**Result:** Clean. All upstream URLs are hardcoded constants. No user-controllable URLs in server-side requests.
