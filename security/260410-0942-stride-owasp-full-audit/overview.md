# Security Audit -- codex-pool (Full STRIDE + OWASP)

**Date:** 2026-04-10 09:42
**Scope:** Entire codebase (all .go files, config, templates)
**Focus:** Comprehensive
**Iterations:** 31
**Mode:** Report only (read-only)

## Summary

- **Total Findings:** 17 unique findings
  - Critical: 1 | High: 3 | Medium: 10 | Low: 6 | Info: 4
- **STRIDE Coverage:** 6/6 categories tested
- **OWASP Coverage:** 10/10 categories tested
- **Confirmed:** 26 | Likely: 1 | Possible: 3

## Top 3 Critical Findings

1. [Refresh Token Forgery](./findings.md#critical-finding-1-refresh-token-forgery-allows-account-impersonation) -- `/oauth/token` accepts any `poolrt_<USER_ID>_<anything>` as a valid refresh token. Combined with user ID enumeration via friend code, this enables full account takeover.

2. [Friend Code Grants Admin Privileges](./findings.md#high-finding-3-friend-code-grants-excessive-account-management-privileges) -- Friend code authentication is used for account management routes (add/refresh/exchange accounts) across all providers, not just read-only stats viewing.

3. [Claude Pool Tokens Never Expire](./findings.md#high-finding-4-claude-pool-tokens-never-expire) -- Pool-generated Claude tokens have no expiry check. A leaked token grants permanent proxy access.

## Attack Chain (Critical)

An attacker can escalate from friend code knowledge to full proxy access:
1. Guess or obtain the friend code
2. Enumerate pool user IDs via `GET /api/pool/users`
3. Forge a refresh token: `POST /oauth/token` with `{"refresh_token":"poolrt_<ID>_x"}`
4. Receive valid access credentials for that user
5. Proxy unlimited requests as that user

## Files in This Report

- [Threat Model](./threat-model.md) -- STRIDE analysis, assets, trust boundaries
- [Attack Surface Map](./attack-surface-map.md) -- entry points, data flows, abuse paths
- [Findings](./findings.md) -- all 17 findings ranked by severity
- [OWASP Coverage](./owasp-coverage.md) -- per-category test results (10/10 tested)
- [Dependency Audit](./dependency-audit.md) -- Go dependency security review
- [Recommendations](./recommendations.md) -- 14 prioritized mitigations with code
- [Iteration Log](./security-audit-results.tsv) -- raw data from all 31 iterations

## Coverage Matrix

### STRIDE

| Category | Tested | Findings |
|----------|--------|----------|
| Spoofing | Yes | 5 |
| Tampering | Yes | 2 |
| Repudiation | Yes | 2 |
| Information Disclosure | Yes | 7 |
| Denial of Service | Yes | 3 |
| Elevation of Privilege | Yes | 4 |

### OWASP Top 10

| Category | Tested | Findings |
|----------|--------|----------|
| A01 Broken Access Control | Yes | 3 |
| A02 Cryptographic Failures | Yes | 4 |
| A03 Injection | Yes | 0 (clean) |
| A04 Insecure Design | Yes | 3 |
| A05 Security Misconfiguration | Yes | 2 |
| A06 Vulnerable Components | Yes | 0 (no scanner) |
| A07 Auth Failures | Yes | 3 |
| A08 Integrity Failures | Yes | 1 (info) |
| A09 Logging Failures | Yes | 1 |
| A10 SSRF | Yes | 0 (clean) |
