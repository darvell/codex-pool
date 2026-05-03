# Dependency Audit -- codex-pool

## Go Version
- **Go 1.24.1** (current)

## Direct Dependencies

| Package | Version | Status | Notes |
|---------|---------|--------|-------|
| github.com/BurntSushi/toml | v1.5.0 | OK | TOML config parsing |
| github.com/fsnotify/fsnotify | v1.9.0 | OK | File watcher for hot-reload |
| github.com/refraction-networking/utls | v1.6.7 | Unused | TLS fingerprinting -- compiled but disabled in code |
| go.etcd.io/bbolt | v1.3.8 | OK | BoltDB embedded database |
| golang.org/x/net | v0.48.0 | OK | HTTP/2 and WebSocket support |
| modernc.org/sqlite | v1.46.1 | OK | SQLite for analytics |

## Indirect Dependencies (Security-Relevant)

| Package | Version | Notes |
|---------|---------|-------|
| github.com/coder/websocket | v1.8.14 | WebSocket protocol handling |
| golang.org/x/crypto | v0.46.0 | Cryptographic functions |
| github.com/cloudflare/circl | v1.3.7 | Cryptographic primitives (via utls) |
| github.com/andybalholm/brotli | v1.2.0 | Brotli compression (via utls) |

## Automated Scan

`govulncheck` is not installed on this system. Manual review shows:

- All direct dependencies are at recent versions
- No known CVEs identified in manual search for these specific versions
- The `utls` library (v1.6.7) pulls in several crypto-related indirect dependencies; since it's disabled, these increase attack surface without benefit

## Recommendations

1. **Remove utls dependency** -- it's disabled in code but still compiled, adding unnecessary dependency surface
2. **Install and run govulncheck** periodically: `go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...`
3. **Pin Go version** in CI/CD to ensure consistent builds
