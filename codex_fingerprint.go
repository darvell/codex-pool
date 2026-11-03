package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	// Match the current codex-rs CLI identity. The originator and the
	// User-Agent client name stay paired, and the version is the CLI engine
	// version rather than the desktop app version: capacity shedding treats
	// mismatched or legacy identities more aggressively and can return
	// server_is_overloaded before producing output.
	codexDefaultOriginator     = "codex_cli_rs"
	codexDefaultCLIVersion     = "0.166.0"
	codexDefaultTerminal       = "xterm-256color"
	codexDefaultResidency      = "us"
	codexCLIReleaseURL         = "https://registry.npmjs.org/@openai/codex/latest"
	codexFingerprintPollPeriod = 24 * time.Hour
)

var codexCLIVersionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

type codexFingerprintState struct {
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
	Terminal string `json:"terminal"`
}

var codexFingerprint = struct {
	mu    sync.RWMutex
	state codexFingerprintState
}{state: defaultCodexFingerprintState()}

func defaultCodexFingerprintState() codexFingerprintState {
	return codexFingerprintState{
		Version:  getenv("CODEX_CLI_VERSION", codexDefaultCLIVersion),
		Platform: getenv("CODEX_PLATFORM", codexPlatform()),
		Arch:     getenv("CODEX_ARCH", codexArch()),
		Terminal: getenv("CODEX_TERMINAL", codexDefaultTerminal),
	}
}

// codexPlatform returns the "<OS> <version>" pair the CLI derives from
// os_info for its User-Agent.
func codexPlatform() string {
	switch runtime.GOOS {
	case "darwin":
		return "Mac OS 26.2.0"
	case "windows":
		return "Windows 11.0.26100"
	default:
		return "Ubuntu 24.4.0"
	}
}

func codexArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "arm64"
	default:
		return runtime.GOARCH
	}
}

func currentCodexFingerprint() codexFingerprintState {
	codexFingerprint.mu.RLock()
	defer codexFingerprint.mu.RUnlock()
	return codexFingerprint.state
}

func codexCLIUserAgent(fp codexFingerprintState) string {
	canonical := fmt.Sprintf("%s/%s (%s; %s) %s", codexDefaultOriginator, fp.Version, fp.Platform, fp.Arch, fp.Terminal)
	ua := strings.TrimSpace(os.Getenv("CODEX_USER_AGENT"))
	if ua == "" {
		return canonical
	}
	// Keep a configured fingerprint suffix, but canonicalize the client
	// identity and version, and drop the optional TUI trailer so originator
	// and User-Agent agree.
	slash := strings.IndexByte(ua, '/')
	if slash <= 0 || strings.ContainsAny(ua, "\r\n") {
		return canonical
	}
	rest := ua[slash+1:]
	versionEnd := len(rest)
	if space := strings.IndexByte(rest, ' '); space >= 0 && space < versionEnd {
		versionEnd = space
	}
	if open := strings.IndexByte(rest, '('); open >= 0 && open < versionEnd {
		versionEnd = open
	}
	suffix := rest[versionEnd:]
	if open := strings.LastIndex(suffix, "("); open > 0 && strings.Contains(strings.ToLower(suffix[open:]), "codex-tui") {
		suffix = strings.TrimRight(suffix[:open], " ")
	}
	return codexDefaultOriginator + "/" + fp.Version + suffix
}

func applyCodexRequestFingerprint(req *http.Request, acc *Account) {
	if req == nil || acc == nil || acc.Type != AccountTypeCodex {
		return
	}

	fp := currentCodexFingerprint()
	req.Header.Set("originator", codexDefaultOriginator)
	req.Header.Set("x-openai-internal-codex-residency", getenv("CODEX_RESIDENCY", codexDefaultResidency))
	if req.Header.Get("x-client-request-id") == "" {
		req.Header.Set("x-client-request-id", uuid.NewString())
	}
	req.Header.Set("OpenAI-Beta", "responses_websockets=2026-02-06")
	req.Header.Set("User-Agent", codexCLIUserAgent(fp))
	// The CLI is not a browser. Drop any client hints a downstream client
	// supplied so the request does not pair a CLI identity with browser
	// headers.
	for _, name := range []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "Accept-Language"} {
		req.Header.Del(name)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json, text/event-stream")
	}
	if req.Header.Get("Content-Type") == "" && req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	applyCodexCookies(req, acc)
}

func applyCodexCookies(req *http.Request, acc *Account) {
	acc.mu.Lock()
	cookies := make(map[string]string, len(acc.CodexCookies))
	for k, v := range acc.CodexCookies {
		if strings.TrimSpace(k) != "" && strings.TrimSpace(v) != "" {
			cookies[k] = v
		}
	}
	acc.mu.Unlock()
	if len(cookies) == 0 {
		return
	}
	for _, existing := range req.Cookies() {
		if _, ok := cookies[existing.Name]; !ok {
			cookies[existing.Name] = existing.Value
		}
	}
	names := make([]string, 0, len(cookies))
	for name := range cookies {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, (&http.Cookie{Name: name, Value: cookies[name]}).String())
	}
	req.Header.Set("Cookie", strings.Join(parts, "; "))
}

func captureCodexResponseState(acc *Account, resp *http.Response, reqID string) {
	if acc == nil || resp == nil || acc.Type != AccountTypeCodex {
		return
	}
	changed := false
	acc.mu.Lock()
	for _, c := range resp.Cookies() {
		if !isPersistedCodexCookie(c.Name) || c.Value == "" {
			continue
		}
		if acc.CodexCookies == nil {
			acc.CodexCookies = map[string]string{}
		}
		if acc.CodexCookies[c.Name] != c.Value {
			acc.CodexCookies[c.Name] = c.Value
			changed = true
		}
	}
	acc.mu.Unlock()
	if changed && acc.File != "" {
		if err := saveAccount(acc); err != nil {
			log.Printf("[%s] warning: failed to persist codex cookies for account %s: %v", reqID, acc.ID, err)
		}
	}
}

func isPersistedCodexCookie(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "cf_clearance", "__cf_bm", "_cfuvid":
		return true
	default:
		return false
	}
}

func startCodexFingerprintUpdater() {
	if getenv("CODEX_FINGERPRINT_AUTO_UPDATE", "1") == "0" {
		return
	}
	go func() {
		checkCodexFingerprintUpdate()
		period := codexFingerprintPollPeriod
		if raw := strings.TrimSpace(os.Getenv("CODEX_FINGERPRINT_UPDATE_SECONDS")); raw != "" {
			if n, err := parseInt64(raw); err == nil && n > 0 {
				period = time.Duration(n) * time.Second
			}
		}
		ticker := time.NewTicker(period)
		defer ticker.Stop()
		for range ticker.C {
			checkCodexFingerprintUpdate()
		}
	}()
}

// checkCodexFingerprintUpdate tracks the latest published CLI release so the
// advertised version follows real clients without a redeploy.
func checkCodexFingerprintUpdate() {
	url := getenv("CODEX_CLI_RELEASE_URL", codexCLIReleaseURL)
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("codex fingerprint update check failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("codex fingerprint update check returned %s", resp.Status)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		log.Printf("codex fingerprint update read failed: %v", err)
		return
	}
	version := parseCodexCLIRelease(body)
	if version == "" {
		return
	}
	codexFingerprint.mu.Lock()
	changed := codexFingerprint.state.Version != version
	if changed {
		codexFingerprint.state.Version = version
	}
	state := codexFingerprint.state
	codexFingerprint.mu.Unlock()
	if changed {
		log.Printf("codex fingerprint updated from CLI release: version=%s", state.Version)
	}
	persistCodexFingerprintState(state)
}

// parseCodexCLIRelease returns the stable CLI version from an npm registry
// "latest" document. Prerelease and malformed versions are ignored.
func parseCodexCLIRelease(body []byte) string {
	var release struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(body, &release) != nil {
		return ""
	}
	version := strings.TrimSpace(release.Version)
	if !codexCLIVersionPattern.MatchString(version) {
		return ""
	}
	return version
}

func persistCodexFingerprintState(state codexFingerprintState) {
	path := strings.TrimSpace(os.Getenv("CODEX_FINGERPRINT_STATE_PATH"))
	if path == "" {
		return
	}
	if b, err := json.MarshalIndent(state, "", "  "); err == nil {
		_ = os.WriteFile(path, b, 0600)
	}
}
