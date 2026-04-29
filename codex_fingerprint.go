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
	codexDefaultOriginator     = "Codex Desktop"
	codexDefaultAppVersion     = "26.318.11754"
	codexDefaultBuildNumber    = "1100"
	codexDefaultChromium       = "144"
	codexDefaultResidency      = "us"
	codexAppcastURL            = "https://persistent.oaistatic.com/codex-app-prod/appcast.xml"
	codexFingerprintPollPeriod = 72 * time.Hour
)

type codexFingerprintState struct {
	Originator      string `json:"originator"`
	AppVersion      string `json:"app_version"`
	BuildNumber     string `json:"build_number"`
	ChromiumVersion string `json:"chromium_version"`
	Platform        string `json:"platform"`
	Arch            string `json:"arch"`
}

var codexFingerprint = struct {
	mu    sync.RWMutex
	state codexFingerprintState
}{state: defaultCodexFingerprintState()}

func defaultCodexFingerprintState() codexFingerprintState {
	return codexFingerprintState{
		Originator:      getenv("CODEX_ORIGINATOR", codexDefaultOriginator),
		AppVersion:      getenv("CODEX_APP_VERSION", codexDefaultAppVersion),
		BuildNumber:     getenv("CODEX_BUILD_NUMBER", codexDefaultBuildNumber),
		ChromiumVersion: getenv("CODEX_CHROMIUM_VERSION", codexDefaultChromium),
		Platform:        getenv("CODEX_PLATFORM", codexPlatform()),
		Arch:            getenv("CODEX_ARCH", codexArch()),
	}
}

func codexPlatform() string {
	switch runtime.GOOS {
	case "darwin":
		return "darwin"
	case "windows":
		return "win32"
	case "linux":
		return "linux"
	default:
		return runtime.GOOS
	}
}

func codexArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
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

func codexDesktopUserAgent(fp codexFingerprintState) string {
	if ua := strings.TrimSpace(os.Getenv("CODEX_USER_AGENT")); ua != "" {
		return ua
	}
	return fmt.Sprintf("Codex Desktop/%s (%s; %s)", fp.AppVersion, fp.Platform, fp.Arch)
}

func applyCodexRequestFingerprint(req *http.Request, acc *Account) {
	if req == nil || acc == nil || acc.Type != AccountTypeCodex {
		return
	}

	fp := currentCodexFingerprint()
	req.Header.Set("originator", fp.Originator)
	req.Header.Set("x-openai-internal-codex-residency", getenv("CODEX_RESIDENCY", codexDefaultResidency))
	if req.Header.Get("x-client-request-id") == "" {
		req.Header.Set("x-client-request-id", uuid.NewString())
	}
	if req.Header.Get("x-codex-turn-state") == "" {
		acc.mu.Lock()
		turnState := acc.CodexTurnState
		acc.mu.Unlock()
		if turnState != "" {
			req.Header.Set("x-codex-turn-state", turnState)
		}
	}
	req.Header.Set("OpenAI-Beta", "responses_websockets=2026-02-06")
	req.Header.Set("User-Agent", codexDesktopUserAgent(fp))
	req.Header.Set("sec-ch-ua", fmt.Sprintf(`"Chromium";v="%s", "Not?A_Brand";v="24"`, fp.ChromiumVersion))
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", fmt.Sprintf(`"%s"`, codexSecCHPlatform(fp.Platform)))
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("sec-fetch-site", "same-origin")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-dest", "empty")
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json, text/event-stream")
	}
	if req.Header.Get("Content-Type") == "" && req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	applyCodexCookies(req, acc)
}

func codexSecCHPlatform(platform string) string {
	switch strings.ToLower(platform) {
	case "darwin", "macos":
		return "macOS"
	case "win32", "windows":
		return "Windows"
	case "linux":
		return "Linux"
	default:
		return platform
	}
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
	if turnState := strings.TrimSpace(resp.Header.Get("x-codex-turn-state")); turnState != "" && turnState != acc.CodexTurnState {
		acc.CodexTurnState = turnState
	}
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

func checkCodexFingerprintUpdate() {
	url := getenv("CODEX_APPCAST_URL", codexAppcastURL)
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		log.Printf("codex fingerprint update read failed: %v", err)
		return
	}
	version, build := parseCodexAppcastVersion(string(body))
	if version == "" || build == "" {
		return
	}
	codexFingerprint.mu.Lock()
	changed := codexFingerprint.state.AppVersion != version || codexFingerprint.state.BuildNumber != build
	if changed {
		codexFingerprint.state.AppVersion = version
		codexFingerprint.state.BuildNumber = build
	}
	state := codexFingerprint.state
	codexFingerprint.mu.Unlock()
	if changed {
		log.Printf("codex fingerprint updated from appcast: version=%s build=%s", state.AppVersion, state.BuildNumber)
	}
	persistCodexFingerprintState(state)
}

func parseCodexAppcastVersion(xml string) (string, string) {
	item := regexp.MustCompile(`(?is)<item>(.*?)</item>`).FindStringSubmatch(xml)
	if len(item) < 2 {
		return "", ""
	}
	version := firstRegexpGroup(item[1], `sparkle:shortVersionString="([^"]+)"`, `(?is)<sparkle:shortVersionString>([^<]+)</sparkle:shortVersionString>`)
	build := firstRegexpGroup(item[1], `sparkle:version="([^"]+)"`, `(?is)<sparkle:version>([^<]+)</sparkle:version>`)
	return strings.TrimSpace(version), strings.TrimSpace(build)
}

func firstRegexpGroup(s string, patterns ...string) string {
	for _, pattern := range patterns {
		m := regexp.MustCompile(pattern).FindStringSubmatch(s)
		if len(m) > 1 {
			return m[1]
		}
	}
	return ""
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
