package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServeCodexSetupScript_PowerShell(t *testing.T) {
	h := &proxyHandler{}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/setup/codex/testtoken?shell=powershell", nil)
	rr := httptest.NewRecorder()
	h.serveCodexSetupScript(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain*", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Set-StrictMode -Version Latest") {
		t.Fatalf("expected PowerShell script body, got:\n%s", body)
	}
	if !strings.Contains(body, "Join-Path $HOME '.codex'") {
		t.Fatalf("expected codex paths in script body, got:\n%s", body)
	}
	if !strings.Contains(body, "model_catalog_json = ") {
		t.Fatalf("expected model catalog config in script body, got:\n%s", body)
	}
	if !strings.Contains(body, "[mcp_servers.model_sync]") {
		t.Fatalf("expected MCP sidecar config in script body, got:\n%s", body)
	}
	if !strings.Contains(body, "model_sync.ps1") {
		t.Fatalf("expected MCP sidecar script install in PowerShell body, got:\n%s", body)
	}
	if !strings.Contains(body, "$firstLine = [Console]::In.ReadLine()") {
		t.Fatalf("expected MCP JSONL transport support in PowerShell body, got:\n%s", body)
	}
}

func TestServeCodexSetupScript_Bash(t *testing.T) {
	h := &proxyHandler{}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/setup/codex/testtoken", nil)
	rr := httptest.NewRecorder()
	h.serveCodexSetupScript(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/x-shellscript") {
		t.Fatalf("Content-Type = %q, want text/x-shellscript*", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "model_sync.sh") {
		t.Fatalf("expected MCP sidecar script install in bash body, got:\n%s", body)
	}
	if !strings.Contains(body, "model_catalog_json = ") {
		t.Fatalf("expected model catalog config in bash script body, got:\n%s", body)
	}
	if !strings.Contains(body, "[mcp_servers.model_sync]") {
		t.Fatalf("expected MCP sidecar config in bash script body, got:\n%s", body)
	}
	if !strings.Contains(body, "MCP_TRANSPORT_MODE=\"jsonl\"") {
		t.Fatalf("expected MCP JSONL transport support in bash body, got:\n%s", body)
	}
}

func TestServeGrokSetupScript_Bash(t *testing.T) {
	h := &proxyHandler{}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/setup/grok/testtoken", nil)
	rr := httptest.NewRecorder()
	h.serveGrokSetupScript(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	for _, want := range []string{"[endpoints]", `models_base_url = \"`, `[model."%s"]`, "grok-build", "gpt-5.6-luna", "claude-sonnet-5", "auth.json.before-codex-pool", "/config/grok/$TOKEN"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected Grok setup script to contain %q", want)
		}
	}
}

func TestServeGrokSetupScript_PowerShell(t *testing.T) {
	h := &proxyHandler{}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/setup/grok/testtoken?shell=powershell", nil)
	rr := httptest.NewRecorder()
	h.serveGrokSetupScript(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "models_base_url") || !strings.Contains(rr.Body.String(), "[model.\"' + $Model.Id + '\"]") {
		t.Fatalf("PowerShell Grok setup missing proxy endpoint or model credentials: status=%d", rr.Code)
	}
}

func TestServeGrokSetupScript_BashPreservesConfigAndIsIdempotent(t *testing.T) {
	h := &proxyHandler{}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/setup/grok/testtoken", nil)
	rr := httptest.NewRecorder()
	h.serveGrokSetupScript(rr, req)

	home := t.TempDir()
	configDir := filepath.Join(home, ".grok")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(configDir, "config.toml")
	initial := "[cli]\nauto_update = true\n\n[models]\ndefault = \"grok-build\"\n"
	if err := os.WriteFile(configFile, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	authFile := filepath.Join(configDir, "auth.json")
	if err := os.WriteFile(authFile, []byte(`{"oauth":"credential"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(home, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fakeCurl := "#!/bin/sh\nprintf '%s\\n' '{\"api_key\":\"pool-jwt\"}'\n"
	if err := os.WriteFile(filepath.Join(binDir, "curl"), []byte(fakeCurl), 0o700); err != nil {
		t.Fatal(err)
	}

	for range 2 {
		cmd := exec.Command("bash")
		cmd.Stdin = strings.NewReader(rr.Body.String())
		cmd.Env = append(os.Environ(), "HOME="+home, "PATH="+binDir+":"+os.Getenv("PATH"))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("run installer: %v\n%s", err, output)
		}
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatal(err)
	}
	config := string(data)
	for _, want := range []string{"[cli]", "auto_update = true", `default = "grok-build"`, `[endpoints]`, `models_base_url = "http://example.com/v1"`, `api_key = "pool-jwt"`} {
		if !strings.Contains(config, want) {
			t.Fatalf("installed config missing %q:\n%s", want, config)
		}
	}
	if strings.Contains(config, "codex-pool-grok") {
		t.Fatalf("installer must not create or select a synthetic model:\n%s", config)
	}
	if count := strings.Count(config, `[model."grok-build"]`); count != 1 {
		t.Fatalf("grok-build credential override count = %d, want 1:\n%s", count, config)
	}
	if _, err := os.Stat(authFile); !os.IsNotExist(err) {
		t.Fatalf("active Grok OAuth file still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "auth.json.before-codex-pool")); err != nil {
		t.Fatalf("Grok OAuth backup missing: %v", err)
	}
}

func TestServePiSetupScriptMergesProviders(t *testing.T) {
	h := &proxyHandler{}
	for _, target := range []string{
		"http://example.com/setup/pi/testtoken",
		"http://example.com/setup/pi/testtoken?shell=powershell",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rr := httptest.NewRecorder()
		h.servePiSetupScript(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status = %d", target, rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, "/config/pi/testtoken") || !strings.Contains(body, "providers") {
			t.Fatalf("%s did not generate a merging Pi installer", target)
		}
	}
}

func TestServeGeminiSetupScript_PowerShell(t *testing.T) {
	secret := "test-secret-key-12345678901234567890"
	t.Setenv("POOL_JWT_SECRET", secret)

	tmpDir := t.TempDir()
	usersPath := filepath.Join(tmpDir, "pool_users.json")
	store, err := newPoolUserStore(usersPath)
	if err != nil {
		t.Fatalf("newPoolUserStore: %v", err)
	}

	user := &PoolUser{
		ID:        "user123",
		Token:     "tok123",
		Email:     "test@example.com",
		PlanType:  "pro",
		CreatedAt: time.Now(),
	}
	if err := store.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	h := &proxyHandler{poolUsers: store}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/setup/gemini/tok123?shell=powershell", nil)
	rr := httptest.NewRecorder()
	h.serveGeminiSetupScript(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain*", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "$env:CODE_ASSIST_ENDPOINT = $BaseUrl") {
		t.Fatalf("expected PowerShell env setup in body, got:\n%s", body)
	}
	if strings.Contains(body, "`") {
		t.Fatalf("PowerShell script should not contain backticks (Go raw string safety), got:\n%s", body)
	}
}

func newTestPoolUserStoreWithUser(t *testing.T, token string) *PoolUserStore {
	t.Helper()
	tmpDir := t.TempDir()
	usersPath := filepath.Join(tmpDir, "pool_users.json")
	store, err := newPoolUserStore(usersPath)
	if err != nil {
		t.Fatalf("newPoolUserStore: %v", err)
	}
	user := &PoolUser{ID: "user-" + token, Token: token, Email: token + "@example.com", PlanType: "pro", CreatedAt: time.Now()}
	if err := store.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return store
}

func TestServeCuteCodeLanding(t *testing.T) {
	h := &proxyHandler{}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/cute-code", nil)
	rr := httptest.NewRecorder()

	h.serveCuteCodeLanding(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	for _, want := range []string{"codex pool + cute-code", "Generate setup", "cute-code --model gpt-5.6-sol"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected cute-code landing to contain %q, got:\n%s", want, body)
		}
	}
}

func TestFriendLandingServesReactSignalRoom(t *testing.T) {
	h := &proxyHandler{cfg: &config{friendCode: "peepee"}}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rr := httptest.NewRecorder()

	h.serveFriendLanding(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`<div id="root"></div>`,
		`AI Pool — Full-Spectrum Signal Room`,
		`src="/assets/`,
		`href="/assets/`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected React signal room to contain %q", want)
		}
	}
	for _, unwanted := range []string{`id="access-form"`, `onclick="switchSubTab`, `id="codex-add-section"`} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("React shell still contains legacy friend markup %q", unwanted)
		}
	}
}

func TestFriendCodeIsNotEmbeddedInPublicSignalRoom(t *testing.T) {
	const secret = "friend-secret-that-must-never-ship"
	h := &proxyHandler{cfg: &config{friendCode: secret}}
	page := httptest.NewRecorder()
	h.serveFriendLanding(page, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if strings.Contains(page.Body.String(), secret) {
		t.Fatal("friend code leaked into public HTML")
	}
	if err := fs.WalkDir(signalRoomContent, "web/dist", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := signalRoomContent.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), secret) {
			t.Fatalf("friend code leaked into embedded asset %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestServeSignalRoomAsset(t *testing.T) {
	h := &proxyHandler{cfg: &config{friendCode: "peepee"}}
	page := httptest.NewRecorder()
	h.serveFriendLanding(page, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	body := page.Body.String()
	start := strings.Index(body, `src="/assets/`)
	if start < 0 {
		t.Fatal("signal room script asset missing")
	}
	start += len(`src="`)
	end := strings.Index(body[start:], `"`)
	if end < 0 {
		t.Fatal("signal room script asset is malformed")
	}
	assetPath := body[start : start+end]

	rr := httptest.NewRecorder()
	h.serveSignalRoomAsset(rr, httptest.NewRequest(http.MethodGet, "http://example.com"+assetPath, nil))
	if rr.Code != http.StatusOK || rr.Body.Len() == 0 {
		t.Fatalf("asset response status=%d bytes=%d", rr.Code, rr.Body.Len())
	}
	if got := rr.Header().Get("Content-Type"); !strings.Contains(got, "javascript") {
		t.Fatalf("Content-Type = %q, want JavaScript", got)
	}
	if got := rr.Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Fatalf("Cache-Control = %q, want immutable", got)
	}
}

func TestServeHeroImageWebP(t *testing.T) {
	h := &proxyHandler{}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/hero.webp", nil)
	rr := httptest.NewRecorder()

	h.serveHeroImage(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := rr.Header().Get("Content-Type"); got != "image/webp" {
		t.Fatalf("Content-Type = %q, want image/webp", got)
	}
	body := rr.Body.Bytes()
	if len(body) < 12 || string(body[:4]) != "RIFF" || string(body[8:12]) != "WEBP" {
		t.Fatalf("hero response is not WebP: %q", body[:min(len(body), 12)])
	}
}

func TestServeCuteCodeSetupScript_Bash(t *testing.T) {
	secret := "test-secret-key-12345678901234567890"
	t.Setenv("POOL_JWT_SECRET", secret)
	t.Setenv("PUBLIC_URL", "")

	h := &proxyHandler{poolUsers: newTestPoolUserStoreWithUser(t, "tok-cute")}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/setup/cute-code/tok-cute", nil)
	rr := httptest.NewRecorder()
	h.serveCuteCodeSetupScript(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"https://git.irrigate.cc/pp/cute-code/raw/branch/main/install.sh",
		"/config/cute-code/tok-cute",
		"CLAUDE_DIR=\"${CLAUDE_CONFIG_DIR:-$HOME/.claude}\"",
		"cute-code --model gpt-5.6-sol",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected cute-code bash setup to contain %q, got:\n%s", want, body)
		}
	}
}

func TestServeCuteCodeSetupScript_PowerShell(t *testing.T) {
	secret := "test-secret-key-12345678901234567890"
	t.Setenv("POOL_JWT_SECRET", secret)
	t.Setenv("PUBLIC_URL", "")

	h := &proxyHandler{poolUsers: newTestPoolUserStoreWithUser(t, "tok-cute-ps")}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/setup/cute-code/tok-cute-ps?shell=powershell", nil)
	rr := httptest.NewRecorder()
	h.serveCuteCodeSetupScript(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"https://git.irrigate.cc/pp/cute-code/raw/branch/main/install.ps1",
		"/config/cute-code/tok-cute-ps",
		"$claudeDir = $env:CLAUDE_CONFIG_DIR",
		"cute-code --model gpt-5.6-sol",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected cute-code PowerShell setup to contain %q, got:\n%s", want, body)
		}
	}
}

func TestServeCuteCodeSettingsConfig(t *testing.T) {
	secret := "test-secret-key-12345678901234567890"
	t.Setenv("POOL_JWT_SECRET", secret)
	t.Setenv("PUBLIC_URL", "")

	h := &proxyHandler{poolUsers: newTestPoolUserStoreWithUser(t, "tok-cute-config")}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/config/cute-code/tok-cute-config", nil)
	rr := httptest.NewRecorder()
	h.serveCuteCodeSettingsConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`"openaiBaseUrl": "http://example.com"`,
		`"anthropicBaseUrl": "http://example.com"`,
		`"openaiApiKey": "sk-ant-oat01-pool-`,
		`"model": "gpt-5.6-sol"`,
		`"id": "gpt-5.6-sol"`,
		`"id": "gpt-5.5"`,
		`"id": "claude-fable-5"`,
		`"id": "claude-opus-4-8"`,
		`"id": "MiniMax-M3"`,
		`"id": "MiniMax-M2.7"`,
		`"id": "glm-5.2"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected cute-code config to contain %q, got:\n%s", want, body)
		}
	}
	for _, forbidden := range []string{"remoteCompactForAnthropic", "remoteCompactModel"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("cute-code config should not contain %q, got:\n%s", forbidden, body)
		}
	}
}

func TestServeClaudeSetupScript_BashClearsConflictingClaudeAuth(t *testing.T) {
	secret := "test-secret-key-12345678901234567890"
	t.Setenv("POOL_JWT_SECRET", secret)
	t.Setenv("PUBLIC_URL", "")

	tmpDir := t.TempDir()
	usersPath := filepath.Join(tmpDir, "pool_users.json")
	store, err := newPoolUserStore(usersPath)
	if err != nil {
		t.Fatalf("newPoolUserStore: %v", err)
	}

	user := &PoolUser{ID: "user789", Token: "tok789", Email: "test3@example.com", PlanType: "pro", CreatedAt: time.Now()}
	if err := store.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	h := &proxyHandler{poolUsers: store}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/setup/claude/tok789", nil)
	rr := httptest.NewRecorder()
	h.serveClaudeSetupScript(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"CONFLICTING_ENV_VARS=(",
		"unset ANTHROPIC_AUTH_TOKEN",
		"unset ANTHROPIC_API_KEY",
		"CLAUDE_DIR=\"${CLAUDE_CONFIG_DIR:-$HOME/.claude}\"",
		"delete settings.apiKeyHelper;",
		"settings.pop('apiKeyHelper', None)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected bash script to contain %q, got:\n%s", want, body)
		}
	}
}

func TestServeClaudeSetupScript_PowerShell(t *testing.T) {
	secret := "test-secret-key-12345678901234567890"
	t.Setenv("POOL_JWT_SECRET", secret)

	// Ensure env is not contaminated by user-specific settings during test runs.
	t.Setenv("PUBLIC_URL", "")

	tmpDir := t.TempDir()
	usersPath := filepath.Join(tmpDir, "pool_users.json")
	store, err := newPoolUserStore(usersPath)
	if err != nil {
		t.Fatalf("newPoolUserStore: %v", err)
	}

	user := &PoolUser{
		ID:        "user456",
		Token:     "tok456",
		Email:     "test2@example.com",
		PlanType:  "pro",
		CreatedAt: time.Now(),
	}
	if err := store.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	h := &proxyHandler{poolUsers: store}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/setup/claude/tok456?shell=powershell", nil)
	rr := httptest.NewRecorder()
	h.serveClaudeSetupScript(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain*", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "$env:ANTHROPIC_BASE_URL = $BaseUrl") {
		t.Fatalf("expected PowerShell env setup in body, got:\n%s", body)
	}
	for _, want := range []string{
		"[Environment]::SetEnvironmentVariable('CLAUDE_CODE_OAUTH_TOKEN', $OAuthToken, 'User')",
		"[Environment]::SetEnvironmentVariable($name, $null, 'User')",
		"Remove-ObjectProperty -Object $settings -Name 'apiKeyHelper'",
		"foreach ($name in $conflictingEnvVars) { Remove-ObjectProperty -Object $envObj -Name $name }",
		"$claudeDir = $env:CLAUDE_CONFIG_DIR",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected PowerShell script to contain %q, got:\n%s", want, body)
		}
	}
	if !strings.Contains(body, "ConvertTo-Json -Depth 10") {
		t.Fatalf("expected PowerShell JSON update logic in body, got:\n%s", body)
	}
	if strings.Contains(body, "`") {
		t.Fatalf("PowerShell script should not contain backticks (Go raw string safety), got:\n%s", body)
	}
}
