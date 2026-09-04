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
	for _, setting := range []string{
		"experimental_realtime_webrtc_call_base_url",
		"experimental_realtime_ws_base_url",
		`realtime.version = "v3"`,
		`realtime.transport = "webrtc"`,
	} {
		if !strings.Contains(body, setting) {
			t.Fatalf("expected %s in PowerShell setup script", setting)
		}
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
	if !strings.Contains(body, "features enable realtime_conversation") {
		t.Fatal("expected PowerShell setup to enable realtime_conversation")
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
	for _, setting := range []string{
		"experimental_realtime_webrtc_call_base_url",
		"experimental_realtime_ws_base_url",
		`realtime.version = "v3"`,
		`realtime.transport = "webrtc"`,
	} {
		if !strings.Contains(body, setting) {
			t.Fatalf("expected %s in bash setup script", setting)
		}
	}
	if !strings.Contains(body, "[mcp_servers.model_sync]") {
		t.Fatalf("expected MCP sidecar config in bash script body, got:\n%s", body)
	}
	if !strings.Contains(body, "MCP_TRANSPORT_MODE=\"jsonl\"") {
		t.Fatalf("expected MCP JSONL transport support in bash body, got:\n%s", body)
	}
	if !strings.Contains(body, "features enable realtime_conversation") {
		t.Fatal("expected bash setup to enable realtime_conversation")
	}
}

func TestCodexSetupDefaultModel(t *testing.T) {
	h := &proxyHandler{}
	for _, shell := range []string{"bash", "powershell"} {
		rr := httptest.NewRecorder()
		h.serveCodexSetupScript(rr, httptest.NewRequest(http.MethodGet, "http://example.com/setup/codex/token?shell="+shell, nil))
		if !strings.Contains(rr.Body.String(), `model = "gpt-6-astra"`) {
			t.Fatalf("%s setup is missing the Astra default", shell)
		}
	}
}

func TestCodexSetupPreservesModel(t *testing.T) {
	h := &proxyHandler{}
	rr := httptest.NewRecorder()
	h.serveCodexSetupScript(rr, httptest.NewRequest(http.MethodGet, "http://example.com/setup/codex/token", nil))
	body := rr.Body.String()
	start := strings.Index(body, `echo "4. Updating configuration..."`)
	end := strings.Index(body, "if command -v codex >/dev/null")
	if start < 0 || end <= start {
		t.Fatal("configuration section missing")
	}

	for _, tc := range []struct{ name, initial, want string }{
		{"fresh", "", "gpt-6-astra"},
		{"selected", "model = \"gpt-5.6-sol\"\n", "gpt-5.6-sol"},
		{"pool update", "model_provider = \"codex-pool\"\n", "gpt-6-astra"},
		{"pool selection", "model = \"gpt-5.6-luna\"\nmodel_provider = \"codex-pool\"\n", "gpt-5.6-luna"},
		{"profile only", "[profiles.fast]\nmodel = \"gpt-5.6-luna\"\n", "gpt-6-astra"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			configFile := filepath.Join(dir, "config.toml")
			if err := os.WriteFile(configFile, []byte(tc.initial), 0o600); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				cmd := exec.Command("bash", "-eu")
				cmd.Stdin = strings.NewReader(body[start:end])
				cmd.Env = append(os.Environ(), "CONFIG_FILE="+configFile, "BASE_URL=http://example.com", "MODEL_CATALOG="+filepath.Join(dir, "models.json"), "MCP_SCRIPT="+filepath.Join(dir, "sync.sh"))
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("configure: %v\n%s", err, output)
				}
			}
			data, err := os.ReadFile(configFile)
			if err != nil {
				t.Fatal(err)
			}
			root := strings.SplitN(string(data), "[", 2)[0]
			if !strings.Contains(root, `model = "`+tc.want+`"`) || strings.Count(root, "model =") != 1 {
				t.Fatalf("expected one root model %q:\n%s", tc.want, data)
			}
			if tc.initial != "" && !strings.Contains(string(data), tc.initial) {
				t.Fatalf("existing configuration changed:\n%s", data)
			}
		})
	}
}

func TestSetupExamplesUseAstra(t *testing.T) {
	for _, path := range []string{"templates/friend_landing.html", "web/src/App.tsx"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		body := string(data)
		if !strings.Contains(body, "gpt-6-astra") {
			t.Errorf("%s has no Astra onboarding example", path)
		}
		for _, stale := range []string{`model="gpt-5.6-luna"`, `model="gpt-5.6-sol"`, `model: "gpt-5.6-sol"`, `"model":"gpt-5.6-sol"`, "cute-code --model gpt-5.6-sol", "Use gpt-5.6-luna as the first smoke-test model"} {
			if strings.Contains(body, stale) {
				t.Errorf("%s retains stale onboarding example %q", path, stale)
			}
		}
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
	for _, want := range []string{"[endpoints]", `models_base_url = \"`, `[model."%s"]`, "grok-4.5", "gpt-5.6-luna", "claude-sonnet-5", "auth.json.before-codex-pool", "/config/grok/$TOKEN"} {
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
	initial := "[cli]\nauto_update = true\n\n[models]\ndefault = \"grok-4.5\"\n"
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
	for _, want := range []string{"[cli]", "auto_update = true", `default = "grok-4.5"`, `[endpoints]`, `models_base_url = "http://example.com/v1"`, `api_key = "pool-jwt"`} {
		if !strings.Contains(config, want) {
			t.Fatalf("installed config missing %q:\n%s", want, config)
		}
	}
	if strings.Contains(config, "codex-pool-grok") {
		t.Fatalf("installer must not create or select a synthetic model:\n%s", config)
	}
	if count := strings.Count(config, `[model."grok-4.5"]`); count != 1 {
		t.Fatalf("grok-4.5 credential override count = %d, want 1:\n%s", count, config)
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

func TestFriendLandingServesOldTemplate(t *testing.T) {
	h := &proxyHandler{cfg: &config{legacyFriendCode: "peepee"}}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/friend", nil)
	rr := httptest.NewRecorder()

	h.serveFriendLanding(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`Friends of`,
		`friend_code`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected friend landing to contain %q", want)
		}
	}
}

func TestPassportSPAServesReactSignalRoom(t *testing.T) {
	h := &proxyHandler{cfg: &config{legacyFriendCode: "peepee"}}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/app", nil)
	rr := httptest.NewRecorder()

	h.servePassportSPA(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`<div id="root"></div>`,
		`AI Pool`,
		`src="/assets/`,
		`href="/assets/`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected Passport SPA to contain %q", want)
		}
	}
}

func TestFriendCodeIsNotEmbeddedInPublicSignalRoom(t *testing.T) {
	const secret = "friend-secret-that-must-never-ship"
	h := &proxyHandler{cfg: &config{legacyFriendCode: secret}}
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
	h := &proxyHandler{cfg: &config{legacyFriendCode: "peepee"}}
	page := httptest.NewRecorder()
	h.servePassportSPA(page, httptest.NewRequest(http.MethodGet, "http://example.com/app", nil))
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
		"cute-code --model gpt-6-astra",
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
		"cute-code --model gpt-6-astra",
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
		`"model": "gpt-6-astra"`,
		`"id": "gpt-6-astra"`,
		`"id": "gpt-5.6-sol"`,
		`"id": "gpt-5.5"`,
		`"id": "claude-fable-5-1"`,
		`"id": "claude-fable-5"`,
		`"id": "claude-opus-4-8"`,
		`"id": "claude-opus-5"`,
		`"id": "MiniMax-M3"`,
		`"id": "MiniMax-M2.7"`,
		`"id": "glm-5.3"`,
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
