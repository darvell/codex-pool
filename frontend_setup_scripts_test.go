package main

import (
	"net/http"
	"net/http/httptest"
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
	for _, want := range []string{"codex pool + cute-code", "Generate setup", "cute-code --model gpt-5.5"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected cute-code landing to contain %q, got:\n%s", want, body)
		}
	}
}

func TestFriendLandingIncludesCuteCodeSetup(t *testing.T) {
	h := &proxyHandler{cfg: &config{friendCode: "peepee"}}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rr := httptest.NewRecorder()

	h.serveFriendLanding(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	for _, want := range []string{"data-tab=\"cute-code\"", "cute-code-install-unix", "cute_code_settings_json"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected friend landing cute-code setup to contain %q, got:\n%s", want, body)
		}
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
		"cute-code --model gpt-5.5",
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
		"cute-code --model gpt-5.5",
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
		`"id": "gpt-5.5"`,
		`"id": "claude-opus-4-7"`,
		`"id": "MiniMax-M2.7"`,
		`"id": "glm-5.1"`,
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
