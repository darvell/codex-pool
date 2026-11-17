package main

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
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

func TestCodexSetupCatalogFailure(t *testing.T) {
	catalog, err := json.Marshal(map[string]any{
		"models": []any{claudeModelEntry("gpt-6-astra", "gpt-6-astra", 200000)},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"fresh", "missing catalog", "existing catalog"} {
		t.Run(state, func(t *testing.T) {
			home := t.TempDir()
			authDir := filepath.Join(home, ".codex")
			if err := os.MkdirAll(authDir, 0o700); err != nil {
				t.Fatal(err)
			}
			configFile := filepath.Join(authDir, "config.toml")
			catalogFile := filepath.Join(authDir, "model_catalog.json")
			initialConfig := ""
			if state != "fresh" {
				initialConfig = "model_provider = \"codex-pool\"\nmodel_catalog_json = \"" + catalogFile + "\"\n"
				if err := os.WriteFile(configFile, []byte(initialConfig), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			oldCatalog := string(catalog) + "\n"
			if state == "existing catalog" {
				if err := os.WriteFile(catalogFile, []byte(oldCatalog), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			var catalogStatus atomic.Int32
			catalogStatus.Store(http.StatusServiceUnavailable)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/config/codex/token":
					w.Write([]byte(`{"tokens":{"access_token":"test-token"}}`))
				case "/backend-api/codex/models":
					if r.Header.Get("Authorization") != "Bearer test-token" {
						t.Error("catalog request missing pool authorization")
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					w.WriteHeader(int(catalogStatus.Load()))
					w.Write(catalog)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			h := &proxyHandler{}
			rr := httptest.NewRecorder()
			h.serveCodexSetupScript(rr, httptest.NewRequest(http.MethodGet, server.URL+"/setup/codex/token", nil))
			run := func() ([]byte, error) {
				cmd := exec.Command("bash", "-s")
				cmd.Stdin = strings.NewReader(rr.Body.String())
				cmd.Env = append(os.Environ(), "HOME="+home, "CODEX_HOME="+authDir)
				return cmd.CombinedOutput()
			}
			output, err := run()
			if err == nil || strings.Contains(string(output), "Setup complete!") {
				t.Fatalf("failed catalog download reported success: %v\n%s", err, output)
			}
			data, err := os.ReadFile(configFile)
			if state == "fresh" {
				if !os.IsNotExist(err) {
					t.Fatalf("failed setup created config: %v\n%s", err, data)
				}
			} else if err != nil || string(data) != initialConfig {
				t.Fatalf("failed setup changed config: %v\n%s", err, data)
			}
			data, err = os.ReadFile(catalogFile)
			if state == "existing catalog" {
				if err != nil || string(data) != oldCatalog {
					t.Fatalf("failed download replaced catalog: %v\n%s", err, data)
				}
			} else if !os.IsNotExist(err) {
				t.Fatalf("failed download left a catalog: %v\n%s", err, data)
			}
			if files, err := filepath.Glob(catalogFile + ".tmp.*"); err != nil || len(files) != 0 {
				t.Fatalf("download temporary files remain: %v, %v", files, err)
			}

			catalogStatus.Store(http.StatusOK)
			if output, err := run(); err != nil {
				t.Fatalf("retry after recovery: %v\n%s", err, output)
			}
			if data, err := os.ReadFile(catalogFile); err != nil || string(data) != string(catalog) {
				t.Fatalf("retry did not install catalog: %v\n%s", err, data)
			}
			if data, err := os.ReadFile(configFile); err != nil || !strings.Contains(string(data), `model_catalog_json = "`+catalogFile+`"`) {
				t.Fatalf("retry did not configure catalog: %v\n%s", err, data)
			}
		})
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
	t.Setenv("PUBLIC_URL", "")
	h := &proxyHandler{}
	rr := httptest.NewRecorder()
	h.serveCodexSetupScript(rr, httptest.NewRequest(http.MethodGet, "http://example.com/setup/codex/token", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("setup status = %d", rr.Code)
	}

	for _, tc := range []struct{ name, initial, want string }{
		{"fresh", "", "gpt-6-astra"},
		{"selected", "model = \"gpt-5.6-sol\"\n", "gpt-5.6-sol"},
		{"pool update", "model_provider = \"codex-pool\"\n", "gpt-6-astra"},
		{"pool selection", "model = \"gpt-5.6-luna\"\nmodel_provider = \"codex-pool\"\n", "gpt-5.6-luna"},
		{"profile only", "[profiles.fast]\nmodel = \"gpt-5.6-luna\"\n", "gpt-6-astra"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			authDir := filepath.Join(home, ".codex")
			if err := os.MkdirAll(authDir, 0o700); err != nil {
				t.Fatal(err)
			}
			configFile := filepath.Join(authDir, "config.toml")
			if tc.initial != "" {
				if err := os.WriteFile(configFile, []byte(tc.initial), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			env := setupTestEnv(t, home, map[string]string{
				"http://example.com/config/codex/token":                              `{"tokens":{"access_token":"test-access-token"}}`,
				"http://example.com/backend-api/codex/models?client_version=0.125.0": `{"models":[]}`,
			})
			var firstConfig string
			for run := range 2 {
				cmd := exec.Command("bash", "-s")
				cmd.Stdin = strings.NewReader(rr.Body.String())
				cmd.Env = env
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("configure: %v\n%s", err, output)
				}
				data, err := os.ReadFile(configFile)
				if err != nil {
					t.Fatal(err)
				}
				config := string(data)
				root := strings.SplitN(config, "[", 2)[0]
				if !strings.Contains(root, `model = "`+tc.want+`"`) || strings.Count(root, "model =") != 1 {
					t.Fatalf("expected one root model %q:\n%s", tc.want, data)
				}
				if tc.initial != "" && !strings.Contains(config, tc.initial) {
					t.Fatalf("existing configuration changed:\n%s", data)
				}
				for _, want := range []string{
					`model_catalog_json = "` + filepath.Join(authDir, "model_catalog.json") + `"`,
					`experimental_realtime_webrtc_call_base_url = "http://example.com/v1"`,
					`experimental_realtime_ws_base_url = "http://example.com/v1"`,
					`realtime.version = "v3"`, `realtime.transport = "webrtc"`, `[mcp_servers.model_sync]`,
				} {
					if !strings.Contains(config, want) {
						t.Fatalf("installed config missing %q:\n%s", want, data)
					}
				}
				if run == 0 {
					firstConfig = config
				} else if config != firstConfig {
					t.Fatalf("repeated setup changed configuration:\n%s", data)
				}
			}
			if data, err := os.ReadFile(filepath.Join(authDir, "auth.json")); err != nil || string(data) != `{"tokens":{"access_token":"test-access-token"}}` {
				t.Fatalf("installed auth = %s, %v", data, err)
			}
			if data, err := os.ReadFile(filepath.Join(authDir, "model_catalog.json")); err != nil || string(data) != `{"models":[]}` {
				t.Fatalf("installed catalog = %s, %v", data, err)
			}
			if info, err := os.Stat(filepath.Join(authDir, "model_sync.sh")); err != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("MCP sidecar executable missing: %v", err)
			}
		})
	}
}

func TestSetupExamplesUseAstra(t *testing.T) {
	h := &proxyHandler{cfg: &config{}}
	rr := httptest.NewRecorder()
	h.serveFriendLanding(rr, httptest.NewRequest(http.MethodGet, "http://example.com/friend", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("friend page status = %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{`model="gpt-6-astra"`, `"model":"gpt-6-astra"`, "cute-code --model gpt-6-astra"} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered onboarding example missing %q", want)
		}
	}
	for _, stale := range []string{`model="gpt-5.6-luna"`, `model="gpt-5.6-sol"`, `model: "gpt-5.6-sol"`, `"model":"gpt-5.6-sol"`, "cute-code --model gpt-5.6-sol", "Use gpt-5.6-luna as the first smoke-test model"} {
		if strings.Contains(body, stale) {
			t.Errorf("rendered onboarding retains stale example %q", stale)
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
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is unavailable")
	}
	t.Setenv("PUBLIC_URL", "")
	h := &proxyHandler{}
	for _, target := range []string{
		"http://example.com/setup/pi/testtoken",
		"http://example.com/setup/pi/testtoken?shell=powershell",
	} {
		rr := httptest.NewRecorder()
		h.servePiSetupScript(rr, httptest.NewRequest(http.MethodGet, target, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status = %d", target, rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, "/config/pi/testtoken") || !strings.Contains(body, "providers") {
			t.Fatalf("%s did not generate a merging Pi installer", target)
		}
		if strings.Contains(target, "powershell") {
			continue
		}
		home := t.TempDir()
		dir := filepath.Join(home, ".pi", "agent")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		modelsFile := filepath.Join(dir, "models.json")
		if err := os.WriteFile(modelsFile, []byte(`{"defaultModel":"personal/model","providers":{"personal":{"baseUrl":"https://personal.test","apiKey":"personal-key"},"codex-pool":{"apiKey":"old-pool-key"}}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		env := setupTestEnv(t, home, map[string]string{
			"http://example.com/config/pi/testtoken": `{"providers":{"codex-pool":{"apiKey":"new-pool-key","models":[{"id":"gpt-6-astra"}]},"pool-claude":{"apiKey":"claude-key"}}}`,
		})
		var first string
		for run := range 2 {
			cmd := exec.Command("bash", "-s")
			cmd.Stdin = strings.NewReader(body)
			cmd.Env = env
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("merge Pi providers: %v\n%s", err, output)
			}
			data, err := os.ReadFile(modelsFile)
			if err != nil {
				t.Fatal(err)
			}
			var got, want any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(`{"defaultModel":"personal/model","providers":{"personal":{"baseUrl":"https://personal.test","apiKey":"personal-key"},"codex-pool":{"apiKey":"new-pool-key","models":[{"id":"gpt-6-astra"}]},"pool-claude":{"apiKey":"claude-key"}}}`), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("merged Pi settings = %s", data)
			}
			if run == 0 {
				first = string(data)
			} else if string(data) != first {
				t.Fatalf("repeated Pi setup changed providers: %s", data)
			}
		}
		if info, err := os.Stat(modelsFile); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("Pi models file permissions: %v", err)
		}
	}
}

func TestServeGeminiSetupScript_PowerShell(t *testing.T) {
	t.Setenv("PUBLIC_URL", "")
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

	geminiAuth, err := generateGeminiAuth(secret, user)
	if err != nil {
		t.Fatal(err)
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
	for _, want := range []string{
		"#requires -Version 5.1", "$BaseUrl = 'http://example.com'", "$PoolToken = '" + geminiAuth.AccessToken + "'",
		"$utf8 = New-Object System.Text.UTF8Encoding($false)",
		"$env:GOOGLE_GENAI_USE_GCA = '1'", "$env:GOOGLE_CLOUD_ACCESS_TOKEN = $PoolToken",
		"$profilePath = $PROFILE.CurrentUserAllHosts",
		"[System.IO.File]::WriteAllText($Path, $Value, $utf8)",
		"Set-Utf8NoBom -Path $profilePath -Value $updated",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("PowerShell Gemini setup missing %q", want)
		}
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
		`"id": "claude-opus-5-5"`,
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
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is unavailable")
	}
	t.Setenv("POOL_JWT_SECRET", "test-secret-key-12345678901234567890")
	t.Setenv("PUBLIC_URL", "")
	h := &proxyHandler{poolUsers: newTestPoolUserStoreWithUser(t, "tok789")}
	rr := httptest.NewRecorder()
	h.serveClaudeSetupScript(rr, httptest.NewRequest(http.MethodGet, "http://example.com/setup/claude/tok789", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("setup status = %d", rr.Code)
	}
	auth, err := generateClaudeAuth(h.cfg.poolJWTSecret(), h.userForSetup("tok789"))
	if err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	env := setupTestEnv(t, home, nil)
	claudeDir := filepath.Join(home, "claude-config")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	conflicting := []string{"ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY", "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST", "ANTHROPIC_UNIX_SOCKET", "CLAUDE_CODE_SIMPLE"}
	settingsEnv := map[string]string{"KEEP_ME": "kept", "ANTHROPIC_BASE_URL": "https://old.test", "CLAUDE_CODE_OAUTH_TOKEN": "old-token"}
	profile := "export KEEP_ME=kept\nexport ANTHROPIC_BASE_URL=https://old.test\nexport CLAUDE_CODE_OAUTH_TOKEN=old-token\n"
	for _, name := range conflicting {
		settingsEnv[name] = "conflicting-value"
		profile += "export " + name + "=conflicting-value\n"
		env = append(env, name+"=conflicting-value")
	}
	settingsFile := filepath.Join(claudeDir, "settings.json")
	settings, err := json.Marshal(map[string]any{"apiKeyHelper": "old-helper", "env": settingsEnv, "theme": "dark"})
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{
		settingsFile:                        settings,
		filepath.Join(home, ".bashrc"):      []byte(profile),
		filepath.Join(home, ".claude.json"): []byte(`{"hasCompletedOnboarding":false,"theme":"dark"}`),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(home, "setup.sh")
	if err := os.WriteFile(script, rr.Body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		for _, shell := range []struct{ name, command string }{
			{"sourced setup", `source "$1" >/dev/null; node -e 'console.log(JSON.stringify(process.env))'`},
			{"saved profile", `source "$HOME/.bashrc"; node -e 'console.log(JSON.stringify(process.env))'`},
		} {
			cmd := exec.Command("bash", "-ec", shell.command, "setup-test", script)
			cmd.Env = append(env, "KEEP_ME=kept")
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s: %v\n%s", shell.name, err, output)
			}
			var current map[string]string
			if err := json.Unmarshal(output, &current); err != nil {
				t.Fatalf("%s environment: %v\n%s", shell.name, err, output)
			}
			for _, name := range conflicting {
				if _, exists := current[name]; exists {
					t.Errorf("%s retains conflicting variable %s", shell.name, name)
				}
			}
			if current["ANTHROPIC_BASE_URL"] != "http://example.com" || current["CLAUDE_CODE_OAUTH_TOKEN"] != auth.AccessToken || current["KEEP_ME"] != "kept" {
				t.Fatalf("%s lost unrelated settings or did not use pool credentials", shell.name)
			}
		}
		data, err := os.ReadFile(settingsFile)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"theme": "dark", "env": map[string]any{"KEEP_ME": "kept", "ANTHROPIC_BASE_URL": "http://example.com", "CLAUDE_CODE_OAUTH_TOKEN": auth.AccessToken}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Claude settings do not preserve unrelated values and remove conflicting auth: %s", data)
		}
		data, err = os.ReadFile(filepath.Join(home, ".claude.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if got["hasCompletedOnboarding"] != true || got["theme"] != "dark" {
			t.Fatalf("Claude onboarding settings = %s", data)
		}
		data, err = os.ReadFile(filepath.Join(home, ".bashrc"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(data), "export ANTHROPIC_BASE_URL=") != 1 || strings.Count(string(data), "export CLAUDE_CODE_OAUTH_TOKEN=") != 1 || !strings.Contains(string(data), "export KEEP_ME=kept") {
			t.Fatal("profile must retain unrelated settings and one assignment per pool credential")
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("custom CLAUDE_CONFIG_DIR ignored: %v", err)
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

	claudeAuth, err := generateClaudeAuth(secret, user)
	if err != nil {
		t.Fatal(err)
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
	for _, want := range []string{
		"#requires -Version 5.1", "$BaseUrl = 'http://example.com'", "$OAuthToken = '" + claudeAuth.AccessToken + "'",
		"$utf8 = New-Object System.Text.UTF8Encoding($false)",
		"$profilePath = $PROFILE.CurrentUserAllHosts",
		"[System.IO.File]::WriteAllText($Path, $Value, $utf8)",
		"Set-Utf8NoBom -Path $profilePath -Value $updated",
		"Set-Utf8NoBom -Path $settingsFile -Value ($settings | ConvertTo-Json -Depth 10)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("PowerShell Claude setup missing %q", want)
		}
	}
}
