package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const kimiCatalogFixture = `{"data":[
	{"id":"k3.1-pro","display_name":"K3.1 Pro","context_length":1048576,"supports_reasoning":true,"supports_image_in":true,"supports_video_in":true},
	{"id":"k3.1-pro-highspeed","display_name":"K3.1 Pro Highspeed","context_length":1048576,"supports_reasoning":true,"supports_image_in":true,"supports_video_in":true},
	{"id":"kimi-for-coding","display_name":"K2.8 Preview","context_length":1048576,"supports_reasoning":true,"supports_image_in":true,"supports_video_in":true},
	{"id":"kimi-future-fixture","display_name":"Future fixture","context_length":524288,"supports_reasoning":true}
]}`

func TestKimiDiscoveredRouting(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "kimi-test-secret")
	models, err := parseProviderModels([]byte(kimiCatalogFixture))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"k3.1-pro", "k3.1-pro-highspeed", "kimi-future-fixture"} {
		for _, mode := range []string{"buffered", "chunked"} {
			t.Run(id+"/"+mode, func(t *testing.T) {
				called := false
				h := preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
					called = true
					if req.URL.String() != "https://api.kimi.test/coding/v1/messages" || req.Header.Get("Authorization") != "Bearer kimi-fixture" {
						t.Errorf("request dispatched to wrong upstream: %s", req.URL)
					}
					var body struct {
						Model string `json:"model"`
					}
					if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					if body.Model != id {
						t.Errorf("upstream model = %q, want %q", body.Model, id)
					}
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"id":"msg_fixture","type":"message","role":"assistant","content":[{"type":"text","text":"OK"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":1}}`))}, nil
				}))
				h.registry = NewProviderRegistry(NewCodexProvider(mustParse("https://codex.test"), nil, nil), NewClaudeProvider(mustParse("https://claude.test")), nil, NewKimiProvider(mustParse("https://api.kimi.test/coding")))
				h.pool = newPoolState([]*Account{
					{ID: "unentitled", Type: AccountTypeKimi, AccessToken: "wrong-fixture", Models: map[string]DiscoveredModel{"k3": {ID: "k3"}}},
					{ID: "entitled", Type: AccountTypeKimi, AccessToken: "kimi-fixture", Models: models},
				}, false)
				payload := fmt.Sprintf(`{"model":%q,"max_tokens":1024,"messages":[{"role":"user","content":"Reply OK"}]}`, strings.ToUpper(id))
				req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(payload))
				req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("kimi-test-secret", "kimi-user"))
				req.Header.Set("Content-Type", "application/json")
				if mode == "chunked" {
					req.ContentLength = -1
				}
				w := httptest.NewRecorder()
				h.proxyRequest(w, req, "kimi-discovery")
				if !called || w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"OK"`) {
					t.Fatalf("called=%v status=%d body=%s", called, w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestKimiLiveCatalogExports(t *testing.T) {
	models, err := parseProviderModels([]byte(kimiCatalogFixture))
	if err != nil {
		t.Fatal(err)
	}
	pool := newPoolState([]*Account{{ID: "kimi", Type: AccountTypeKimi, Models: models}}, false)
	found := make(map[string]poolModelDescriptor)
	for _, model := range poolModelDescriptors(pool) {
		if model.Provider == string(AccountTypeKimi) {
			found[model.ID] = model
		}
	}
	for id, live := range models {
		got, ok := found[id]
		if !ok || got.Name != live.DisplayName || got.ContextWindow != live.ContextWindow || !got.Capabilities["reasoning"] || got.AvailableAccounts != 1 {
			t.Errorf("catalog %s = %+v, want live metadata %+v", id, got, live)
		}
	}
	for _, id := range []string{"k3.1-pro", "k3.1-pro-highspeed"} {
		if !containsString(found[id].Modalities, "image") || !containsString(found[id].Modalities, "video") {
			t.Errorf("modalities for %s = %v", id, found[id].Modalities)
		}
	}
	piJSON, err := generatePiModelsJSON("https://pool.test", "fixture", "fixture", pool)
	if err != nil {
		t.Fatal(err)
	}
	var pi piModelsConfig
	if err := json.Unmarshal(piJSON, &pi); err != nil {
		t.Fatal(err)
	}
	piFound := make(map[string]piModelConfig)
	for _, model := range pi.Providers["kimi"].Models {
		piFound[model.ID] = model
	}
	cuteJSON, err := generateCuteCodeSettingsJSON("https://pool.test", "fixture", pool)
	if err != nil {
		t.Fatal(err)
	}
	var cute cuteCodeSettings
	if err := json.Unmarshal(cuteJSON, &cute); err != nil {
		t.Fatal(err)
	}
	cuteFound := make(map[string]cuteCodeModelConfig)
	for _, model := range cute.CustomModels {
		cuteFound[model.ID] = model
	}
	for id, live := range models {
		if got := piFound[id]; got.Name != live.DisplayName || got.ContextWindow != live.ContextWindow {
			t.Errorf("Pi %s = %+v", id, got)
		}
		if got := cuteFound[id]; got.Name != live.DisplayName || got.ContextWindow != live.ContextWindow {
			t.Errorf("settings %s = %+v", id, got)
		}
	}
}

func TestKimiCatalogSyncAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kimi.json")
	if err := os.WriteFile(path, []byte(`{"api_key":"fixture"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := NewKimiProvider(mustParse("https://api.kimi.test/coding"))
	registry := NewProviderRegistry(nil, nil, nil, provider)
	account := &Account{ID: "kimi", Type: AccountTypeKimi, File: path, AccessToken: "fixture"}
	catalog := kimiCatalogFixture
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(catalog))}, nil
	})
	if err := syncProviderModels(context.Background(), transport, registry, account); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := provider.LoadAccount("kimi.json", path, raw)
	if err != nil {
		t.Fatal(err)
	}
	applyCommonAccountFileState(reloaded, raw)
	if len(reloaded.Models) != 4 || reloaded.ModelsFetchedAt.IsZero() {
		t.Fatalf("reloaded catalog = %+v", reloaded.Models)
	}
	catalog = `{"error":"temporarily unavailable"}`
	if err := syncProviderModels(context.Background(), transport, registry, account); err == nil {
		t.Fatal("invalid discovery response accepted")
	}
	if len(account.Models) != 4 {
		t.Fatal("failed refresh discarded the previous catalog")
	}
	catalog = `{"data":[{"id":"k3.1-pro"}]}`
	if err := syncProviderModels(context.Background(), transport, registry, account); err != nil {
		t.Fatal(err)
	}
	if len(account.Models) != 1 || account.Models["k3.1-pro"].ID == "" {
		t.Fatalf("catalog refresh = %+v", account.Models)
	}
}

func TestKimiAdmissionSavesCatalog(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/coding/v1/models" || r.Header.Get("Authorization") != "Bearer fixture" {
			t.Errorf("unexpected validation request: %s", r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, kimiCatalogFixture)
	}))
	defer upstream.Close()
	base := mustParse(upstream.URL + "/coding")
	h := &proxyHandler{cfg: &config{poolDir: t.TempDir(), kimiBase: base}, registry: NewProviderRegistry(nil, nil, nil, NewKimiProvider(base)), pool: newPoolState(nil, false), transport: http.DefaultTransport}
	req := httptest.NewRequest(http.MethodPost, "/admin/kimi/add", strings.NewReader(`{"api_key":"fixture"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.handleKimiAdd(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("admission status=%d body=%s", w.Code, w.Body.String())
	}
	accounts := h.pool.allAccounts()
	if len(accounts) != 1 || len(accounts[0].Models) != 4 || time.Since(accounts[0].ModelsFetchedAt) > time.Minute {
		t.Fatalf("admitted accounts = %+v", accounts)
	}
}
