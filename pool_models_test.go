package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPoolModelDescriptorsCoverEveryProvider(t *testing.T) {
	t.Parallel()

	descriptors := poolModelDescriptors()
	byID := make(map[string]poolModelDescriptor, len(descriptors))
	for _, descriptor := range descriptors {
		byID[descriptor.ID] = descriptor
	}

	tests := map[string]string{
		"gpt-5.6-sol":      "openai",
		"gpt-5.6-sol[1m]":  "openai",
		"gpt-5.6-luna[1m]": "openai",
		"gemini-3.7-flash": "gemini",
		"claude-sonnet-5":  "anthropic",
		"claude-fable-5-1": "anthropic",
		"claude-opus-5":    "anthropic",
		"k3":               "anthropic",
		"kimi-for-coding":  "anthropic",
		"MiniMax-M3":       "anthropic",
		"glm-5.3":          "anthropic",
		"glm-5.3-flash":    "anthropic",
		"mimo-v2.5-pro":    "anthropic",
		"grok-4.5":         "openai",
	}
	for id, protocol := range tests {
		descriptor, ok := byID[id]
		if !ok {
			t.Fatalf("missing model %q", id)
		}
		if descriptor.Protocol != protocol {
			t.Fatalf("model %q protocol = %q, want %q", id, descriptor.Protocol, protocol)
		}
		if descriptor.ContextWindow <= 0 {
			t.Fatalf("model %q has invalid context window %d", id, descriptor.ContextWindow)
		}
		if id == "glm-5.3" {
			if descriptor.MaxOutputTokens != 131072 {
				t.Fatalf("GLM-5.3 max output tokens = %d, want 131072", descriptor.MaxOutputTokens)
			}
			if len(descriptor.Aliases) != 1 || descriptor.Aliases[0] != "glm-5.2" {
				t.Fatalf("GLM-5.3 aliases = %#v, want [glm-5.2]", descriptor.Aliases)
			}
		}
	}
}

func TestPoolModelDescriptorsMatchCurrentProviderCatalogs(t *testing.T) {
	t.Parallel()

	byID := make(map[string]poolModelDescriptor)
	for _, descriptor := range poolModelDescriptors() {
		byID[descriptor.ID] = descriptor
	}

	if _, ok := byID["claude-opus-4-1-20250805"]; ok {
		t.Fatal("retired Claude Opus 4.1 is still advertised")
	}
	if got := byID["claude-sonnet-5"].MaxOutputTokens; got != 128000 {
		t.Fatalf("Claude Sonnet 5 max output = %d, want 128000", got)
	}
	for _, id := range []string{"k3-256k", "mimo-v2.5", "grok-4.6"} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("current model %q is missing", id)
		}
	}
	for _, id := range []string{"MiniMax-M2.7", "MiniMax-M2.7-highspeed"} {
		if slices.Contains(byID[id].Modalities, "image") {
			t.Fatalf("%s incorrectly advertises image input on the Anthropic endpoint", id)
		}
	}
	if !slices.Contains(byID["MiniMax-M3"].Modalities, "video") {
		t.Fatal("MiniMax-M3 does not advertise video input")
	}
}

func TestPoolModelDescriptorsAdvertiseVerifiedNativeWebSearchRoutes(t *testing.T) {
	t.Parallel()

	descriptors := poolModelDescriptors()
	byID := make(map[string]poolModelDescriptor, len(descriptors))
	for _, descriptor := range descriptors {
		byID[descriptor.ID] = descriptor
	}

	tests := map[string]poolNativeToolDescriptor{
		"gpt-5.6-sol": {
			Protocol: "openai-responses",
			Endpoint: "/v1/responses",
			ToolType: "web_search",
		},
		"gpt-5.6-luna": {
			Protocol: "openai-responses",
			Endpoint: "/v1/responses",
			ToolType: "web_search",
		},
		"grok-4.5": {
			Protocol: "openai-responses",
			Endpoint: "/v1/responses",
			ToolType: "web_search",
		},
		"claude-sonnet-5": {
			Protocol: "anthropic-messages",
			Endpoint: "/v1/messages",
			ToolType: "web_search_20250305",
		},
		"claude-sonnet-4-6": {
			Protocol: "anthropic-messages",
			Endpoint: "/v1/messages",
			ToolType: "web_search_20250305",
		},
		"k3": {
			Protocol: "anthropic-messages",
			Endpoint: "/v1/messages",
			ToolType: "web_search_20250305",
		},
		"mimo-v2.5-pro": {
			Protocol: "anthropic-messages",
			Endpoint: "/v1/messages",
			ToolType: "web_search_20250305",
		},
	}

	for id, want := range tests {
		descriptor, ok := byID[id]
		if !ok {
			t.Fatalf("missing model %q", id)
		}
		if !descriptor.Capabilities["web_search"] {
			t.Fatalf("model %q does not advertise web_search", id)
		}
		got, ok := descriptor.NativeTools["web_search"]
		if !ok {
			t.Fatalf("model %q has no native web_search route", id)
		}
		if got != want {
			t.Fatalf("model %q web_search route = %#v, want %#v", id, got, want)
		}
	}

	for _, id := range []string{"gpt-5.6-terra", "MiniMax-M3"} {
		descriptor := byID[id]
		if descriptor.Capabilities["web_search"] || descriptor.NativeTools["web_search"].Endpoint != "" {
			t.Fatalf("unverified model %q advertises native web search", id)
		}
	}
}

func TestPoolModelDescriptorsUseRelativeNativeToolEndpoints(t *testing.T) {
	t.Parallel()

	for _, descriptor := range poolModelDescriptors() {
		for name, tool := range descriptor.NativeTools {
			if !strings.HasPrefix(tool.Endpoint, "/") || strings.Contains(tool.Endpoint, "://") {
				t.Fatalf("model %q native tool %q has non-relative endpoint %q", descriptor.ID, name, tool.Endpoint)
			}
		}
	}
}

func TestUnifiedGeminiCatalogIncludesGeminiAccounts(t *testing.T) {
	pool := newPoolState([]*Account{{ID: "gemini", Type: AccountTypeGemini}}, false)
	recorder := httptest.NewRecorder()
	serveUnifiedGeminiModels(recorder, pool)

	var body struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, model := range body.Models {
		if model.Name == "models/gemini-3.7-flash" {
			return
		}
	}
	t.Fatal("Gemini OAuth catalog is absent from the native models endpoint")
}

func TestServePoolModelsOmitsCredentials(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	servePoolModels(recorder)

	if recorder.Code != 200 {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var response struct {
		SchemaVersion int              `json:"schema_version"`
		Models        []map[string]any `json:"models"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.SchemaVersion != poolModelsSchemaVersion {
		t.Fatalf("schema version = %d, want %d", response.SchemaVersion, poolModelsSchemaVersion)
	}
	if len(response.Models) == 0 {
		t.Fatal("models are empty")
	}
	for _, model := range response.Models {
		if _, ok := model["apiKey"]; ok {
			t.Fatalf("model %q exposed apiKey", model["id"])
		}
		if _, ok := model["baseUrl"]; ok {
			t.Fatalf("model %q exposed baseUrl", model["id"])
		}
	}
}

func TestServePoolModelsIncludesNativeGeminiProtocol(t *testing.T) {
	t.Parallel()

	antigravityModels.Reset()
	t.Cleanup(antigravityModels.Reset)
	antigravityModels.ReplaceAccount("ag-1", AntigravityAccountSnapshot{
		FetchedAt: time.Now().UTC(),
		Models: map[string]AntigravityModelInfo{
			"gemini-3.8-flash-tiered": {
				ID:            "gemini-3.8-flash-tiered",
				DisplayName:   "Gemini 3.8 Flash (Tiered)",
				SupportsTools: true,
			},
			"claude-sonnet-4-6": {
				ID:            "claude-sonnet-4-6",
				DisplayName:   "Claude Sonnet 4.6",
				SupportsTools: true,
			},
		},
	})

	recorder := httptest.NewRecorder()
	servePoolModels(recorder)

	var response struct {
		Models []struct {
			ID       string `json:"id"`
			Protocol string `json:"protocol"`
		} `json:"models"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	var foundGrok46, foundGemini38, foundGeminiCLI, foundClaudeAG bool
	for _, model := range response.Models {
		if model.ID == "grok-4.6" {
			foundGrok46 = true
		}
		if model.ID == "antigravity/gemini-3.8-flash-tiered" {
			foundGemini38 = true
			if model.Protocol != "gemini" {
				t.Fatalf("antigravity/gemini-3.8-flash-tiered protocol = %q, want gemini", model.Protocol)
			}
		}
		if model.ID == "antigravity/claude-sonnet-4-6" {
			foundClaudeAG = true
			if model.Protocol != "openai" {
				t.Fatalf("antigravity/claude-sonnet-4-6 protocol = %q, want openai", model.Protocol)
			}
		}
		if model.ID == "gemini-3.7-flash" {
			foundGeminiCLI = true
			if model.Protocol != "gemini" {
				t.Fatalf("gemini-3.7-flash protocol = %q, want gemini", model.Protocol)
			}
		}
	}
	if !foundGrok46 {
		t.Fatal("grok-4.6 missing from cute-code catalog")
	}
	if !foundGemini38 {
		t.Fatal("antigravity/gemini-3.8-flash-tiered missing from cute-code catalog")
	}
	if !foundClaudeAG {
		t.Fatal("antigravity/claude-sonnet-4-6 missing from cute-code catalog")
	}
	if !foundGeminiCLI {
		t.Fatal("gemini-3.7-flash missing from cute-code catalog")
	}
}

func TestPoolModelsEndpointRequiresPoolToken(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")
	handler := &proxyHandler{cfg: &config{}}

	request := httptest.NewRequest(http.MethodGet, "http://pool.example/api/pool/models", nil)
	recorder := httptest.NewRecorder()
	handler.proxyRequest(recorder, request, "request-id")
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}

	auth, err := generateClaudeAuth("test-secret", &PoolUser{
		ID:        "model-user",
		Token:     "download-token",
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("generate pool auth: %v", err)
	}
	request = httptest.NewRequest(http.MethodGet, "http://pool.example/api/pool/models", nil)
	request.Header.Set("Authorization", "Bearer "+auth.AccessToken)
	recorder = httptest.NewRecorder()
	handler.proxyRequest(recorder, request, "request-id")
	if recorder.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
}

func TestPoolCatalogEndpointAcceptsBreakGlassAdminAuthentication(t *testing.T) {
	handler := &proxyHandler{cfg: &config{adminToken: "admin-secret"}, pool: newPoolState(nil, false)}
	request := httptest.NewRequest(http.MethodGet, "http://pool.example/api/pool/catalog", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	request = httptest.NewRequest(http.MethodGet, "http://pool.example/api/pool/catalog", nil)
	request.Header.Set("X-Admin-Token", "admin-secret")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("admin-authenticated status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
}

func TestPoolModelDescriptorsReportAliasesAndAccountAvailability(t *testing.T) {
	account := &Account{Type: AccountTypeCodex, ID: "codex-account"}
	descriptors := poolModelDescriptors(newPoolState([]*Account{account}, false))
	var found bool
	for _, descriptor := range descriptors {
		if descriptor.ID != "gpt-5.6-sol" {
			continue
		}
		found = true
		if descriptor.SupportingAccounts != 1 || descriptor.AvailableAccounts != 1 || !descriptor.AvailableNow {
			t.Fatalf("availability = %d/%d now=%v", descriptor.AvailableAccounts, descriptor.SupportingAccounts, descriptor.AvailableNow)
		}
		if len(descriptor.Aliases) != 1 || descriptor.Aliases[0] != "gpt-5.6" {
			t.Fatalf("aliases = %#v", descriptor.Aliases)
		}
	}
	if !found {
		t.Fatal("gpt-5.6-sol descriptor missing")
	}
}

func TestPoolModelDescriptorsDoNotAdvertiseGrokInternalAlias(t *testing.T) {
	for _, descriptor := range poolModelDescriptors() {
		if descriptor.ID != "grok-4.5" {
			continue
		}
		for _, alias := range descriptor.Aliases {
			if alias == "grok-4.5-build" {
				t.Fatalf("grok discovery leaked internal alias: %#v", descriptor.Aliases)
			}
		}
		return
	}
	t.Fatal("grok-4.5 descriptor missing")
}

func TestPoolModelDescriptorsUseOneCanonicalAntigravityRow(t *testing.T) {
	antigravityModels.Reset()
	t.Cleanup(antigravityModels.Reset)
	antigravityModels.ReplaceAccount("antigravity-test", AntigravityAccountSnapshot{
		FetchedAt: time.Now(),
		Models: map[string]AntigravityModelInfo{
			"gemini-test": {ID: "gemini-test", DisplayName: "Gemini Test", MaxTokens: 1000, WebSearch: true},
		},
	})

	descriptors := poolModelDescriptors(newPoolState([]*Account{{Type: AccountTypeAntigravity, ID: "antigravity-test"}}, false))
	count := 0
	for _, descriptor := range descriptors {
		if descriptor.Provider != string(AccountTypeAntigravity) || descriptor.UpstreamID != "gemini-test" {
			continue
		}
		count++
		if descriptor.ID != "antigravity/gemini-test" {
			t.Fatalf("canonical ID = %q", descriptor.ID)
		}
		if descriptor.Protocol != "gemini" {
			t.Fatalf("protocol = %q, want gemini", descriptor.Protocol)
		}
		if len(descriptor.Aliases) != 1 || descriptor.Aliases[0] != "gemini-test" {
			t.Fatalf("aliases = %#v", descriptor.Aliases)
		}
		if !descriptor.Capabilities["web_search"] {
			t.Fatal("Antigravity model did not advertise web_search")
		}
		want := poolNativeToolDescriptor{
			Protocol: "openai-completions",
			Endpoint: "/v1/chat/completions",
			ToolType: "web_search",
		}
		if got := descriptor.NativeTools["web_search"]; got != want {
			t.Fatalf("Antigravity web_search route = %#v, want %#v", got, want)
		}
	}
	if count != 1 {
		t.Fatalf("Antigravity descriptor count = %d, want 1", count)
	}
}
