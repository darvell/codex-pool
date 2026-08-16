package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		"gpt-5.6-sol":     "openai",
		"claude-sonnet-5": "anthropic",
		"claude-opus-5":   "anthropic",
		"k3":              "anthropic",
		"kimi-for-coding": "anthropic",
		"MiniMax-M3":      "anthropic",
		"glm-5.2":         "anthropic",
		"mimo-v2.5-pro":   "anthropic",
		"grok-4.5":        "openai",
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

	for _, id := range []string{"gpt-5.6-terra", "MiniMax-M3", "mimo-v2.5-pro"} {
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

func TestPoolCatalogEndpointAcceptsFriendAuthentication(t *testing.T) {
	handler := &proxyHandler{cfg: &config{friendCode: "friend-secret"}, pool: newPoolState(nil, false)}
	request := httptest.NewRequest(http.MethodGet, "http://pool.example/api/pool/catalog", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	request = httptest.NewRequest(http.MethodGet, "http://pool.example/api/pool/catalog", nil)
	request.Header.Set("X-Friend-Code", "friend-secret")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("friend-authenticated status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
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
