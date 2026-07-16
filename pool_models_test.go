package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestServePoolModelsOmitsCredentials(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	servePoolModels(recorder)

	if recorder.Code != 200 {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var response struct {
		Models []map[string]any `json:"models"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
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

func TestPoolModelDescriptorsUseOneCanonicalAntigravityRow(t *testing.T) {
	antigravityModels.Reset()
	t.Cleanup(antigravityModels.Reset)
	antigravityModels.ReplaceAccount("antigravity-test", AntigravityAccountSnapshot{
		FetchedAt: time.Now(),
		Models: map[string]AntigravityModelInfo{
			"gemini-test": {ID: "gemini-test", DisplayName: "Gemini Test", MaxTokens: 1000},
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
	}
	if count != 1 {
		t.Fatalf("Antigravity descriptor count = %d, want 1", count)
	}
}
