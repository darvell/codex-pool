package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPoolModelDescriptorsCoverProviderProtocols(t *testing.T) {
	t.Parallel()

	descriptors, err := poolModelDescriptors()
	if err != nil {
		t.Fatalf("poolModelDescriptors: %v", err)
	}
	byID := make(map[string]cuteCodeModelConfig, len(descriptors))
	for _, descriptor := range descriptors {
		byID[descriptor.ID] = descriptor
	}

	tests := map[string]string{
		"gpt-5.6-sol":     "openai",
		"claude-sonnet-5": "anthropic",
		"k2p5":            "anthropic",
		"MiniMax-M3":      "anthropic",
		"glm-5.2":         "anthropic",
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
		if descriptor.BaseURL != "" || descriptor.APIKey != "" {
			t.Fatalf("model %q contains credentials or endpoint overrides", id)
		}
	}
}

func TestServePoolModelsOmitsCredentials(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	servePoolModels(recorder)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
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
