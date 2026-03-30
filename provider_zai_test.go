package main

import (
	"net/url"
	"strings"
	"testing"
)

func TestIsZAIModelHandlesCodingPlanModels(t *testing.T) {
	t.Parallel()

	for _, model := range []string{
		"glm-5.1",
		"GLM-5.1",
	} {
		if !isZAIModel(model) {
			t.Fatalf("expected %q to route to zai", model)
		}
		if got := zaiCanonicalModel(model); got != strings.ToLower(model) {
			t.Fatalf("unexpected canonical model for %q: %q", model, got)
		}
	}

	for _, model := range []string{"glm-4.7", "glm-5", "glm-5-turbo"} {
		if isZAIModel(model) {
			t.Fatalf("did not expect %q to route to zai", model)
		}
	}
}

func TestModelRouteOverrideZAIModelUsesZAIBase(t *testing.T) {
	t.Parallel()

	zaiBase, _ := url.Parse("https://api.z.ai/api/anthropic")
	handler := &proxyHandler{
		registry: NewProviderRegistry(
			&CodexProvider{},
			&ClaudeProvider{},
			&GeminiProvider{},
			NewZAIProvider(zaiBase),
		),
	}

	provider, base, rewritten := handler.modelRouteOverride("/v1/messages", "GLM-5.1", []byte(`{"model":"GLM-5.1"}`))
	if provider == nil {
		t.Fatal("expected override provider")
	}
	if provider.Type() != AccountTypeZAI {
		t.Fatalf("expected zai provider, got %s", provider.Type())
	}
	if base == nil || base.String() != zaiBase.String() {
		t.Fatalf("expected zai base %s, got %v", zaiBase, base)
	}
	if string(rewritten) != `{"model":"glm-5.1"}` {
		t.Fatalf("unexpected rewritten body: %s", rewritten)
	}
}
