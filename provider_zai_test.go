package main

import (
	"net/url"
	"testing"
)

func TestIsZAIModelHandlesCodingPlanModels(t *testing.T) {
	t.Parallel()

	for model, wantCanonical := range map[string]string{
		"glm-5.3":       "glm-5.3",
		"GLM-5.3":       "glm-5.3",
		"glm-5.3-flash": "glm-5.3-flash",
		"GLM-5.3-Flash": "glm-5.3-flash",
		"glm-5.2":       "glm-5.3", // Upgrade existing installed configurations.
		"GLM-5.2":       "glm-5.3",
	} {
		if !isZAIModel(model) {
			t.Fatalf("expected %q to route to zai", model)
		}
		if got := zaiCanonicalModel(model); got != wantCanonical {
			t.Fatalf("canonical model for %q = %q, want %q", model, got, wantCanonical)
		}
	}

	for _, model := range []string{"glm-4.5", "glm-4.5-air", "glm-4.6", "glm-4.7", "glm-5", "glm-5-turbo", "glm-5.1"} {
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

	provider, base, rewritten := handler.modelRouteOverride("/v1/messages", "GLM-5.2", []byte(`{"model":"GLM-5.2"}`))
	if provider == nil {
		t.Fatal("expected override provider")
	}
	if provider.Type() != AccountTypeZAI {
		t.Fatalf("expected zai provider, got %s", provider.Type())
	}
	if base == nil || base.String() != zaiBase.String() {
		t.Fatalf("expected zai base %s, got %v", zaiBase, base)
	}
	if string(rewritten) != `{"model":"glm-5.3"}` {
		t.Fatalf("unexpected rewritten body: %s", rewritten)
	}
}
