package main

import (
	"net/url"
	"testing"
)

func TestModelRouteDiscoveryScope(t *testing.T) {
	base, err := url.Parse("https://example.test/v1")
	if err != nil {
		t.Fatal(err)
	}
	h := &proxyHandler{registry: NewProviderRegistry(NewCodexProvider(base, base, base), NewClaudeProvider(base), NewGeminiProvider(base, base), NewGrokProvider(base)), pool: newPoolState([]*Account{{Type: AccountTypeGrok, ID: "grok", Models: map[string]DiscoveredModel{"future-grok-model": {ID: "future-grok-model"}}}}, false)}
	if provider, _, _ := h.modelRouteOverride("/v1/responses", "future-grok-model", nil); provider != nil {
		t.Fatalf("buffered discovery unexpectedly changed routing: %v", provider)
	}
	provider, _, model := h.resolveStreamedModelRoute("/v1/responses", "future-grok-model")
	if provider == nil || provider.Type() != AccountTypeGrok || model != "future-grok-model" {
		t.Fatalf("streamed discovery = %v, %q", provider, model)
	}
}
