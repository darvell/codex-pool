package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDefaultModelAliasGPT56ToSol(t *testing.T) {
	t.Parallel()

	aliases := newModelAliases(nil)
	got, ok := aliases.resolve("gpt-5.6")
	if !ok || got != "gpt-5.6-sol" {
		t.Fatalf("resolve(gpt-5.6) = (%q, %v), want (gpt-5.6-sol, true)", got, ok)
	}
	// Case-insensitive.
	got, ok = aliases.resolve("GPT-5.6")
	if !ok || got != "gpt-5.6-sol" {
		t.Fatalf("resolve(GPT-5.6) = (%q, %v), want (gpt-5.6-sol, true)", got, ok)
	}
	// Real variant names pass through.
	for _, model := range []string{"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.5"} {
		got, ok = aliases.resolve(model)
		if ok || got != model {
			t.Fatalf("resolve(%q) = (%q, %v), want passthrough", model, got, ok)
		}
	}
}

func TestModelAliasConfigOverridesDefault(t *testing.T) {
	t.Parallel()

	aliases := newModelAliases(map[string]string{
		"gpt-5.6": "gpt-5.6-luna",
	})
	got, ok := aliases.resolve("gpt-5.6")
	if !ok || got != "gpt-5.6-luna" {
		t.Fatalf("resolve with override = (%q, %v), want (gpt-5.6-luna, true)", got, ok)
	}
}

func TestModelAliasReloadKeepsDefaults(t *testing.T) {
	t.Parallel()

	aliases := newModelAliases(map[string]string{"spark": "gpt-5.3-codex-spark"})
	aliases.reload(nil)
	got, ok := aliases.resolve("gpt-5.6")
	if !ok || got != "gpt-5.6-sol" {
		t.Fatalf("after reload(nil) resolve(gpt-5.6) = (%q, %v)", got, ok)
	}
	// Custom alias from before reload is gone.
	if _, ok := aliases.resolve("spark"); ok {
		t.Fatal("expected spark alias cleared after reload(nil)")
	}
}

func TestApplyModelAliasRewritesBody(t *testing.T) {
	t.Parallel()

	aliases := newModelAliases(nil)
	body := []byte(`{"model":"gpt-5.6","input":"hi"}`)
	resolved, out := applyModelAlias(aliases, "gpt-5.6", body, false, "req")
	if resolved != "gpt-5.6-sol" {
		t.Fatalf("resolved = %q, want gpt-5.6-sol", resolved)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal rewritten body: %v", err)
	}
	if got := parsed["model"]; got != "gpt-5.6-sol" {
		t.Fatalf("body model = %#v, want gpt-5.6-sol", got)
	}
}

func TestApplyModelAliasToJSONFrameForWebSocket(t *testing.T) {
	t.Parallel()

	h := &proxyHandler{aliases: newModelAliases(nil)}
	in := []byte(`{"type":"response.create","model":"gpt-5.6","input":[]}`)
	out := applyModelAliasToJSONFrame(h, "req", in)
	if !bytes.Contains(out, []byte(`"model":"gpt-5.6-sol"`)) {
		t.Fatalf("expected gpt-5.6-sol in frame, got %s", out)
	}
	// Unaliased models pass through unchanged.
	passthrough := []byte(`{"type":"response.create","model":"gpt-5.6-terra"}`)
	if got := applyModelAliasToJSONFrame(h, "req", passthrough); !bytes.Equal(got, passthrough) {
		t.Fatalf("terra frame rewritten unexpectedly: %s", got)
	}
}
