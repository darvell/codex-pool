package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestClaudeCodeFingerprintProfileIsCoherent(t *testing.T) {
	if got, want := ccUserAgent(), "claude-cli/2.1.161 (external, cli)"; got != want {
		t.Fatalf("user agent = %q, want %q", got, want)
	}

	headers := make(http.Header)
	ccStainlessHeaders(headers.Set)
	if got := headers.Get("X-Stainless-Package-Version"); got != "0.94.0" {
		t.Fatalf("SDK version = %q", got)
	}
	if got := headers.Get("X-Stainless-Runtime-Version"); got != "v24.3.0" {
		t.Fatalf("runtime version = %q", got)
	}
}

func TestClaudeCodeSystemMimicryUsesCurrentThreeBlockShape(t *testing.T) {
	bodyObj := map[string]any{
		"system": "Keep answers terse.",
		"messages": []any{
			map[string]any{"role": "user", "content": "hello world"},
		},
	}
	raw, err := json.Marshal(bodyObj)
	if err != nil {
		t.Fatal(err)
	}
	out := ccInjectSystemBlocks(bodyObj, raw)
	if err := json.Unmarshal(out, &bodyObj); err != nil {
		t.Fatal(err)
	}
	system := bodyObj["system"].([]any)
	if len(system) != 3 {
		t.Fatalf("system blocks = %d, want 3", len(system))
	}
	billing := system[0].(map[string]any)["text"].(string)
	if !strings.Contains(billing, "cc_entrypoint=cli;") || strings.Contains(billing, "cch=") {
		t.Fatalf("unexpected billing block: %q", billing)
	}
	if got := system[1].(map[string]any)["text"]; got != ccSystemPrefix {
		t.Fatalf("identity block = %#v", got)
	}
	if got := system[2].(map[string]any)["text"]; got != ccSystemExpansion {
		t.Fatalf("expansion block = %#v", got)
	}
	messages := bodyObj["messages"].([]any)
	if len(messages) != 3 {
		t.Fatalf("messages = %d, want injected pair plus original", len(messages))
	}
}

func TestGenuineClaudeCodeDetectionRequiresUAAndMetadata(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", ccUserAgent())
	body := map[string]any{"metadata": map[string]any{"user_id": "session"}}
	if !ccIsGenuineClaudeCodeRequest(req, body) {
		t.Fatal("expected genuine Claude Code request")
	}
	delete(body, "metadata")
	if ccIsGenuineClaudeCodeRequest(req, body) {
		t.Fatal("UA alone must not bypass mimicry")
	}
}

func TestClaudeCodeOAuthBetasIncludeFullMimicrySet(t *testing.T) {
	header := ccBetaHeader("claude-sonnet-4-6", true, false, false, false, false)
	for _, beta := range []string{
		betaClaudeCode,
		betaOAuth,
		betaInterleavedThink,
		betaCacheScope,
		betaEffort,
		betaContextManagement,
		betaExtendedCacheTTL,
	} {
		if !strings.Contains(header, beta) {
			t.Fatalf("beta header %q is missing %q", header, beta)
		}
	}
}
