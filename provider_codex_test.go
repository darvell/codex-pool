package main

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestParseCodexClaimsNormalizesProLitePlan(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"https://api.openai.com/auth":{"chatgpt_plan_type":"PROLITE"}}`))
	claims := parseCodexClaims("header." + payload + ".signature")
	if claims.PlanType != "prolite" {
		t.Fatalf("PlanType = %q, want prolite", claims.PlanType)
	}
}

func TestCodexProviderNormalizeResponsesPaths(t *testing.T) {
	base, _ := url.Parse("https://chatgpt.com/backend-api/codex")
	provider := NewCodexProvider(base, base, base)

	cases := map[string]string{
		"/v1/responses":                      "/responses",
		"/responses":                         "/responses",
		"/v1/responses/compact":              "/responses/compact",
		"/v1/responses/resp_123":             "/responses/resp_123",
		"/v1/responses/resp_123/cancel":      "/responses/resp_123/cancel",
		"/v1/responses/resp_123/input_items": "/responses/resp_123/input_items",
	}
	for in, want := range cases {
		if got := provider.NormalizePath(in); got != want {
			t.Fatalf("NormalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCodexProviderRoutesRealtimeAndLiveToTheirNativeOrigins(t *testing.T) {
	responsesBase, _ := url.Parse("https://chatgpt.com/backend-api/codex")
	realtimeBase, _ := url.Parse("https://api.openai.com")
	whamBase, _ := url.Parse("https://chatgpt.com/backend-api")
	provider := NewCodexProviderWithRealtime(responsesBase, realtimeBase, whamBase, nil)

	for _, path := range []string{"/v1/realtime", "/v1/realtime/calls"} {
		if got := provider.UpstreamURL(path); got.String() != realtimeBase.String() {
			t.Fatalf("UpstreamURL(%q) = %s, want %s", path, got, realtimeBase)
		}
	}
	for _, path := range []string{"/v1/live", "/v1/live/call_123"} {
		if got := provider.UpstreamURL(path); got.String() != responsesBase.String() {
			t.Fatalf("UpstreamURL(%q) = %s, want %s", path, got, responsesBase)
		}
		if got := provider.NormalizePath(path); got != "/realtime/calls" {
			t.Fatalf("NormalizePath(%q) = %s, want /realtime/calls", path, got)
		}
	}
	if got := provider.UpstreamURL("/v1/responses"); got.String() != responsesBase.String() {
		t.Fatalf("UpstreamURL(/v1/responses) = %s, want %s", got, responsesBase)
	}
}

func TestCodexProviderDetectsSSEFromContentType(t *testing.T) {
	provider := &CodexProvider{}
	if provider.DetectsSSE("/v1/models", "application/json") {
		t.Fatal("JSON /v1 response should not be treated as SSE")
	}
	if !provider.DetectsSSE("/v1/responses", "") {
		t.Fatal("empty content-type /v1/responses should still default to SSE")
	}
	if !provider.DetectsSSE("/v1/models", "text/event-stream") {
		t.Fatal("text/event-stream should be treated as SSE")
	}
}

func TestCodexProviderLoadAccountReadsCyberAccess(t *testing.T) {
	provider := &CodexProvider{}
	data := []byte(`{
		"cyber_access": true,
		"tokens": {
			"access_token": "access",
			"refresh_token": "refresh",
			"id_token": "id",
			"account_id": "acct_123"
		}
	}`)

	acc, err := provider.LoadAccount("darv.json", "/tmp/darv.json", data)
	if err != nil {
		t.Fatalf("LoadAccount: %v", err)
	}
	if acc == nil {
		t.Fatal("expected account")
	}
	if !acc.CyberAccess {
		t.Fatal("expected cyber access flag")
	}
}
