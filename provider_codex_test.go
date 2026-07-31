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
	publicLivePaths := map[string]string{
		"/live":          "/v1/live",
		"/live/call_123": "/v1/live/call_123",
	}
	for path, wantPath := range publicLivePaths {
		if got := provider.UpstreamURL(path); got.String() != realtimeBase.String() {
			t.Fatalf("UpstreamURL(%q) = %s, want %s", path, got, realtimeBase)
		}
		if got := provider.NormalizePath(path); got != wantPath {
			t.Fatalf("NormalizePath(%q) = %s, want %s", path, got, wantPath)
		}
	}
	if got := provider.UpstreamURL("/v1/live"); got.String() != responsesBase.String() {
		t.Fatalf("UpstreamURL(/v1/live) = %s, want %s", got, responsesBase)
	}
	if got := provider.NormalizePath("/v1/live"); got != "/realtime/calls" {
		t.Fatalf("NormalizePath(/v1/live) = %s, want /realtime/calls", got)
	}
	if got := provider.UpstreamURL("/v1/live/rtc_123"); got.String() != realtimeBase.String() {
		t.Fatalf("UpstreamURL(/v1/live/rtc_123) = %s, want %s", got, realtimeBase)
	}
	if got := provider.NormalizePath("/v1/live/rtc_123"); got != "/v1/live/rtc_123" {
		t.Fatalf("NormalizePath(/v1/live/rtc_123) = %s, want /v1/live/rtc_123", got)
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
