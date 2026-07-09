package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGrokProviderLoadsCLIAuthJSON(t *testing.T) {
	expires := time.Date(2026, 6, 6, 17, 51, 28, 0, time.UTC)
	body := `{
		"https://auth.x.ai::b1a00492-073a-47ea-816f-4c329264a828": {
			"key": "access-token",
			"refresh_token": "refresh-token",
			"expires_at": "` + expires.Format(time.RFC3339Nano) + `",
			"oidc_issuer": "https://auth.x.ai",
			"team_id": "12345678-1234-1234-1234-123456789abc"
		}
	}`

	provider := NewGrokProvider(mustParse("https://cli-chat-proxy.grok.com/v1"))
	acc, err := provider.LoadAccount("auth.json", "/tmp/auth.json", []byte(body))
	if err != nil {
		t.Fatalf("LoadAccount error: %v", err)
	}
	if acc == nil {
		t.Fatal("expected account")
	}
	if acc.Type != AccountTypeGrok || acc.AccessToken != "access-token" || acc.RefreshToken != "refresh-token" {
		t.Fatalf("unexpected account: %#v", acc)
	}
	if acc.ID != "grok-12345678" {
		t.Fatalf("id = %q", acc.ID)
	}
	if acc.AccountID != "https://auth.x.ai/oauth2/token" {
		t.Fatalf("token endpoint = %q", acc.AccountID)
	}
	if !acc.ExpiresAt.Equal(expires) {
		t.Fatalf("expires = %v, want %v", acc.ExpiresAt, expires)
	}
}

func TestGrokProviderLoadsPiGrokCliAuthJSON(t *testing.T) {
	expires := time.Date(2026, 6, 6, 17, 51, 28, 0, time.UTC)
	body := `{
		"access": "access-token",
		"refresh": "refresh-token",
		"expires": ` + strconv.FormatInt(expires.UnixMilli(), 10) + `,
		"tokenEndpoint": "https://auth.x.ai/oauth2/token",
		"baseUrl": "https://cli-chat-proxy.grok.com/v1"
	}`

	provider := NewGrokProvider(mustParse("https://cli-chat-proxy.grok.com/v1"))
	acc, err := provider.LoadAccount("pi.json", "/tmp/pi.json", []byte(body))
	if err != nil {
		t.Fatalf("LoadAccount error: %v", err)
	}
	if acc == nil {
		t.Fatal("expected account")
	}
	if acc.AccessToken != "access-token" || acc.RefreshToken != "refresh-token" || acc.AccountID != "https://auth.x.ai/oauth2/token" {
		t.Fatalf("unexpected account: %#v", acc)
	}
	if !acc.ExpiresAt.Equal(expires) {
		t.Fatalf("expires = %v, want %v", acc.ExpiresAt, expires)
	}
}

func TestGrokProviderRefreshesOAuthToken(t *testing.T) {
	provider := NewGrokProvider(mustParse("https://cli-chat-proxy.grok.com/v1"))
	acc := &Account{
		Type:         AccountTypeGrok,
		ID:           "grok",
		File:         t.TempDir() + "/auth.json",
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		AccountID:    "https://auth.x.ai/oauth2/token",
	}
	writeTestFile(t, acc.File, `{"access_token":"old-access","refresh_token":"old-refresh"}`)

	called := false
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		if req.URL.String() != "https://auth.x.ai/oauth2/token" {
			t.Fatalf("refresh URL = %s", req.URL.String())
		}
		if req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Fatalf("content-type = %q", req.Header.Get("Content-Type"))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`)),
		}, nil
	})

	if err := provider.RefreshToken(context.Background(), acc, transport); err != nil {
		t.Fatalf("RefreshToken error: %v", err)
	}
	if !called {
		t.Fatal("transport not called")
	}
	if acc.AccessToken != "new-access" || acc.RefreshToken != "new-refresh" {
		t.Fatalf("tokens = %q/%q", acc.AccessToken, acc.RefreshToken)
	}
	if acc.ExpiresAt.Before(time.Now().Add(59 * time.Minute)) {
		t.Fatalf("expires too soon: %v", acc.ExpiresAt)
	}
}

func TestGrokProviderNormalizePathAvoidsDuplicateV1(t *testing.T) {
	provider := NewGrokProvider(mustParse("https://cli-chat-proxy.grok.com/v1"))
	if got := provider.NormalizePath("/v1/responses"); got != "/responses" {
		t.Fatalf("NormalizePath(/v1/responses) = %q", got)
	}
	if got := provider.NormalizePath("/responses"); got != "/responses" {
		t.Fatalf("NormalizePath(/responses) = %q", got)
	}
}

func TestSaveGrokAccountPreservesPiGrokCliShape(t *testing.T) {
	path := t.TempDir() + "/pi.json"
	writeTestFile(t, path, `{"access":"old-access","refresh":"old-refresh","expires":1,"tokenEndpoint":"https://auth.x.ai/oauth2/token","baseUrl":"https://cli-chat-proxy.grok.com/v1"}`)
	expires := time.Date(2026, 6, 6, 17, 51, 28, 0, time.UTC)
	acc := &Account{Type: AccountTypeGrok, ID: "pi", File: path, AccessToken: "new-access", RefreshToken: "new-refresh", ExpiresAt: expires, AccountID: "https://auth.x.ai/oauth2/token"}
	if err := saveGrokAccount(acc); err != nil {
		t.Fatalf("saveGrokAccount: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	if root["access"] != "new-access" || root["refresh"] != "new-refresh" || root["access_token"] != nil {
		t.Fatalf("unexpected saved shape: %s", data)
	}
	if got := int64(root["expires"].(float64)); got != expires.UnixMilli() {
		t.Fatalf("expires = %d, want %d", got, expires.UnixMilli())
	}
}

func TestGrokProviderSetsBearerHeaders(t *testing.T) {
	provider := NewGrokProvider(mustParse("https://cli-chat-proxy.grok.com/v1"))
	req := httptest.NewRequest(http.MethodPost, "https://cli-chat-proxy.grok.com/v1/responses", nil)
	req.Header.Set("X-Api-Key", "wrong")
	provider.SetAuthHeaders(req, &Account{AccessToken: "token"})
	if got := req.Header.Get("Authorization"); got != "Bearer token" {
		t.Fatalf("authorization = %q", got)
	}
	if got := req.Header.Get("X-XAI-Token-Auth"); got != "xai-grok-cli" {
		t.Fatalf("X-XAI-Token-Auth = %q", got)
	}
	if got := req.Header.Get("x-grok-client-identifier"); got != "grok-cli" {
		t.Fatalf("x-grok-client-identifier = %q", got)
	}
	if got := req.Header.Get("x-grok-client-version"); got != "0.2.93" {
		t.Fatalf("x-grok-client-version = %q", got)
	}
	if got := req.Header.Get("X-Api-Key"); got != "" {
		t.Fatalf("x-api-key = %q", got)
	}
	if got := req.Header.Get("x-grok-source"); got != "" {
		t.Fatalf("x-grok-source = %q", got)
	}
}

func TestSanitizeGrokRequestBodyRemovesUnsupportedFields(t *testing.T) {
	body := []byte(`{"model":"grok-build","input":"hello","metadata":{"conversation_id":"c"},"prompt_cache_retention":"24h","external_web_access":true,"store":false,"include":["reasoning.encrypted_content"],"prompt_cache_key":"abc","service_tier":"priority","response_format":{"type":"json_object"},"reasoning":{"effort":"high"},"reasoningEffort":"high","tools":[{"type":"web_search","external_web_access":true},{"type":"function","name":"ok","description":"ok","parameters":{"type":"object"},"strict":true}],"tool_choice":"auto","parallel_tool_calls":true}`)
	rewritten := sanitizeGrokRequestBody(body, "grok-build")
	text := string(rewritten)
	for _, forbidden := range []string{"metadata", "external_web_access", "response_format", "reasoningEffort", `"reasoning"`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("rewritten body still contains %q: %s", forbidden, text)
		}
	}
	for _, preserved := range []string{"prompt_cache_retention", `"store":false`, "reasoning.encrypted_content", "prompt_cache_key", "service_tier", "web_search", `"strict":true`, `"tool_choice":"auto"`, `"parallel_tool_calls":true`} {
		if !strings.Contains(text, preserved) {
			t.Fatalf("rewritten body missing preserved field %q: %s", preserved, text)
		}
	}
	if !strings.Contains(text, `"text":{"format":{"type":"json_object"}}`) {
		t.Fatalf("rewritten body missing text.format: %s", text)
	}
}

func TestSanitizeGrokRequestBodyPreservesReasoningForGrok45(t *testing.T) {
	body := []byte(`{"model":"grok-4.5","input":"hello","reasoning":{"effort":"medium"},"reasoningEffort":"medium","metadata":{"conversation_id":"c"}}`)
	rewritten := rewriteAndSanitizeGrokRequestBody(body, "grok-4.5-build")
	text := string(rewritten)
	if !strings.Contains(text, `"model":"grok-4.5"`) {
		t.Fatalf("expected canonical grok-4.5 model: %s", text)
	}
	if !strings.Contains(text, `"reasoning":{"effort":"medium"}`) {
		t.Fatalf("expected reasoning effort preserved for grok-4.5: %s", text)
	}
	if strings.Contains(text, "reasoningEffort") {
		t.Fatalf("chat-style reasoningEffort should be stripped: %s", text)
	}
	if strings.Contains(text, "metadata") {
		t.Fatalf("metadata should be stripped: %s", text)
	}
	if !grokModelSupportsReasoningEffort("grok-4.5") || !grokModelSupportsReasoningEffort("grok-4.5-build") {
		t.Fatal("expected grok-4.5 aliases to support reasoning effort")
	}
	if got := grokModelContextWindow("grok-4.5"); got != 500000 {
		t.Fatalf("context window = %d, want 500000", got)
	}
}

func TestGrokUsagePollerDoesNotDeadMarkAccount(t *testing.T) {
	t.Parallel()

	accountFile := filepath.Join(t.TempDir(), "grok.json")
	if err := os.WriteFile(accountFile, []byte(`{"access_token":"access","refresh_token":"refresh","expires_at":"2026-06-12T18:02:58Z"}`), 0600); err != nil {
		t.Fatal(err)
	}

	acc := &Account{
		Type:         AccountTypeGrok,
		ID:           "grok",
		File:         accountFile,
		AccessToken:  "access",
		RefreshToken: "refresh",
		PlanType:     "grok",
	}
	calls := 0
	h := &proxyHandler{
		cfg:  &config{usageRefresh: time.Minute},
		pool: newPoolState([]*Account{acc}, false),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			t.Fatalf("Grok usage poller should not call transport, got %s %s", req.Method, req.URL.String())
			return nil, nil
		}),
	}

	h.pollUpstreamUsage()

	if calls != 0 {
		t.Fatalf("transport calls = %d, want 0", calls)
	}
	if acc.Dead {
		t.Fatal("Grok account was marked dead by usage poller")
	}
	data, err := os.ReadFile(accountFile)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if _, ok := saved["dead"]; ok {
		t.Fatalf("usage poller persisted dead flag for Grok account: %s", data)
	}
}

func TestGrokUsageParsesResponsesUsage(t *testing.T) {
	provider := NewGrokProvider(mustParse("https://cli-chat-proxy.grok.com/v1"))
	ru := provider.ParseUsage(map[string]any{
		"model": "grok-build",
		"usage": map[string]any{
			"input_tokens":  float64(100),
			"output_tokens": float64(25),
			"input_tokens_details": map[string]any{
				"cached_tokens": float64(40),
			},
		},
	})
	if ru == nil {
		t.Fatal("expected usage")
	}
	if ru.Model != "grok-build" || ru.InputTokens != 100 || ru.OutputTokens != 25 || ru.CachedInputTokens != 40 || ru.BillableTokens != 85 {
		t.Fatalf("usage = %+v", ru)
	}
}

func TestGrokSanitizesTranslatedRequestBody(t *testing.T) {
	chatBody := []byte(`{"model":"grok-build","messages":[{"role":"user","content":"hello"}],"external_web_access":true,"reasoningEffort":"high","tools":[{"type":"web_search","external_web_access":true}]}`)
	translated, err := translateChatCompletionsToResponses(chatBody)
	if err != nil {
		t.Fatalf("translateChatCompletionsToResponses: %v", err)
	}
	sanitized := rewriteAndSanitizeGrokRequestBody(translated, "grok-build")
	text := string(sanitized)
	for _, forbidden := range []string{"external_web_access", "reasoningEffort", `"reasoning"`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("sanitized translated body still contains %q: %s", forbidden, text)
		}
	}
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
}
