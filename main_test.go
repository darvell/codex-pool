package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBuildWhamUsageURLKeepsBackendAPI(t *testing.T) {
	base, _ := url.Parse("https://chatgpt.com/backend-api")
	got := buildWhamUsageURL(base)
	expected := "https://chatgpt.com/backend-api/wham/usage"
	if got != expected {
		t.Fatalf("expected %s, got %s", expected, got)
	}
}

func TestIsUsageRequestMatchesOnlyUsageResource(t *testing.T) {
	for _, path := range []string{"/api/codex/usage", "/api/codex/usage/", "/backend-api/wham/usage"} {
		if !isUsageRequest(httptest.NewRequest(http.MethodGet, path, nil)) {
			t.Fatalf("expected %s to match", path)
		}
	}
	for _, path := range []string{
		"/backend-api/wham/usage/daily-token-usage-breakdown",
		"/api/codex/usage/details",
	} {
		if isUsageRequest(httptest.NewRequest(http.MethodGet, path, nil)) {
			t.Fatalf("did not expect %s to match", path)
		}
	}
}

func TestBuildWhamResetCreditsURLKeepsBackendAPI(t *testing.T) {
	base, _ := url.Parse("https://chatgpt.com/backend-api")
	got := buildWhamResetCreditsURL(base)
	expected := "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits"
	if got != expected {
		t.Fatalf("expected %s, got %s", expected, got)
	}
}

func TestBuildWhamConsumeResetCreditURLKeepsBackendAPI(t *testing.T) {
	base, _ := url.Parse("https://chatgpt.com/backend-api")
	got := buildWhamConsumeResetCreditURL(base)
	expected := "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits/consume"
	if got != expected {
		t.Fatalf("expected %s, got %s", expected, got)
	}
}

func TestFetchCodexResetCreditsStoresAvailableExpirations(t *testing.T) {
	base, _ := url.Parse("https://chatgpt.com/backend-api")
	h := &proxyHandler{
		cfg: &config{whamBase: base},
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if got := req.Header.Get("Authorization"); got != "Bearer access-token" {
				t.Fatalf("authorization = %q", got)
			}
			if got := req.Header.Get("ChatGPT-Account-ID"); got != "account-id" {
				t.Fatalf("account id = %q", got)
			}
			body := `{
				"available_count": 3,
				"credits": [
					{"id":"credit-later","status":"available","expires_at":"2026-07-31T20:08:45.858813Z"},
					{"id":"credit-redeemed","status":"redeemed","expires_at":"2026-07-12T01:47:43.975382Z"},
					{"id":"credit-sooner","status":"available","expires_at":"2026-07-18T00:35:13.709488Z"}
				]
			}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	account := &Account{
		AccessToken: "access-token",
		AccountID:   "account-id",
	}

	if err := h.fetchCodexResetCredits(account); err != nil {
		t.Fatal(err)
	}
	if account.ResetCreditsAvailable != 3 {
		t.Fatalf("available count = %d", account.ResetCreditsAvailable)
	}
	if len(account.RateLimitResetCredits) != 2 {
		t.Fatalf("expiration count = %d", len(account.RateLimitResetCredits))
	}
	if got := account.RateLimitResetCredits[0].ExpiresAt.Format(time.RFC3339Nano); got != "2026-07-18T00:35:13.709488Z" {
		t.Fatalf("first expiration = %s", got)
	}
	if got := account.RateLimitResetCredits[0].ID; got != "credit-sooner" {
		t.Fatalf("first credit id = %s", got)
	}
	if account.ResetCreditsRetrievedAt.IsZero() {
		t.Fatal("reset credits were not marked as retrieved")
	}
}

func TestAutoRedeemExpiringCodexResetCredit(t *testing.T) {
	base, _ := url.Parse("https://chatgpt.com/backend-api")
	now := time.Date(2026, time.July, 11, 20, 0, 0, 0, time.UTC)
	var requests int
	h := &proxyHandler{
		cfg: &config{whamBase: base},
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requests++
			switch requests {
			case 1:
				if req.Method != http.MethodPost {
					t.Fatalf("method = %s", req.Method)
				}
				var body map[string]string
				if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if got := body["credit_id"]; got != "credit-due" {
					t.Fatalf("credit id = %q", got)
				}
				if got := body["redeem_request_id"]; got != "codex-pool:credit-due" {
					t.Fatalf("redeem request id = %q", got)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Body:       io.NopCloser(strings.NewReader(`{"code":"reset","windows_reset":2}`)),
					Header:     make(http.Header),
				}, nil
			case 2:
				if req.Method != http.MethodGet {
					t.Fatalf("method = %s", req.Method)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Body:       io.NopCloser(strings.NewReader(`{"available_count":0,"credits":[]}`)),
					Header:     make(http.Header),
				}, nil
			default:
				t.Fatalf("unexpected request %d", requests)
				return nil, nil
			}
		}),
	}
	account := &Account{
		ID:          "account",
		AccessToken: "access-token",
		AccountID:   "account-id",
		RateLimitResetCredits: []RateLimitResetCredit{
			{ID: "credit-due", ExpiresAt: now.Add(10 * time.Minute)},
		},
		ResetCreditsAvailable: 1,
	}

	if err := h.autoRedeemExpiringCodexResetCredit(now, account); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d", requests)
	}
	if account.ResetCreditsAvailable != 0 || len(account.RateLimitResetCredits) != 0 {
		t.Fatalf("credits were not refreshed after redemption: %+v", account.RateLimitResetCredits)
	}
}

func TestAutoRedeemCodexResetCreditWaitsUntilThreshold(t *testing.T) {
	base, _ := url.Parse("https://chatgpt.com/backend-api")
	now := time.Date(2026, time.July, 11, 20, 0, 0, 0, time.UTC)
	requests := 0
	h := &proxyHandler{
		cfg: &config{whamBase: base},
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requests++
			return nil, fmt.Errorf("unexpected request to %s", req.URL)
		}),
	}
	account := &Account{
		RateLimitResetCredits: []RateLimitResetCredit{
			{ID: "credit-later", ExpiresAt: now.Add(16 * time.Minute)},
		},
	}

	if err := h.autoRedeemExpiringCodexResetCredit(now, account); err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("requests = %d", requests)
	}
}

func TestCodexProviderUpstreamURLBackendAPIPathUsesWhamBase(t *testing.T) {
	responsesBase, _ := url.Parse("https://chatgpt.com/backend-api/codex")
	whamBase, _ := url.Parse("https://chatgpt.com/backend-api")
	provider := NewCodexProvider(responsesBase, whamBase, nil)

	got := provider.UpstreamURL("/backend-api/codex/models")
	if got.String() != whamBase.String() {
		t.Fatalf("expected wham base %s, got %s", whamBase, got)
	}
}

func TestCodexProviderNormalizePathBackendAPIPathStripsPrefix(t *testing.T) {
	provider := &CodexProvider{}

	normalized := provider.NormalizePath("/backend-api/codex/models")
	got := singleJoin("/backend-api", normalized)
	expected := "/backend-api/codex/models"
	if got != expected {
		t.Fatalf("expected %s, got %s (normalized=%s)", expected, got, normalized)
	}
}

func TestCodexProviderNormalizePathV1Models(t *testing.T) {
	provider := &CodexProvider{}
	if got := provider.NormalizePath("/v1/models"); got != "/models" {
		t.Fatalf("NormalizePath(/v1/models) = %q", got)
	}
}

func TestModelRouteOverrideOpenAIModelKeepsBackendAPIBase(t *testing.T) {
	responsesBase, _ := url.Parse("https://chatgpt.com/backend-api/codex")
	whamBase, _ := url.Parse("https://chatgpt.com/backend-api")
	handler := &proxyHandler{
		registry: NewProviderRegistry(
			NewCodexProvider(responsesBase, whamBase, nil),
			&ClaudeProvider{},
			&GeminiProvider{},
		),
	}

	provider, base, _ := handler.modelRouteOverride("/backend-api/codex/responses", "gpt-5.4", []byte(`{"model":"gpt-5.4"}`))
	if provider == nil {
		t.Fatal("expected override provider")
	}
	if provider.Type() != AccountTypeCodex {
		t.Fatalf("expected codex provider, got %s", provider.Type())
	}
	if base == nil {
		t.Fatal("expected override base URL")
	}
	if got := base.String(); got != whamBase.String() {
		t.Fatalf("expected wham base %s, got %s", whamBase, got)
	}
}

func TestModelRouteOverrideRoutesGrokCodeModels(t *testing.T) {
	base, _ := url.Parse("https://example.test/v1")
	handler := &proxyHandler{
		registry: NewProviderRegistry(
			NewCodexProvider(base, base, nil),
			NewClaudeProvider(base),
			NewGeminiProvider(base, base),
			NewGrokProvider(base),
		),
	}

	provider, overrideBase, rewritten := handler.modelRouteOverride("/v1/responses", "grok-composer", []byte(`{"model":"grok-composer","input":"hello"}`))
	if provider == nil || provider.Type() != AccountTypeGrok {
		t.Fatalf("provider = %v, want grok", provider)
	}
	if overrideBase == nil || overrideBase.String() != base.String() {
		t.Fatalf("overrideBase = %v, want %v", overrideBase, base)
	}
	if !bytes.Contains(rewritten, []byte(`"model":"grok-composer-2.5-fast"`)) {
		t.Fatalf("rewritten body = %s", rewritten)
	}
}

func TestGrokPassThroughSSESkipsResponseSampling(t *testing.T) {
	base, _ := url.Parse("https://cli-chat-proxy.grok.com/v1")
	provider := NewGrokProvider(base)
	resp := &http.Response{Header: http.Header{"Content-Type": []string{"text/event-stream"}}}

	if shouldSampleResponseBodyForRequest(provider, &Account{Type: AccountTypeGrok}, "/v1/responses", resp, TranslateNone, "conv", false) {
		t.Fatal("grok pass-through SSE should skip response sampling")
	}
	if !shouldSampleResponseBodyForRequest(provider, &Account{Type: AccountTypeGrok}, "/v1/responses", resp, TranslateChatToResponses, "conv", false) {
		t.Fatal("translated SSE should still sample/inspect response body")
	}
	if !shouldSampleResponseBodyForRequest(provider, &Account{Type: AccountTypeGrok}, "/v1/responses", resp, TranslateNone, "conv", true) {
		t.Fatal("body logging should keep response sampling enabled")
	}
}

func TestCodexSSEStillSamplesWhenCyberPolicyMayInspect(t *testing.T) {
	base, _ := url.Parse("https://chatgpt.com/backend-api/codex")
	provider := NewCodexProvider(base, base, nil)
	resp := &http.Response{Header: http.Header{"Content-Type": []string{"text/event-stream"}}}

	if !shouldSampleResponseBodyForRequest(provider, &Account{Type: AccountTypeCodex}, "/v1/responses", resp, TranslateNone, "conv", false) {
		t.Fatal("codex non-cyber SSE should keep sampling for cyber policy inspection")
	}
	if shouldSampleResponseBodyForRequest(provider, &Account{Type: AccountTypeCodex, CyberAccess: true}, "/v1/responses", resp, TranslateNone, "conv", false) {
		t.Fatal("codex cyber-access SSE with conversation ID can skip response sampling")
	}
}

func TestModelRouteOverrideDoesNotRouteCodexClientPathsToClaude(t *testing.T) {
	base, _ := url.Parse("https://chatgpt.com/backend-api/codex")
	handler := &proxyHandler{
		registry: NewProviderRegistry(
			NewCodexProvider(base, base, nil),
			NewClaudeProvider(base),
			NewGeminiProvider(base, base),
		),
	}

	for _, path := range []string{"/v1/responses", "/responses", "/v1/chat/completions", "/v1/completions"} {
		for _, model := range []string{"opus", "fable"} {
			provider, overrideBase, rewritten := handler.modelRouteOverride(path, model, []byte(`{"model":"`+model+`"}`))
			if provider != nil || overrideBase != nil || rewritten != nil {
				t.Fatalf("modelRouteOverride(%q, %s) = provider=%v base=%v rewritten=%s, want no Claude override", path, model, provider, overrideBase, rewritten)
			}
		}
	}
}

func TestModelRouteOverrideRewritesClaudeFableAlias(t *testing.T) {
	base, _ := url.Parse("https://api.anthropic.com")
	handler := &proxyHandler{
		registry: NewProviderRegistry(
			NewCodexProvider(base, base, nil),
			NewClaudeProvider(base),
			NewGeminiProvider(base, base),
		),
	}

	provider, overrideBase, rewritten := handler.modelRouteOverride("/v1/messages", "fable", []byte(`{"model":"fable"}`))
	if provider == nil || provider.Type() != AccountTypeClaude || overrideBase == nil {
		t.Fatalf("modelRouteOverride(/v1/messages, fable) = provider=%v base=%v, want Claude override", provider, overrideBase)
	}
	if !bytes.Contains(rewritten, []byte(`"model":"claude-fable-5"`)) {
		t.Fatalf("rewritten body = %s, want claude-fable-5", rewritten)
	}
}

func TestModelRouteOverrideRewritesClaudeSonnetAlias(t *testing.T) {
	base, _ := url.Parse("https://api.anthropic.com")
	handler := &proxyHandler{
		registry: NewProviderRegistry(
			NewCodexProvider(base, base, nil),
			NewClaudeProvider(base),
			NewGeminiProvider(base, base),
		),
	}

	provider, overrideBase, rewritten := handler.modelRouteOverride("/v1/messages", "sonnet", []byte(`{"model":"sonnet"}`))
	if provider == nil || provider.Type() != AccountTypeClaude || overrideBase == nil {
		t.Fatalf("modelRouteOverride(/v1/messages, sonnet) = provider=%v base=%v, want Claude override", provider, overrideBase)
	}
	if !bytes.Contains(rewritten, []byte(`"model":"claude-sonnet-5"`)) {
		t.Fatalf("rewritten body = %s, want claude-sonnet-5", rewritten)
	}
}

func TestCodexClientClaudeModelStaysOnCodexAccount(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	base, _ := url.Parse("https://chatgpt.com/backend-api/codex")
	codex := &Account{Type: AccountTypeCodex, ID: "codex", AccessToken: "codex-token", AccountID: "acct_codex", PlanType: "pro"}
	claude := &Account{Type: AccountTypeClaude, ID: "claude", AccessToken: "sk-ant-api-upstream", PlanType: "max"}
	var upstreamPath string
	var codexAccountID string
	var claudeAPIKey string

	h := &proxyHandler{
		cfg:     &config{maxAttempts: 1, maxInMemoryBodyBytes: 4096},
		pool:    newPoolState([]*Account{codex, claude}, false),
		metrics: newMetrics(),
		recent:  newRecentErrors(5),
		registry: NewProviderRegistry(
			NewCodexProvider(base, base, nil),
			NewClaudeProvider(base),
			NewGeminiProvider(base, base),
		),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			upstreamPath = req.URL.Path
			codexAccountID = req.Header.Get("ChatGPT-Account-ID")
			claudeAPIKey = req.Header.Get("X-Api-Key")
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewBufferString(`{"ok":true}`)),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewBufferString(`{"model":"opus","input":"hello"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("test-secret", "codex-user"))
	rr := httptest.NewRecorder()
	h.proxyRequest(rr, req, "req-codex-opus")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if upstreamPath != "/backend-api/codex/responses" {
		t.Fatalf("upstream path = %q, want Codex responses path", upstreamPath)
	}
	if codexAccountID != "acct_codex" {
		t.Fatalf("ChatGPT-Account-ID = %q, want Codex account", codexAccountID)
	}
	if claudeAPIKey != "" {
		t.Fatalf("Claude X-Api-Key should not be set, got %q", claudeAPIKey)
	}
}

func TestClaudePoolTranslatesResponsesClientFormat(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	base, _ := url.Parse("https://api.anthropic.com")
	claude := &Account{Type: AccountTypeClaude, ID: "claude", AccessToken: "sk-ant-api-upstream", PlanType: "max"}
	transportCalled := false
	var upstreamPath string
	var upstreamModel string

	h := &proxyHandler{
		cfg:     &config{maxAttempts: 1, maxInMemoryBodyBytes: 4096},
		pool:    newPoolState([]*Account{claude}, false),
		metrics: newMetrics(),
		recent:  newRecentErrors(5),
		registry: NewProviderRegistry(
			NewCodexProvider(base, base, nil),
			NewClaudeProvider(base),
			NewGeminiProvider(base, base),
		),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			transportCalled = true
			upstreamPath = req.URL.Path
			var body map[string]any
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			upstreamModel, _ = body["model"].(string)
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body: io.NopCloser(strings.NewReader(
					`{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-4-8","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`,
				)),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewBufferString(`{"model":"opus","input":"hello"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", generateClaudePoolToken("test-secret", "claude-user"))
	rr := httptest.NewRecorder()
	h.proxyRequest(rr, req, "req-claude-responses")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if !transportCalled {
		t.Fatal("transport was not called")
	}
	if upstreamPath != "/v1/messages" {
		t.Fatalf("upstream path = %q", upstreamPath)
	}
	if upstreamModel != "claude-opus-4-8" {
		t.Fatalf("upstream model = %q", upstreamModel)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type chunkedReadCloser struct {
	chunks []string
	index  int
}

func (r *chunkedReadCloser) Read(p []byte) (int, error) {
	if r.index >= len(r.chunks) {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[r.index])
	r.chunks[r.index] = r.chunks[r.index][n:]
	if r.chunks[r.index] == "" {
		r.index++
	}
	return n, nil
}

func (r *chunkedReadCloser) Close() error { return nil }

func TestClaudeToolNameReadCloserRestoresSplitNames(t *testing.T) {
	body := &chunkedReadCloser{chunks: []string{`{"content":[{"name":"t_123`, `45678"}]}`}}
	reader := newClaudeToolNameReadCloser(body, map[string]string{"t_12345678": "Bash"})
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if strings.Contains(string(out), "t_12345678") || !strings.Contains(string(out), `"name":"Bash"`) {
		t.Fatalf("tool name was not restored across chunks: %s", out)
	}
}

func TestClaudePoolTokenAcceptedViaXAPIKeyPreservesNativeClaudeRequest(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	base, _ := url.Parse("https://api.anthropic.com")
	acc := &Account{Type: AccountTypeClaude, ID: "claude", AccessToken: "sk-ant-oat-upstream", PlanType: "max"}
	var upstreamBody map[string]any
	var upstreamAuth string
	var upstreamAPIKey string
	var upstreamBeta string
	var obfuscatedToolName string

	h := &proxyHandler{
		cfg:     &config{maxAttempts: 1, maxInMemoryBodyBytes: 4096},
		pool:    newPoolState([]*Account{acc}, false),
		metrics: newMetrics(),
		recent:  newRecentErrors(5),
		registry: NewProviderRegistry(
			NewCodexProvider(base, base, nil),
			NewClaudeProvider(base),
			NewGeminiProvider(base, base),
		),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			upstreamAuth = req.Header.Get("Authorization")
			upstreamAPIKey = req.Header.Get("X-Api-Key")
			upstreamBeta = req.Header.Get("anthropic-beta")
			body, _ := io.ReadAll(req.Body)
			if err := json.Unmarshal(body, &upstreamBody); err != nil {
				t.Fatalf("unmarshal upstream body: %v\n%s", err, body)
			}
			tools, _ := upstreamBody["tools"].([]any)
			tool, _ := tools[0].(map[string]any)
			obfuscatedToolName, _ = tool["name"].(string)
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewBufferString(`{"content":[{"type":"tool_use","name":"` + obfuscatedToolName + `"}]}`)),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewBufferString(`{
		"model":"claude-sonnet-4-6",
		"max_tokens":128,
		"system":[{"type":"text","text":"be helpful","cache_control":{"type":"ephemeral","ttl":"5m"}}],
		"tools":[{"name":"Bash","input_schema":{"type":"object"},"cache_control":{"type":"ephemeral","ttl":"5m"}}],
		"messages":[{"role":"user","content":[{"type":"text","text":"hello","cache_control":{"type":"ephemeral","ttl":"1h"}}]}]
	}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", generateClaudePoolToken("test-secret", "sdk-user"))
	rr := httptest.NewRecorder()
	h.proxyRequest(rr, req, "req-sdk")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if upstreamAuth != "Bearer sk-ant-oat-upstream" {
		t.Fatalf("upstream Authorization = %q", upstreamAuth)
	}
	if upstreamAPIKey != "" {
		t.Fatalf("upstream X-Api-Key leaked pool token: %q", upstreamAPIKey)
	}
	for _, beta := range []string{betaClaudeCode, betaOAuth, betaInterleavedThink, betaCacheScope} {
		if !strings.Contains(upstreamBeta, beta) {
			t.Fatalf("upstream anthropic-beta = %q, missing %q", upstreamBeta, beta)
		}
	}
	if obfuscatedToolName != "Bash" {
		t.Fatalf("tool name should be preserved, got %q", obfuscatedToolName)
	}
	system, _ := upstreamBody["system"].([]any)
	systemBlock, _ := system[0].(map[string]any)
	if text, _ := systemBlock["text"].(string); !strings.Contains(text, "x-anthropic-billing-header") {
		t.Fatalf("billing system block missing: %#v", systemBlock)
	}
	if len(system) != 3 || system[1].(map[string]any)["text"] != ccSystemPrefix {
		t.Fatalf("Claude Code system shape missing: %#v", system)
	}
	tools, _ := upstreamBody["tools"].([]any)
	tool, _ := tools[0].(map[string]any)
	toolCache, _ := tool["cache_control"].(map[string]any)
	if tool["name"] != "Bash" || toolCache["ttl"] != "5m" {
		t.Fatalf("tool cache block was rewritten: %#v", tool)
	}
	messages, _ := upstreamBody["messages"].([]any)
	if len(messages) != 3 {
		t.Fatalf("messages = %#v, want instruction pair plus original", messages)
	}
	instruction := messages[0].(map[string]any)["content"].([]any)[0].(map[string]any)
	if instruction["text"] != "[System Instructions]\nbe helpful" {
		t.Fatalf("system instructions were not preserved: %#v", instruction)
	}
	original, _ := messages[2].(map[string]any)
	content, _ := original["content"].([]any)
	textBlock, _ := content[0].(map[string]any)
	messageCache, _ := textBlock["cache_control"].(map[string]any)
	if textBlock["text"] != "hello" || messageCache["ttl"] != "1h" {
		t.Fatalf("message cache block was rewritten: %#v", textBlock)
	}
	if !strings.Contains(rr.Body.String(), `"name":"Bash"`) {
		t.Fatalf("response body changed unexpectedly: %s", rr.Body.String())
	}
}

func TestClaudeSDKRequestToGPTMapsReasoningEffort(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	base, _ := url.Parse("https://chatgpt.com/backend-api/codex")
	wham, _ := url.Parse("https://chatgpt.com/backend-api")
	acc := &Account{Type: AccountTypeCodex, ID: "codex", AccessToken: "codex-token", AccountID: "acct_codex", PlanType: "pro"}
	var upstreamPath string
	var upstreamBody map[string]any

	h := &proxyHandler{
		cfg:     &config{maxAttempts: 1, maxInMemoryBodyBytes: 4096},
		pool:    newPoolState([]*Account{acc}, false),
		metrics: newMetrics(),
		recent:  newRecentErrors(5),
		registry: NewProviderRegistry(
			NewCodexProvider(base, wham, nil),
			NewClaudeProvider(base),
			NewGeminiProvider(base, base),
		),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			upstreamPath = req.URL.Path
			body, _ := io.ReadAll(req.Body)
			if err := json.Unmarshal(body, &upstreamBody); err != nil {
				t.Fatalf("unmarshal upstream body: %v\n%s", err, body)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(bytes.NewBufferString("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"output\":[]}}\n\n")),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewBufferString(`{
		"model":"gpt-5.5",
		"max_tokens":128,
		"thinking":{"type":"enabled","budget_tokens":8192},
		"messages":[{"role":"user","content":"hello"}]
	}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", generateClaudePoolToken("test-secret", "sdk-user"))
	rr := httptest.NewRecorder()
	h.proxyRequest(rr, req, "req-gpt")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("non-streaming Claude client got SSE response: %s", rr.Body.String())
	}
	var translated map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &translated); err != nil {
		t.Fatalf("non-streaming Claude response was not JSON: %v\n%s", err, rr.Body.String())
	}
	if translated["type"] != "message" || translated["model"] != "gpt-5.5" {
		t.Fatalf("unexpected translated Claude response: %#v", translated)
	}
	if upstreamPath != "/backend-api/codex/responses" {
		t.Fatalf("upstream path = %q", upstreamPath)
	}
	reasoning, _ := upstreamBody["reasoning"].(map[string]any)
	if got := reasoning["effort"]; got != "medium" {
		t.Fatalf("reasoning effort = %#v, body=%#v", got, upstreamBody)
	}
}

func TestCyberPolicyStreamPinsConversationToCyberAccessAccount(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	base, _ := url.Parse("https://chatgpt.com/backend-api")
	ordinary := &Account{Type: AccountTypeCodex, ID: "ordinary", AccessToken: "ordinary-token", AccountID: "acct_ordinary", PlanType: "pro"}
	cyber := &Account{Type: AccountTypeCodex, ID: "cyber", AccessToken: "cyber-token", AccountID: "acct_cyber", PlanType: "pro", CyberAccess: true}
	var accounts []string

	h := &proxyHandler{
		cfg: &config{
			maxAttempts:          2,
			maxInMemoryBodyBytes: 1024,
		},
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			accountID := req.Header.Get("ChatGPT-Account-ID")
			accounts = append(accounts, accountID)
			if len(accounts) == 1 {
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
					Body:       io.NopCloser(bytes.NewBufferString("data: {\"type\":\"error\",\"error\":{\"code\":\"cyber_policy\",\"message\":\"blocked\"}}\n\n")),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewBufferString(`{"ok":true}`)),
			}, nil
		}),
		refreshTransport: http.DefaultTransport,
		pool:             newPoolState([]*Account{ordinary, cyber}, false),
		registry:         NewProviderRegistry(NewCodexProvider(base, base, base), NewClaudeProvider(base), NewGeminiProvider(base, base)),
		metrics:          newMetrics(),
		recent:           newRecentErrors(5),
	}

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/backend-api/codex/responses", bytes.NewBufferString(`{"model":"gpt-5.5","input":"hi"}`))
		req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("test-secret", "user-1"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("session_id", "thread-cyber")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d status=%d body=%s", i+1, rr.Code, rr.Body.String())
		}
	}

	if len(accounts) != 2 || accounts[0] != "acct_ordinary" || accounts[1] != "acct_cyber" {
		t.Fatalf("accounts = %#v, want ordinary then cyber", accounts)
	}
}

func TestCyberPolicyErrorRetriesOnCyberAccessAccount(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	base, _ := url.Parse("https://chatgpt.com/backend-api")
	ordinary := &Account{Type: AccountTypeCodex, ID: "ordinary", AccessToken: "ordinary-token", AccountID: "acct_ordinary", PlanType: "pro"}
	cyber := &Account{Type: AccountTypeCodex, ID: "cyber", AccessToken: "cyber-token", AccountID: "acct_cyber", PlanType: "pro", CyberAccess: true}
	var accounts []string

	h := &proxyHandler{
		cfg: &config{
			maxAttempts:          2,
			maxInMemoryBodyBytes: 1024,
		},
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			accountID := req.Header.Get("ChatGPT-Account-ID")
			accounts = append(accounts, accountID)
			if accountID == "acct_ordinary" {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Status:     "400 Bad Request",
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewBufferString(`{"error":{"type":"invalid_request","code":"cyber_policy","message":"blocked"}}`)),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewBufferString(`{"ok":true}`)),
			}, nil
		}),
		refreshTransport: http.DefaultTransport,
		pool:             newPoolState([]*Account{ordinary, cyber}, false),
		registry:         NewProviderRegistry(NewCodexProvider(base, base, base), NewClaudeProvider(base), NewGeminiProvider(base, base)),
		metrics:          newMetrics(),
		recent:           newRecentErrors(5),
	}

	req := httptest.NewRequest(http.MethodPost, "/backend-api/test", bytes.NewBufferString(`{"model":"gpt-5.5","input":"hi"}`))
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("test-secret", "user-1"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(accounts) != 2 || accounts[0] != "acct_ordinary" || accounts[1] != "acct_cyber" {
		t.Fatalf("accounts = %#v, want ordinary then cyber", accounts)
	}
}

func TestInjectClaudeModelsAddsMissingCodexFallbackModels(t *testing.T) {
	t.Parallel()

	body := []byte(`{"models":[{"slug":"gpt-5.4","display_name":"gpt-5.4","description":"template","context_window":272000,"max_context_window":1000000,"visibility":"list","supported_in_api":true,"supported_reasoning_levels":[{"effort":"high"}]}]}`)
	out := injectClaudeModels(body)

	var catalog map[string]any
	if err := json.Unmarshal(out, &catalog); err != nil {
		t.Fatalf("unmarshal injected catalog: %v", err)
	}
	models, ok := catalog["models"].([]any)
	if !ok {
		t.Fatalf("models missing from catalog: %#v", catalog)
	}

	found := map[string]map[string]any{}
	for _, model := range models {
		m, ok := model.(map[string]any)
		if !ok {
			continue
		}
		if slug, _ := m["slug"].(string); slug != "" {
			found[slug] = m
		}
	}
	if found["gpt-5.5"] == nil {
		t.Fatalf("missing gpt-5.5 in injected catalog: %#v", models)
	}
	if got := int(found["gpt-5.5"]["context_window"].(float64)); got != 272000 {
		t.Fatalf("gpt-5.5 context_window = %d", got)
	}
	if got := found["gpt-5.5"]["display_name"]; got != "GPT-5.5" {
		t.Fatalf("gpt-5.5 display_name = %#v", got)
	}
	for _, slug := range []string{"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"} {
		if found[slug] == nil {
			t.Fatalf("missing %s in injected catalog: %#v", slug, models)
		}
		if got := int(found[slug]["context_window"].(float64)); got != 372000 {
			t.Fatalf("%s context_window = %d, want 372000", slug, got)
		}
	}
	if found["claude-sonnet-5"] == nil {
		t.Fatalf("missing claude-sonnet-5 in injected catalog: %#v", models)
	}
	if got := found["claude-sonnet-5"]["display_name"]; got != "Claude Sonnet 5" {
		t.Fatalf("claude-sonnet-5 display_name = %#v", got)
	}
}

func TestInjectClaudeModelsDoesNotDuplicateExistingCodexFallbackModels(t *testing.T) {
	t.Parallel()

	body := []byte(`{"models":[{"slug":"gpt-5.5","display_name":"gpt-5.5"}]}`)
	out := injectClaudeModels(body)

	var catalog map[string]any
	if err := json.Unmarshal(out, &catalog); err != nil {
		t.Fatalf("unmarshal injected catalog: %v", err)
	}
	models := catalog["models"].([]any)
	count := 0
	for _, model := range models {
		m, ok := model.(map[string]any)
		if ok && m["slug"] == "gpt-5.5" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("gpt-5.5 count = %d, want 1", count)
	}
}

func TestCodexProviderParseUsageHeaders(t *testing.T) {
	acc := &Account{Type: AccountTypeCodex}
	provider := &CodexProvider{}
	provider.ParseUsageHeaders(acc, mapToHeader(map[string]string{
		"X-Codex-Primary-Used-Percent":     "25",
		"X-Codex-Secondary-Used-Percent":   "50",
		"X-Codex-Primary-Window-Minutes":   "300",
		"X-Codex-Secondary-Window-Minutes": "10080",
	}))

	if acc.Usage.PrimaryUsedPercent != 0.25 {
		t.Fatalf("primary percent = %v", acc.Usage.PrimaryUsedPercent)
	}
	if acc.Usage.SecondaryUsedPercent != 0.50 {
		t.Fatalf("secondary percent = %v", acc.Usage.SecondaryUsedPercent)
	}
	if acc.Usage.PrimaryWindowMinutes != 300 {
		t.Fatalf("primary window = %d", acc.Usage.PrimaryWindowMinutes)
	}
	if acc.Usage.SecondaryWindowMinutes != 10080 {
		t.Fatalf("secondary window = %d", acc.Usage.SecondaryWindowMinutes)
	}
}

func TestCodexProviderMapsWeeklyOnlyPrimarySlotAndClearsRemovedFiveHourWindow(t *testing.T) {
	oldReset := time.Now().Add(time.Hour).Truncate(time.Second)
	weeklyReset := time.Now().Add(6 * 24 * time.Hour).Truncate(time.Second)
	acc := &Account{
		Type: AccountTypeCodex,
		Usage: UsageSnapshot{
			PrimaryUsed:            0.75,
			PrimaryUsedPercent:     0.75,
			PrimaryWindowMinutes:   300,
			PrimaryResetAt:         oldReset,
			SecondaryUsed:          0.40,
			SecondaryUsedPercent:   0.40,
			SecondaryWindowMinutes: 10080,
			SecondaryResetAt:       oldReset,
			CreditsBalance:         10,
			HasCredits:             true,
		},
	}

	provider := &CodexProvider{}
	provider.ParseUsageHeaders(acc, mapToHeader(map[string]string{
		"X-Codex-Primary-Used-Percent":     "82",
		"X-Codex-Primary-Window-Minutes":   "10080",
		"X-Codex-Primary-Reset-At":         strconv.FormatInt(weeklyReset.Unix(), 10),
		"X-Codex-Secondary-Used-Percent":   "0",
		"X-Codex-Secondary-Window-Minutes": "0",
		"X-Codex-Credits-Has-Credits":      "false",
		"X-Codex-Credits-Unlimited":        "false",
		"X-Codex-Credits-Balance":          "0",
	}))

	if usagePrimaryWindowAvailable(acc.Usage) {
		t.Fatalf("removed five-hour window survived: %+v", acc.Usage)
	}
	if got := usageSecondaryUsed(acc.Usage); got != 0.82 {
		t.Fatalf("weekly usage = %v, want 0.82", got)
	}
	if acc.Usage.SecondaryWindowMinutes != 10080 {
		t.Fatalf("weekly window = %d", acc.Usage.SecondaryWindowMinutes)
	}
	if !acc.Usage.SecondaryResetAt.Equal(weeklyReset) {
		t.Fatalf("weekly reset = %v, want %v", acc.Usage.SecondaryResetAt, weeklyReset)
	}
	if acc.Usage.HasCredits || acc.Usage.CreditsBalance != 0 {
		t.Fatalf("stale credits survived: %+v", acc.Usage)
	}
}

func TestCodexProviderMapsFiveHourOnlyPrimarySlotAndClearsRemovedWeeklyWindow(t *testing.T) {
	fiveHourReset := time.Now().Add(4 * time.Hour).Truncate(time.Second)
	acc := &Account{
		Type: AccountTypeCodex,
		Usage: UsageSnapshot{
			SecondaryUsed:          0.82,
			SecondaryUsedPercent:   0.82,
			SecondaryWindowMinutes: 10080,
			SecondaryResetAt:       time.Now().Add(6 * 24 * time.Hour),
		},
	}

	provider := &CodexProvider{}
	provider.ParseUsageHeaders(acc, mapToHeader(map[string]string{
		"X-Codex-Primary-Used-Percent":     "25",
		"X-Codex-Primary-Window-Minutes":   "300",
		"X-Codex-Primary-Reset-At":         strconv.FormatInt(fiveHourReset.Unix(), 10),
		"X-Codex-Secondary-Used-Percent":   "0",
		"X-Codex-Secondary-Window-Minutes": "0",
	}))

	if got := usagePrimaryUsed(acc.Usage); got != 0.25 {
		t.Fatalf("five-hour usage = %v, want 0.25", got)
	}
	if acc.Usage.PrimaryWindowMinutes != 300 || !acc.Usage.PrimaryResetAt.Equal(fiveHourReset) {
		t.Fatalf("five-hour window = %+v", acc.Usage)
	}
	if usageSecondaryWindowAvailable(acc.Usage) {
		t.Fatalf("removed weekly window survived: %+v", acc.Usage)
	}
}

func TestCodexUsageSlotsEncodeWeeklyOnlyAsUpstreamPrimary(t *testing.T) {
	resetAt := time.Now().Add(6 * 24 * time.Hour).Truncate(time.Second)
	slots := codexUsageSlotsFromSnapshot(UsageSnapshot{
		SecondaryUsed:          0.82,
		SecondaryUsedPercent:   0.82,
		SecondaryWindowMinutes: 10080,
		SecondaryResetAt:       resetAt,
	})
	if slots.Primary == nil {
		t.Fatal("missing upstream primary slot")
	}
	if slots.Primary.WindowMinutes != 10080 || slots.Primary.UsedPercent != 0.82 {
		t.Fatalf("primary slot = %+v", slots.Primary)
	}
	if slots.Secondary != nil {
		t.Fatalf("unexpected secondary slot: %+v", slots.Secondary)
	}
}

func TestReplaceUsageHeadersEmitsWeeklyOnlyPoolInPrimarySlot(t *testing.T) {
	account := &Account{
		ID:       "weekly-only",
		Type:     AccountTypeCodex,
		PlanType: "prolite",
		Usage: UsageSnapshot{
			SecondaryUsed:          0.82,
			SecondaryUsedPercent:   0.82,
			SecondaryWindowMinutes: 10080,
		},
	}
	h := &proxyHandler{pool: newPoolState([]*Account{account}, false)}
	headers := mapToHeader(map[string]string{
		"X-Codex-Primary-Used-Percent":     "82",
		"X-Codex-Primary-Window-Minutes":   "10080",
		"X-Codex-Secondary-Used-Percent":   "0",
		"X-Codex-Secondary-Window-Minutes": "0",
	})

	h.replaceUsageHeaders(headers)

	if got := headers.Get("X-Codex-Primary-Used-Percent"); got != "82.0" {
		t.Fatalf("primary used header = %q", got)
	}
	if got := headers.Get("X-Codex-Primary-Window-Minutes"); got != "10080" {
		t.Fatalf("primary window header = %q", got)
	}
	if got := headers.Get("X-Codex-Secondary-Used-Percent"); got != "" {
		t.Fatalf("stale secondary header = %q", got)
	}
}

func TestHandleAggregatedUsageMatchesWeeklyOnlyUpstreamShape(t *testing.T) {
	account := &Account{
		ID:       "weekly-only",
		Type:     AccountTypeCodex,
		PlanType: "prolite",
		Usage: UsageSnapshot{
			SecondaryUsed:          0.82,
			SecondaryUsedPercent:   0.82,
			SecondaryWindowMinutes: 10080,
		},
	}
	h := &proxyHandler{
		cfg:  &config{},
		pool: newPoolState([]*Account{account}, false),
	}
	recorder := httptest.NewRecorder()

	h.handleAggregatedUsage(recorder, "test")

	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	rateLimit := payload["rate_limit"].(map[string]any)
	primary := rateLimit["primary_window"].(map[string]any)
	if got := int(primary["limit_window_seconds"].(float64)); got != 604800 {
		t.Fatalf("primary window seconds = %d", got)
	}
	if got := primary["used_percent"].(float64); got != 82 {
		t.Fatalf("primary used percent = %v", got)
	}
	if rateLimit["secondary_window"] != nil {
		t.Fatalf("secondary window = %#v, want null", rateLimit["secondary_window"])
	}
}

func TestParseRequestUsageFromSSE(t *testing.T) {
	line := []byte(`{"type":"response.completed","prompt_cache_key":"pc","usage":{"input_tokens":100,"cached_input_tokens":40,"output_tokens":10,"billable_tokens":70}}`)
	var obj map[string]any
	if err := json.Unmarshal(line, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ru := parseRequestUsage(obj)
	if ru == nil {
		t.Fatalf("expected usage parsed")
	}
	if ru.InputTokens != 100 || ru.CachedInputTokens != 40 || ru.OutputTokens != 10 || ru.BillableTokens != 70 {
		t.Fatalf("unexpected values: %+v", ru)
	}
	if ru.PromptCacheKey != "pc" {
		t.Fatalf("prompt_cache_key=%s", ru.PromptCacheKey)
	}
}

func TestExtractRequestedModelFromJSON(t *testing.T) {
	body := []byte(`{"model":"gpt-5.3-codex-spark","input":"hi"}`)
	got := extractRequestedModelFromJSON(body)
	if got != "gpt-5.3-codex-spark" {
		t.Fatalf("model=%q", got)
	}
	if !modelRequiresCodexPro(got) {
		t.Fatalf("expected model to require codex pro")
	}
}

func TestPlanMatchesClaudePremium(t *testing.T) {
	t.Parallel()

	for _, plan := range []string{"max", "max_x5", "max_x20", "team", "team_enterprise", "max_team", " Max "} {
		if !planMatchesRequired(plan, "claude_premium") {
			t.Fatalf("expected plan %q to match claude_premium", plan)
		}
	}
	for _, plan := range []string{"", "pro", "free", "enterprise"} {
		if planMatchesRequired(plan, "claude_premium") {
			t.Fatalf("did not expect plan %q to match claude_premium", plan)
		}
	}
}

func TestClaudeRequestRequiresPremium(t *testing.T) {
	t.Parallel()

	if !claudeRequestRequiresPremium(nil, "claude-opus-4-7") {
		t.Fatal("expected opus model to require a premium Claude account")
	}
	if !claudeRequestRequiresPremium(nil, "opus") {
		t.Fatal("expected opus alias to require a premium Claude account")
	}
	if !claudeRequestRequiresPremium(nil, "claude-sonnet-5 [1m]") {
		t.Fatal("expected [1m] model suffix to require a premium Claude account")
	}
	if !claudeRequestRequiresPremium(nil, "claude-sonnet-4-6 [1m]") {
		t.Fatal("expected [1m] model suffix to require a premium Claude account")
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Header.Set("anthropic-beta", "context-1m-2025-08-07")
	if !claudeRequestRequiresPremium(req, "claude-sonnet-4-6") {
		t.Fatal("expected 1m beta header to require a premium Claude account")
	}
	if claudeRequestRequiresPremium(nil, "claude-sonnet-5") {
		t.Fatal("did not expect regular sonnet model to require a premium Claude account")
	}
	if claudeRequestRequiresPremium(nil, "claude-sonnet-4-6") {
		t.Fatal("did not expect regular sonnet model to require a premium Claude account")
	}
}

func TestClaudePremiumRequestSkipsPinnedProAccount(t *testing.T) {
	t.Parallel()

	pro := &Account{Type: AccountTypeClaude, ID: "pro", PlanType: "pro"}
	team := &Account{Type: AccountTypeClaude, ID: "team", PlanType: "team"}
	pool := newPoolState([]*Account{pro, team}, false)
	pool.pin("conv", pro.ID)

	got := pool.candidate("conv", nil, AccountTypeClaude, "claude_premium", "")
	if got == nil {
		t.Fatal("expected a premium Claude account")
	}
	if got.ID != team.ID {
		t.Fatalf("candidate = %q, want team account", got.ID)
	}
}

func TestClaudeProviderParseUsageHeaders(t *testing.T) {
	acc := &Account{Type: AccountTypeClaude}
	provider := &ClaudeProvider{}
	initialAt := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	acc.Usage = UsageSnapshot{
		PrimaryUsedPercent:   0.25,
		SecondaryUsedPercent: 0.33,
		PrimaryUsed:          0.25,
		SecondaryUsed:        0.33,
		PrimaryResetAt:       initialAt,
		SecondaryResetAt:     initialAt,
		RetrievedAt:          initialAt,
		Source:               "claude-api",
	}

	provider.ParseUsageHeaders(acc, mapToHeader(map[string]string{
		"anthropic-ratelimit-unified-tokens-utilization":   "99.9",
		"anthropic-ratelimit-unified-requests-utilization": "88.8",
		"anthropic-ratelimit-unified-tokens-reset":         "9999999999",
		"anthropic-ratelimit-unified-requests-reset":       "9999999999",
	}))

	if math.Abs(acc.Usage.PrimaryUsedPercent-0.999) > 1e-9 {
		t.Fatalf("primary percent = %v", acc.Usage.PrimaryUsedPercent)
	}
	if math.Abs(acc.Usage.SecondaryUsedPercent-0.888) > 1e-9 {
		t.Fatalf("secondary percent = %v", acc.Usage.SecondaryUsedPercent)
	}
	if acc.Usage.PrimaryResetAt.UTC().Unix() != 9999999999 {
		t.Fatalf("primary reset = %v want %v", acc.Usage.PrimaryResetAt.UTC(), time.Unix(9999999999, 0).UTC())
	}
	if acc.Usage.SecondaryResetAt.UTC().Unix() != 9999999999 {
		t.Fatalf("secondary reset = %v want %v", acc.Usage.SecondaryResetAt.UTC(), time.Unix(9999999999, 0).UTC())
	}
	if acc.Usage.Source != "headers" {
		t.Fatalf("source = %q", acc.Usage.Source)
	}
	if !acc.Usage.RetrievedAt.After(initialAt) {
		t.Fatalf("retrieved_at should be updated from headers: %v", acc.Usage.RetrievedAt.UTC())
	}
}

func TestKimiProviderParseUsageHeaders(t *testing.T) {
	acc := &Account{Type: AccountTypeKimi}
	provider := &KimiProvider{}
	provider.ParseUsageHeaders(acc, mapToHeader(map[string]string{
		"x-ratelimit-remaining-requests": "90",
		"x-ratelimit-limit-requests":     "100",
		"x-ratelimit-remaining-tokens":   "400",
		"x-ratelimit-limit-tokens":       "500",
		"x-ratelimit-reset-requests":     "9999999999",
	}))

	if acc.Usage.PrimaryUsedPercent != 0.1 {
		t.Fatalf("primary percent = %v", acc.Usage.PrimaryUsedPercent)
	}
	if acc.Usage.SecondaryUsedPercent != 0.2 {
		t.Fatalf("secondary percent = %v", acc.Usage.SecondaryUsedPercent)
	}
	if acc.Usage.PrimaryResetAt.UTC().Unix() != 9999999999 {
		t.Fatalf("primary reset = %v want %v", acc.Usage.PrimaryResetAt.UTC(), time.Unix(9999999999, 0).UTC())
	}
}

func TestMergeUsageClaudeAPIAllowsPerWindowResetToZero(t *testing.T) {
	prev := UsageSnapshot{
		PrimaryUsedPercent:   0.5,
		SecondaryUsedPercent: 0.25,
		PrimaryUsed:          0.5,
		SecondaryUsed:        0.25,
		RetrievedAt:          time.Now().UTC().Add(-10 * time.Minute),
		Source:               "claude-api",
	}
	next := UsageSnapshot{
		PrimaryUsedPercent:   0,
		SecondaryUsedPercent: 0.25,
		PrimaryUsed:          0,
		SecondaryUsed:        0.25,
		RetrievedAt:          time.Now().UTC(),
		Source:               "claude-api",
	}

	got := mergeUsage(prev, next)
	if got.PrimaryUsedPercent != 0 {
		t.Fatalf("primary percent = %v", got.PrimaryUsedPercent)
	}
	if got.PrimaryUsed != 0 {
		t.Fatalf("primary used = %v", got.PrimaryUsed)
	}
	if got.SecondaryUsedPercent != 0.25 {
		t.Fatalf("secondary percent = %v", got.SecondaryUsedPercent)
	}
}

func TestParseClaudeResetAt(t *testing.T) {
	resetAt := time.Now().UTC().Add(4 * time.Hour).Truncate(time.Second)

	if _, ok := parseClaudeResetAt(nil); ok {
		t.Fatalf("expected nil reset value to be ignored")
	}
	if _, ok := parseClaudeResetAt(""); ok {
		t.Fatalf("expected empty reset value to be ignored")
	}

	fromString, ok := parseClaudeResetAt(resetAt.Format(time.RFC3339))
	if !ok {
		t.Fatalf("expected RFC3339 reset to parse")
	}
	if fromString.UTC().Unix() != resetAt.Unix() {
		t.Fatalf("string reset = %v want %v", fromString.UTC(), resetAt)
	}

	fromUnix, ok := parseClaudeResetAt(float64(resetAt.Unix()))
	if !ok {
		t.Fatalf("expected unix reset to parse")
	}
	if fromUnix.UTC().Unix() != resetAt.Unix() {
		t.Fatalf("unix reset = %v want %v", fromUnix.UTC(), resetAt)
	}
}

func TestInferClaudeWindowReset(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	window := 5 * time.Hour

	got := inferClaudeWindowReset(now, time.Time{}, window)
	if got.UTC().Unix() != now.Add(window).Unix() {
		t.Fatalf("zero prev reset = %v want %v", got.UTC(), now.Add(window).UTC())
	}

	prev := now.Add(-2 * time.Hour)
	got = inferClaudeWindowReset(now, prev, window)
	want := prev.Add(5 * time.Hour)
	if got.UTC().Unix() != want.Unix() {
		t.Fatalf("prev reset = %v want %v", got.UTC(), want.UTC())
	}
}

func TestServeHTTPNoopsNoisyCodexPaths(t *testing.T) {
	t.Parallel()

	h := &proxyHandler{cfg: &config{}}
	for _, tc := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/codex/analytics-events/events"},
		{method: http.MethodGet, path: "/plugins/featured"},
		{method: http.MethodGet, path: "/plugins/list"},
		{method: http.MethodGet, path: "/backend-api/plugins/featured"},
		{method: http.MethodPost, path: "/backend-api/codex/analytics-events/events"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s %s status=%d want %d", tc.method, tc.path, rr.Code, http.StatusOK)
		}
		if rr.Body.Len() != 0 {
			t.Fatalf("%s %s body length=%d want 0", tc.method, tc.path, rr.Body.Len())
		}
	}
}

func TestServeHTTPCodexAppsMCPInitializeReturnsJSON(t *testing.T) {
	t.Parallel()

	h := &proxyHandler{cfg: &config{}}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"codex","version":"0"}}}`)

	// Cover reverse-proxy rewrite variants (with/without /backend-api prefix).
	for _, path := range []string{
		"/backend-api/wham/apps",
		"/wham/apps",
		"/api/codex/apps",
		"/backend-api/ps/mcp",
		"/api/codex/ps/mcp",
		"/backend-api/wham/apps/", // trailing slash
	} {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		// Codex sends a ChatGPT access token here — not a pool JWT. The stub
		// must succeed without pool auth.
		req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.chatgpt-access.not-a-pool-token")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("%s status=%d want %d body=%s", path, rr.Code, http.StatusOK, rr.Body.String())
		}
		if got := rr.Header().Get("Content-Type"); got != "application/json" {
			t.Fatalf("%s content-type=%q want application/json", path, got)
		}
		var response map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatalf("%s unmarshal response: %v body=%s", path, err, rr.Body.String())
		}
		result, ok := response["result"].(map[string]any)
		if !ok {
			t.Fatalf("%s missing result: %#v", path, response)
		}
		if got := result["protocolVersion"]; got != "2025-06-18" {
			t.Fatalf("%s protocolVersion=%#v", path, got)
		}
	}
}

func TestServeHTTPCodexResetCreditsAlwaysReturnsEmpty(t *testing.T) {
	t.Parallel()

	h := &proxyHandler{cfg: &config{}}
	for _, path := range []string{
		"/backend-api/wham/rate-limit-reset-credits",
		"/api/codex/rate-limit-reset-credits",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer invalid-pool-token")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, rr.Code, rr.Body.String())
		}
		var response struct {
			AvailableCount int   `json:"available_count"`
			Credits        []any `json:"credits"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatalf("%s unmarshal: %v", path, err)
		}
		if response.AvailableCount != 0 || len(response.Credits) != 0 {
			t.Fatalf("%s response=%s", path, rr.Body.String())
		}
	}
}

func TestServeHTTPCodexResetCreditConsumeCannotReachUpstream(t *testing.T) {
	t.Parallel()

	h := &proxyHandler{cfg: &config{}}
	body := bytes.NewReader([]byte(`{"redeem_request_id":"request","credit_id":"credit"}`))
	req := httptest.NewRequest(http.MethodPost, "/backend-api/wham/rate-limit-reset-credits/consume", body)
	req.Header.Set("Authorization", "Bearer invalid-pool-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["code"] != "no_credit" || response["windows_reset"] != float64(0) {
		t.Fatalf("response=%#v", response)
	}
}

func TestServeHTTPCodexAppsMCPToolsListEmpty(t *testing.T) {
	t.Parallel()

	h := &proxyHandler{cfg: &config{}}
	body := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/wham/apps", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	result, _ := response["result"].(map[string]any)
	tools, ok := result["tools"].([]any)
	if !ok || len(tools) != 0 {
		t.Fatalf("tools=%#v want empty array", result["tools"])
	}
}

func TestServeHTTPCodexAppsMCPDoesNotRequirePoolToken(t *testing.T) {
	t.Parallel()

	// Reach the endpoint via proxyRequest path guard as well.
	h := &proxyHandler{cfg: &config{}}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	req := httptest.NewRequest(http.MethodPost, "/wham/apps", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.proxyRequest(rr, req, "test")
	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("proxyRequest returned 401 for codex_apps MCP: %s", rr.Body.String())
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestServeHTTPCodexConnectorsDirectoryReturnsEmptyList(t *testing.T) {
	t.Parallel()

	h := &proxyHandler{cfg: &config{}}
	req := httptest.NewRequest(http.MethodGet, "/connectors/directory/list?external_logos=true", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusOK)
	}
	var response map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	apps, ok := response["apps"].([]any)
	if !ok || len(apps) != 0 {
		t.Fatalf("apps=%#v want empty array", response["apps"])
	}
}

func TestStripCodexModelSuffixes(t *testing.T) {
	base, effort, tier := stripCodexModelSuffixes("gpt-5.4-mini-high-fast")
	if base != "gpt-5.4-mini" || effort != "high" || tier != "priority" {
		t.Fatalf("suffix parse = %q %q %q", base, effort, tier)
	}

	base, effort, tier = stripCodexModelSuffixes("gpt-5.6-sol-max")
	if base != "gpt-5.6-sol" || effort != "max" || tier != "" {
		t.Fatalf("max suffix parse = %q %q %q", base, effort, tier)
	}

	base, effort, tier = stripCodexModelSuffixes("gpt-5.6-ultra")
	if base != "gpt-5.6" || effort != "max" || tier != "" {
		t.Fatalf("ultra suffix parse = %q %q %q want gpt-5.6/max", base, effort, tier)
	}

	base, effort, tier = stripCodexModelSuffixes("gpt-5.6-sol-xhigh")
	if base != "gpt-5.6-sol" || effort != "xhigh" || tier != "" {
		t.Fatalf("xhigh suffix parse = %q %q %q", base, effort, tier)
	}
}

func TestEnsureCodexResponsesCompactBodyDoesNotForceStream(t *testing.T) {
	body := []byte(`{"model":"gpt-5.4-mini-high-fast","input":"summarize","stream":false,"store":true,"temperature":0,"parallel_tool_calls":true,"reasoning":{"summary":"auto"}}`)
	body, _ = applyCodexModelSuffixControls(body, "gpt-5.4-mini-high-fast")
	out := ensureCodexResponsesCompactBody(body)
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := got["stream"]; ok {
		t.Fatalf("compact body should not force stream: %#v", got)
	}
	if _, ok := got["store"]; ok {
		t.Fatalf("compact body should not preserve store: %#v", got)
	}
	if got["parallel_tool_calls"] != true {
		t.Fatalf("compact body should preserve parallel_tool_calls: %#v", got)
	}
	reasoning := got["reasoning"].(map[string]any)
	if reasoning["effort"] != "high" {
		t.Fatalf("reasoning suffix not applied: %#v", reasoning)
	}
	if got["service_tier"] != "priority" {
		t.Fatalf("service_tier suffix not applied: %#v", got)
	}
}

func TestEnsureCodexResponsesInstructionsStripsUnsupportedParams(t *testing.T) {
	t.Parallel()

	body := []byte(`{"model":"gpt-5.4-mini","input":"hi","temperature":0,"max_output_tokens":10,"parallel_tool_calls":true,"prompt_cache_key":"pc_client","prompt_cache_scope":"user|origin"}`)
	out := ensureCodexResponsesInstructions(body)
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	for _, key := range []string{"temperature", "max_output_tokens", "prompt_cache_scope"} {
		if _, ok := got[key]; ok {
			t.Fatalf("%s should not be forwarded to Codex: %#v", key, got)
		}
	}
	if got["instructions"] != "" {
		t.Fatalf("instructions should not be synthesized: %#v", got)
	}
	if stream, _ := got["stream"].(bool); !stream {
		t.Fatalf("stream = %#v, want true", got["stream"])
	}
	if key, _ := got["prompt_cache_key"].(string); key != "pc_client" {
		t.Fatalf("prompt_cache_key = %q, want client value", key)
	}
}

func TestTranslateImagesGenerationToResponses(t *testing.T) {
	body := []byte(`{"model":"gpt-image-1","prompt":"draw a cat","size":"1024x1024","output_format":"webp","response_format":"b64_json"}`)
	out, responseFormat, err := translateImagesGenerationToResponses(body)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if responseFormat != "b64_json" {
		t.Fatalf("response format = %q", responseFormat)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tools := got["tools"].([]any)
	tool := tools[0].(map[string]any)
	if got["model"] != "gpt-5.6-luna" {
		t.Fatalf("image model should map to host responses model: %#v", got["model"])
	}
	if tool["type"] != "image_generation" || tool["size"] != "1024x1024" || tool["output_format"] != "webp" || tool["partial_images"] != float64(0) {
		t.Fatalf("bad image tool: %#v", tool)
	}
	if got["stream"] != true || got["store"] != false {
		t.Fatalf("bad responses controls: %#v", got)
	}
	input := got["input"].([]any)[0].(map[string]any)
	content := input["content"].([]any)
	if content[0].(map[string]any)["text"] != "draw a cat" {
		t.Fatalf("image prompt should be forwarded verbatim: %#v", content[0])
	}
}

func TestTranslateImagesEditToResponses(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("model", "gpt-image-1")
	mw.WriteField("prompt", "turn this red")
	mw.WriteField("size", "1024x1024")
	part, err := mw.CreateFormFile("image", "in.png")
	if err != nil {
		t.Fatalf("create image part: %v", err)
	}
	part.Write([]byte("pngbytes"))
	mw.Close()

	out, responseFormat, err := translateImagesEditToResponses(buf.Bytes(), mw.FormDataContentType())
	if err != nil {
		t.Fatalf("translate edit: %v", err)
	}
	if responseFormat != "b64_json" {
		t.Fatalf("bad responseFormat=%q", responseFormat)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal edit: %v", err)
	}
	input := got["input"].([]any)[0].(map[string]any)
	content := input["content"].([]any)
	if len(content) != 2 || content[0].(map[string]any)["type"] != "input_text" || content[1].(map[string]any)["type"] != "input_image" {
		t.Fatalf("bad edit content: %#v", content)
	}
	if content[0].(map[string]any)["text"] != "turn this red" {
		t.Fatalf("image edit prompt should be forwarded verbatim: %#v", content[0])
	}
	if imageURL, _ := content[1].(map[string]any)["image_url"].(string); !strings.HasPrefix(imageURL, "data:image/") {
		t.Fatalf("bad image url: %q", imageURL)
	}
}

func TestTranslateResponsesToImagesGeneration(t *testing.T) {
	body := []byte(`{"id":"resp_1","created_at":123,"output":[{"type":"image_generation_call","result":"AAAA","revised_prompt":"better cat"}]}`)
	out, err := translateResponsesToImagesGeneration(body, "b64_json")
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	data := got["data"].([]any)
	entry := data[0].(map[string]any)
	if entry["b64_json"] != "AAAA" || entry["revised_prompt"] != "better cat" {
		t.Fatalf("bad image response: %#v", got)
	}
}

func TestRequestHasImageGenerationTool(t *testing.T) {
	t.Parallel()

	body := []byte(`{"model":"gpt-5.4","tools":[{"type":"image_generation"}]}`)
	if !requestHasImageGenerationTool(body) {
		t.Fatal("expected image_generation tool to be detected")
	}
	if requestHasImageGenerationTool([]byte(`{"tools":[{"type":"function"}]}`)) {
		t.Fatal("did not expect function tool to be detected as image generation")
	}
}

func TestResponsesBufferingWriterUsesLatestPartialImageAtStreamEnd(t *testing.T) {
	t.Parallel()

	writer := &responsesBufferingWriter{model: "gpt-5.6-luna"}
	events := []string{
		"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_img\",\"status\":\"in_progress\",\"model\":\"gpt-5.6-luna\"}}\n\n",
		"event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"item\":{\"id\":\"ig_1\",\"type\":\"image_generation_call\",\"status\":\"in_progress\"}}\n\n",
		"event: response.image_generation_call.partial_image\ndata: {\"type\":\"response.image_generation_call.partial_image\",\"item_id\":\"ig_1\",\"partial_image_b64\":\"FIRST\"}\n\n",
		"event: response.image_generation_call.partial_image\ndata: {\"type\":\"response.image_generation_call.partial_image\",\"item_id\":\"ig_1\",\"partial_image_b64\":\"LATEST\"}\n\n",
	}
	for _, event := range events {
		if _, err := writer.Write([]byte(event)); err != nil {
			t.Fatal(err)
		}
	}

	translated, err := translateResponsesToImagesGeneration(writer.Result(), "b64_json")
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	if err := json.Unmarshal(translated, &response); err != nil {
		t.Fatal(err)
	}
	data := response["data"].([]any)
	if got := data[0].(map[string]any)["b64_json"]; got != "LATEST" {
		t.Fatalf("b64_json = %#v, want latest partial image", got)
	}
}

func TestClientOrDefaultTimeoutDoesNotClampStreams(t *testing.T) {
	t.Parallel()

	streamReq := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	streamReq.Header.Set("X-Stainless-Timeout", "60")
	streamBody := []byte(`{"stream":true}`)
	if got := clientOrDefaultTimeout(streamReq, 10*time.Second, 0, streamBody); got != 0 {
		t.Fatalf("stream timeout = %v, want no timeout", got)
	}
	if got := clientOrDefaultTimeout(streamReq, 10*time.Second, 15*time.Minute, streamBody); got != 15*time.Minute {
		t.Fatalf("configured stream timeout = %v, want 15m", got)
	}

	imageReq := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	imageReq.Header.Set("X-Stainless-Timeout", "120")
	imageBody := []byte(`{"tools":[{"type":"image_generation"}]}`)
	if got := clientOrDefaultTimeout(imageReq, 10*time.Second, 0, imageBody); got != 5*time.Minute {
		t.Fatalf("image timeout = %v, want 5m", got)
	}

	plainReq := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	plainReq.Header.Set("X-Stainless-Timeout", "60")
	if got := clientOrDefaultTimeout(plainReq, 10*time.Second, 0, []byte(`{"stream":false}`)); got != time.Minute {
		t.Fatalf("plain timeout = %v, want 1m", got)
	}
}

func TestImageFanoutUsesLoopbackEndpoint(t *testing.T) {
	t.Parallel()

	h := &proxyHandler{cfg: &config{listenAddr: "0.0.0.0:14430"}}
	req := httptest.NewRequest(http.MethodPost, "https://codex.ppflix.net/v1/images/generations", nil)
	if got := h.imageFanoutEndpoint(req); got != "http://127.0.0.1:14430/v1/images/generations" {
		t.Fatalf("fanout endpoint = %q", got)
	}
}

func TestCodexPassthroughNeedsBodyRewrite(t *testing.T) {
	t.Parallel()

	if !codexPassthroughNeedsBodyRewrite("/v1/messages") {
		t.Fatal("expected /v1/messages to require rewrite")
	}
	if !codexPassthroughNeedsBodyRewrite("/v1/chat/completions") {
		t.Fatal("expected /v1/chat/completions to require rewrite")
	}
	if !codexPassthroughNeedsBodyRewrite("/v1/completions") {
		t.Fatal("expected /v1/completions to require rewrite")
	}
	if codexPassthroughNeedsBodyRewrite("/v1/models") {
		t.Fatal("did not expect /v1/models to require body rewrite")
	}
}

func TestCodexPassthroughRewrite(t *testing.T) {
	t.Parallel()

	claudeBody := []byte(`{"model":"gpt-5.4","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`)
	path, rewritten, err := codexPassthroughRewrite("/v1/messages", claudeBody)
	if err != nil {
		t.Fatalf("rewrite /v1/messages: %v", err)
	}
	if path != "/v1/responses" {
		t.Fatalf("rewritten path = %q", path)
	}
	var obj map[string]any
	if err := json.Unmarshal(rewritten, &obj); err != nil {
		t.Fatalf("unmarshal rewritten claude body: %v", err)
	}
	if stream, _ := obj["stream"].(bool); !stream {
		t.Fatalf("expected rewritten claude request to force stream=true, got %#v", obj["stream"])
	}

	chatBody := []byte(`{"model":"gpt-5.4","messages":[{"role":"user","content":"hi"}]}`)
	path, rewritten, err = codexPassthroughRewrite("/v1/chat/completions", chatBody)
	if err != nil {
		t.Fatalf("rewrite /v1/chat/completions: %v", err)
	}
	if path != "/v1/responses" {
		t.Fatalf("rewritten chat path = %q", path)
	}
	if err := json.Unmarshal(rewritten, &obj); err != nil {
		t.Fatalf("unmarshal rewritten chat body: %v", err)
	}
	if stream, _ := obj["stream"].(bool); !stream {
		t.Fatalf("expected rewritten chat request to force stream=true, got %#v", obj["stream"])
	}

	completionBody := []byte(`{"model":"gpt-5.4-mini","prompt":"hi"}`)
	path, rewritten, err = codexPassthroughRewrite("/v1/completions", completionBody)
	if err != nil {
		t.Fatalf("rewrite /v1/completions: %v", err)
	}
	if path != "/v1/responses" {
		t.Fatalf("rewritten completions path = %q", path)
	}
	if err := json.Unmarshal(rewritten, &obj); err != nil {
		t.Fatalf("unmarshal rewritten completions body: %v", err)
	}
	if stream, _ := obj["stream"].(bool); !stream {
		t.Fatalf("expected rewritten completions request to force stream=true, got %#v", obj["stream"])
	}
}

// mapToHeader is a tiny helper to build http.Header in tests without importing net/http everywhere.
func mapToHeader(m map[string]string) http.Header {
	h := http.Header{}
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}
