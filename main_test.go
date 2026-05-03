package main

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	if upstreamBeta != betaOAuth {
		t.Fatalf("upstream anthropic-beta = %q", upstreamBeta)
	}
	if obfuscatedToolName != "Bash" {
		t.Fatalf("tool name should be preserved, got %q", obfuscatedToolName)
	}
	system, _ := upstreamBody["system"].([]any)
	systemBlock, _ := system[0].(map[string]any)
	systemCache, _ := systemBlock["cache_control"].(map[string]any)
	if systemBlock["text"] != "be helpful" || systemCache["ttl"] != "5m" {
		t.Fatalf("system cache block was rewritten: %#v", systemBlock)
	}
	tools, _ := upstreamBody["tools"].([]any)
	tool, _ := tools[0].(map[string]any)
	toolCache, _ := tool["cache_control"].(map[string]any)
	if tool["name"] != "Bash" || toolCache["ttl"] != "5m" {
		t.Fatalf("tool cache block was rewritten: %#v", tool)
	}
	messages, _ := upstreamBody["messages"].([]any)
	first, _ := messages[0].(map[string]any)
	content, _ := first["content"].([]any)
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

	var found map[string]any
	for _, model := range models {
		m, ok := model.(map[string]any)
		if ok && m["slug"] == "gpt-5.5" {
			found = m
			break
		}
	}
	if found == nil {
		t.Fatalf("missing gpt-5.5 in injected catalog: %#v", models)
	}
	if got := int(found["context_window"].(float64)); got != 272000 {
		t.Fatalf("gpt-5.5 context_window = %d", got)
	}
	if got := found["display_name"]; got != "gpt-5.5" {
		t.Fatalf("gpt-5.5 display_name = %#v", got)
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
		"X-Codex-Primary-Used-Percent":   "25",
		"X-Codex-Secondary-Used-Percent": "50",
		"X-Codex-Primary-Window-Minutes": "300",
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
	if !claudeRequestRequiresPremium(nil, "claude-sonnet-4-6 [1m]") {
		t.Fatal("expected [1m] model suffix to require a premium Claude account")
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Header.Set("anthropic-beta", "context-1m-2025-08-07")
	if !claudeRequestRequiresPremium(req, "claude-sonnet-4-6") {
		t.Fatal("expected 1m beta header to require a premium Claude account")
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
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/backend-api/wham/apps", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusOK)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type=%q want application/json", got)
	}
	var response map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	result, ok := response["result"].(map[string]any)
	if !ok {
		t.Fatalf("missing result: %#v", response)
	}
	if got := result["protocolVersion"]; got != "2025-11-25" {
		t.Fatalf("protocolVersion=%#v", got)
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

func TestCodexPassthroughNeedsBodyRewrite(t *testing.T) {
	t.Parallel()

	if !codexPassthroughNeedsBodyRewrite("/v1/messages") {
		t.Fatal("expected /v1/messages to require rewrite")
	}
	if !codexPassthroughNeedsBodyRewrite("/v1/chat/completions") {
		t.Fatal("expected /v1/chat/completions to require rewrite")
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
}

// mapToHeader is a tiny helper to build http.Header in tests without importing net/http everywhere.
func mapToHeader(m map[string]string) http.Header {
	h := http.Header{}
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}
