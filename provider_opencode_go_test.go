package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpencodeGoLoadAccount(t *testing.T) {
	t.Parallel()

	p := NewOpencodeGoProvider(mustParse("https://opencode.ai/zen/go/v1"))
	acc, err := p.LoadAccount("main.json", "/pool/opencode_go/main.json", []byte(`{"api_key":"sk-go-test"}`))
	if err != nil {
		t.Fatal(err)
	}
	if acc == nil {
		t.Fatal("expected account, got nil")
	}
	if acc.Type != AccountTypeOpencodeGo || acc.ID != "main" || acc.AccessToken != "sk-go-test" || acc.PlanType != "opencode_go" {
		t.Fatalf("unexpected account: %#v", acc)
	}

	empty, err := p.LoadAccount("empty.json", "/pool/opencode_go/empty.json", []byte(`{"api_key":""}`))
	if err != nil {
		t.Fatal(err)
	}
	if empty != nil {
		t.Fatalf("expected nil for empty key, got %#v", empty)
	}
}

func TestOpencodeGoAuthHeaders(t *testing.T) {
	t.Parallel()

	p := NewOpencodeGoProvider(mustParse("https://opencode.ai/zen/go/v1"))
	acc := &Account{Type: AccountTypeOpencodeGo, AccessToken: "sk-go-test"}
	req := httptest.NewRequest(http.MethodPost, "https://opencode.ai/zen/go/v1/chat/completions", nil)
	p.SetAuthHeaders(req, acc)
	if got := req.Header.Get("Authorization"); got != "Bearer sk-go-test" {
		t.Fatalf("Authorization = %q", got)
	}
	// The Anthropic-compatible /messages route authenticates on x-api-key.
	if got := req.Header.Get("X-Api-Key"); got != "sk-go-test" {
		t.Fatalf("X-Api-Key = %q", got)
	}
	if p.MatchesPath("/v1/messages") {
		t.Fatal("Go should be model-routed, not path-routed")
	}
}

func TestOpencodeGoNormalizePath(t *testing.T) {
	t.Parallel()

	p := NewOpencodeGoProvider(mustParse("https://opencode.ai/zen/go/v1"))
	cases := map[string]string{
		"/v1/messages":         "/messages",
		"/v1/chat/completions": "/chat/completions",
		"/v1/responses":        "/responses",
	}
	for in, want := range cases {
		if got := p.NormalizePath(in); got != want {
			t.Fatalf("NormalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOpencodeGoEndpointForModel(t *testing.T) {
	t.Parallel()

	for _, model := range []string{"grok-4.6", "grok-4.5", "gpt-5.6-luna", "muse-spark-1.3-contributor", "muse-spark-1.2-contributor"} {
		if got := opencodeGoEndpointForModel(model); got != opencodeGoEndpointResponses {
			t.Fatalf("endpoint(%q) = %q, want responses", model, got)
		}
	}
	for _, model := range []string{"minimax-m3", "minimax-m2.7", "minimax-m2.5", "qwen3.8-max", "qwen3.8-flash", "qwen3.7-max", "qwen3.7-plus", "qwen3.6-plus"} {
		if got := opencodeGoEndpointForModel(model); got != opencodeGoEndpointMessages {
			t.Fatalf("endpoint(%q) = %q, want messages", model, got)
		}
	}
	for _, model := range []string{"kimi-k3", "longcat-2.0", "omen-alpha", "hy3", "glm-5.3", "deepseek-v4-flash", "mimo-v2.5-pro", "qwen3.5-plus"} {
		if got := opencodeGoEndpointForModel(model); got != opencodeGoEndpointChat {
			t.Fatalf("endpoint(%q) = %q, want chat", model, got)
		}
	}
}

func TestIsOpencodeGoModel(t *testing.T) {
	t.Parallel()

	// Prefixed references always route to Go when the model exists.
	for _, model := range []string{"opencode-go/kimi-k3", "opencode-go/longcat-2.0", "opencode-go/grok-4.6", "opencode_go/hy3", "OPencode-GO/MIMO-V2.5"} {
		if !isOpencodeGoModel(model) {
			t.Fatalf("expected %q to route to opencode-go", model)
		}
	}
	if isOpencodeGoModel("opencode-go/no-such-model") {
		t.Fatal("unknown prefixed model should not route to opencode-go")
	}

	// Bare IDs route to Go only when no other provider claims them.
	for _, model := range []string{"longcat-2.0", "omen-alpha", "hy3", "hy4-preview", "qwen3.8-max", "deepseek-v4-pro", "kimi-k3", "kimi-k2.5"} {
		if !isOpencodeGoModel(model) {
			t.Fatalf("expected bare %q to route to opencode-go", model)
		}
	}
	for _, model := range []string{
		"k3", "kimi-for-coding", // kimi
		"MiniMax-M3", "minimax-m2.7", // minimax
		"glm-5.2", "glm-5.3", "glm-5.3-flash", // zai
		"mimo-v2.5-pro", "mimo-v2.5", // xiaomi
		"grok-4.6", "grok-4.5", // grok
		"gpt-5.6-luna", // codex overlap
		"", "   ",
	} {
		if isOpencodeGoModel(model) {
			t.Fatalf("did not expect bare %q to route to opencode-go", model)
		}
	}
}

func TestOpencodeGoCanonicalModel(t *testing.T) {
	t.Parallel()

	if got := opencodeGoCanonicalModel("opencode-go/longcat-2.0"); got != "opencode-go/longcat-2.0" {
		t.Fatalf("canonical = %q", got)
	}
	if got := opencodeGoCanonicalModel("longcat-2.0"); got != "opencode-go/longcat-2.0" {
		t.Fatalf("canonical bare = %q", got)
	}
	if got := opencodeGoUpstreamModel("opencode-go/longcat-2.0"); got != "longcat-2.0" {
		t.Fatalf("upstream = %q", got)
	}
	if got := opencodeGoUpstreamModel("longcat-2.0"); got != "longcat-2.0" {
		t.Fatalf("upstream bare = %q", got)
	}
}

func opencodeGoTestHandler(base *url.URL) *proxyHandler {
	return &proxyHandler{
		registry: NewProviderRegistry(
			NewCodexProvider(base, base, base),
			NewClaudeProvider(base),
			NewGeminiProvider(base, base),
			NewKimiProvider(base),
			NewMinimaxProvider(base),
			NewZAIProvider(base),
			NewXiaomiProvider(base),
			NewGrokProvider(base),
			NewAdverserialProvider(base),
			NewOpencodeGoProvider(base),
		),
	}
}

func TestModelRouteOverrideOpencodeGo(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.test")
	handler := opencodeGoTestHandler(base)

	// Prefixed references route to Go even for overlapping models.
	for _, model := range []string{"opencode-go/kimi-k3", "opencode-go/mimo-v2.5-pro", "opencode-go/grok-4.6", "opencode-go/longcat-2.0"} {
		provider, _, rewritten := handler.modelRouteOverride("/v1/chat/completions", model, []byte(`{"model":"`+model+`"}`))
		if provider == nil || provider.Type() != AccountTypeOpencodeGo {
			t.Fatalf("modelRouteOverride(%q) provider=%v, want opencode-go", model, provider)
		}
		var body map[string]any
		if err := json.Unmarshal(rewritten, &body); err != nil {
			t.Fatal(err)
		}
		want := opencodeGoUpstreamModel(model)
		if body["model"] != want {
			t.Fatalf("rewritten model = %v, want bare %q", body["model"], want)
		}
	}

	// Bare overlapping IDs keep their existing provider.
	overlaps := map[string]AccountType{
		"mimo-v2.5-pro":  AccountTypeXiaomi,
		"glm-5.2":        AccountTypeZAI,
		"grok-4.6":       AccountTypeGrok,
		"kimi-for-coding": AccountTypeKimi,
	}
	for model, want := range overlaps {
		provider, _, _ := handler.modelRouteOverride("/v1/messages", model, []byte(`{"model":"`+model+`"}`))
		if provider == nil || provider.Type() != want {
			t.Fatalf("modelRouteOverride(%q) provider=%v, want %s", model, provider, want)
		}
	}

	// Bare unique IDs route to Go.
	provider, _, rewritten := handler.modelRouteOverride("/v1/chat/completions", "longcat-2.0", []byte(`{"model":"longcat-2.0"}`))
	if provider == nil || provider.Type() != AccountTypeOpencodeGo {
		t.Fatalf("modelRouteOverride(longcat-2.0) provider=%v, want opencode-go", provider)
	}
	var body map[string]any
	if err := json.Unmarshal(rewritten, &body); err != nil {
		t.Fatal(err)
	}
	if body["model"] != "longcat-2.0" {
		t.Fatalf("rewritten model = %v", body["model"])
	}
}

func TestResolveStreamedModelRouteOpencodeGo(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://example.test")
	handler := opencodeGoTestHandler(base)

	provider, _, canonical := handler.resolveStreamedModelRoute("/v1/responses", "opencode-go/gpt-5.6-luna")
	if provider == nil || provider.Type() != AccountTypeOpencodeGo {
		t.Fatalf("streamed route provider=%v, want opencode-go", provider)
	}
	if canonical != "gpt-5.6-luna" {
		t.Fatalf("streamed canonical = %q, want bare upstream id", canonical)
	}

	// Overlapping bare IDs still resolve to their original provider first.
	provider, _, _ = handler.resolveStreamedModelRoute("/v1/responses", "mimo-v2.5-pro")
	if provider == nil || provider.Type() != AccountTypeXiaomi {
		t.Fatalf("streamed route provider=%v, want xiaomi", provider)
	}
}

func TestParseOpencodeGoUsage(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	resetsRolling := now.Add(2 * time.Hour).UTC().Format(time.RFC3339)
	resetsWeekly := now.Add(48 * time.Hour).UTC().Format(time.RFC3339)
	body := []byte(`{"usage":{
		"rolling":{"status":"ok","percent":12.5,"resetsAt":"` + resetsRolling + `"},
		"weekly":{"status":"rate-limited","percent":99.2,"resetsAt":"` + resetsWeekly + `"},
		"monthly":{"status":"ok","percent":45.0,"resetsAt":"` + resetsWeekly + `" }}}`)

	state, err := parseOpencodeGoUsage(body, now)
	if err != nil {
		t.Fatal(err)
	}
	if state.snapshot.PrimaryUsedPercent != 0.125 {
		t.Fatalf("primary = %v, want 0.125", state.snapshot.PrimaryUsedPercent)
	}
	if state.snapshot.SecondaryUsedPercent != 0.992 {
		t.Fatalf("secondary = %v, want 0.992", state.snapshot.SecondaryUsedPercent)
	}
	if state.snapshot.PrimaryWindowMinutes != 300 || state.snapshot.SecondaryWindowMinutes != 10080 {
		t.Fatalf("windows = %d/%d", state.snapshot.PrimaryWindowMinutes, state.snapshot.SecondaryWindowMinutes)
	}
	if state.monthlyPct != 0.45 {
		t.Fatalf("monthly = %v", state.monthlyPct)
	}
	if !state.limited {
		t.Fatal("expected limited=true from rate-limited weekly window")
	}
	if state.limitedUntil.IsZero() || !state.limitedUntil.After(now) {
		t.Fatalf("limitedUntil = %v", state.limitedUntil)
	}
	if _, err := parseOpencodeGoUsage([]byte(`{bad`), now); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestFetchOpencodeGoUsage(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/usage" {
			t.Errorf("usage path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"usage":{
			"rolling":{"status":"ok","percent":10.0,"resetsAt":"` + now.Add(time.Hour).UTC().Format(time.RFC3339) + `"},
			"weekly":{"status":"ok","percent":20.0,"resetsAt":"` + now.Add(24*time.Hour).UTC().Format(time.RFC3339) + `"},
			"monthly":{"status":"ok","percent":30.0,"resetsAt":"` + now.Add(24*time.Hour).UTC().Format(time.RFC3339) + `" }}}`))
	}))
	defer server.Close()

	base, _ := url.Parse(server.URL)
	acc := &Account{Type: AccountTypeOpencodeGo, ID: "go", AccessToken: "sk-go-test"}
	h := &proxyHandler{cfg: &config{opencodeGoBase: base}, transport: http.DefaultTransport}
	if err := h.fetchOpencodeGoUsage(now, acc); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer sk-go-test" {
		t.Fatalf("usage auth = %q", gotAuth)
	}
	acc.mu.Lock()
	defer acc.mu.Unlock()
	if acc.Usage.PrimaryUsedPercent != 0.10 || acc.Usage.SecondaryUsedPercent != 0.20 {
		t.Fatalf("usage = %.2f/%.2f", acc.Usage.PrimaryUsedPercent, acc.Usage.SecondaryUsedPercent)
	}
	if acc.Usage.Source != "opencode-go-usage" {
		t.Fatalf("source = %q", acc.Usage.Source)
	}
}

func TestFetchOpencodeGoUsageUnauthorizedMarksDead(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	accountFile := filepath.Join(dir, "go.json")
	if err := os.WriteFile(accountFile, []byte(`{"api_key":"sk-bad"}`), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	base, _ := url.Parse(server.URL)
	acc := &Account{Type: AccountTypeOpencodeGo, ID: "go", File: accountFile, AccessToken: "sk-bad"}
	h := &proxyHandler{cfg: &config{opencodeGoBase: base}, transport: http.DefaultTransport}
	if err := h.fetchOpencodeGoUsage(time.Now(), acc); err == nil {
		t.Fatal("expected error for 401 usage")
	}
	acc.mu.Lock()
	dead := acc.Dead
	acc.mu.Unlock()
	if !dead {
		t.Fatal("expected account marked dead after 401")
	}
	data, _ := os.ReadFile(accountFile)
	if !strings.Contains(string(data), `"dead": true`) {
		t.Fatalf("dead flag not persisted: %s", data)
	}
}

func TestProxyRequestRoutesOpencodeGoModel(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	goBase, _ := url.Parse("https://opencode.ai/zen/go/v1")
	claudeBase, _ := url.Parse("https://api.anthropic.com")
	codexBase, _ := url.Parse("https://chatgpt.com/backend-api/codex")
	acc := &Account{Type: AccountTypeOpencodeGo, ID: "go", AccessToken: "sk-go-upstream", PlanType: "opencode_go"}

	var upstreamURL, upstreamAuth, upstreamAPIKey string
	var upstreamBody map[string]any

	h := &proxyHandler{
		cfg:     &config{maxAttempts: 1, maxInMemoryBodyBytes: 4096},
		pool:    newPoolState([]*Account{acc}, false),
		metrics: newMetrics(),
		recent:  newRecentErrors(5),
		registry: NewProviderRegistry(
			NewCodexProvider(codexBase, codexBase, nil),
			NewClaudeProvider(claudeBase),
			NewGeminiProvider(claudeBase, claudeBase),
			NewOpencodeGoProvider(goBase),
		),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			upstreamURL = req.URL.String()
			upstreamAuth = req.Header.Get("Authorization")
			upstreamAPIKey = req.Header.Get("X-Api-Key")
			body, _ := io.ReadAll(req.Body)
			_ = json.Unmarshal(body, &upstreamBody)
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"id":"chatcmpl-1","object":"chat.completion","model":"longcat-2.0","choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3}}`)),
			}, nil
		}),
	}

	reqBody := []byte(`{"model":"opencode-go/longcat-2.0","messages":[{"role":"user","content":"hi"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", generateClaudePoolToken("test-secret", "go-user"))
	rr := httptest.NewRecorder()

	h.proxyRequest(rr, req, "req-go")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if upstreamURL != "https://opencode.ai/zen/go/v1/chat/completions" {
		t.Fatalf("upstream URL = %q", upstreamURL)
	}
	if upstreamAuth != "Bearer sk-go-upstream" {
		t.Fatalf("Authorization = %q", upstreamAuth)
	}
	if upstreamAPIKey != "sk-go-upstream" {
		t.Fatalf("X-Api-Key = %q", upstreamAPIKey)
	}
	if upstreamBody["model"] != "longcat-2.0" {
		t.Fatalf("upstream model = %v, want bare id", upstreamBody["model"])
	}
}

func TestOpencodeGoAdminAddValidatesAndSavesAccount(t *testing.T) {
	t.Parallel()

	poolDir := t.TempDir()
	goBase, _ := url.Parse("https://opencode.ai/zen/go/v1")
	validationCalled := false
	h := &proxyHandler{
		cfg:     &config{poolDir: poolDir, opencodeGoBase: goBase},
		pool:    newPoolState(nil, false),
		metrics: newMetrics(),
		recent:  newRecentErrors(5),
		registry: NewProviderRegistry(
			&CodexProvider{},
			&ClaudeProvider{},
			&GeminiProvider{},
			NewOpencodeGoProvider(goBase),
		),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			validationCalled = true
			if req.URL.String() != "https://opencode.ai/zen/go/v1/usage" {
				t.Fatalf("validation URL = %q", req.URL.String())
			}
			if req.Header.Get("Authorization") != "Bearer sk-go-valid" {
				t.Fatalf("validation auth = %q", req.Header.Get("Authorization"))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"usage":{"rolling":{"status":"ok","percent":1.0},"weekly":{"status":"ok","percent":2.0},"monthly":{"status":"ok","percent":3.0}}}`)),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/opencode-go/add", strings.NewReader(`{"api_key":"sk-go-valid"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleOpencodeGoAdd(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if !validationCalled {
		t.Fatal("validation was not called")
	}
	entries, err := os.ReadDir(filepath.Join(poolDir, "opencode_go"))
	if err != nil {
		t.Fatalf("read opencode_go pool dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("saved %d files, want 1", len(entries))
	}
	if h.pool.countByType(AccountTypeOpencodeGo) != 1 {
		t.Fatalf("pool opencode-go count = %d, want 1", h.pool.countByType(AccountTypeOpencodeGo))
	}
}

func TestOpencodeGoAdminRejectsKeyWithoutSubscription(t *testing.T) {
	t.Parallel()

	poolDir := t.TempDir()
	goBase, _ := url.Parse("https://opencode.ai/zen/go/v1")
	h := &proxyHandler{
		cfg:     &config{poolDir: poolDir, opencodeGoBase: goBase},
		pool:    newPoolState(nil, false),
		metrics: newMetrics(),
		recent:  newRecentErrors(5),
		registry: NewProviderRegistry(
			&CodexProvider{},
			&ClaudeProvider{},
			&GeminiProvider{},
			NewOpencodeGoProvider(goBase),
		),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Status:     "403 Forbidden",
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"type":"error","error":{"type":"EntitlementError","message":"OpenCode Go subscription required."}}`)),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/opencode-go/add", strings.NewReader(`{"api_key":"sk-go-nosub"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleOpencodeGoAdd(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatal("expected rejection for key without subscription")
	}
	if _, err := os.Stat(filepath.Join(poolDir, "opencode_go")); !os.IsNotExist(err) {
		t.Fatal("pool dir should not exist after rejected key")
	}
}

func TestLoadPoolLoadsOpencodeGoAccounts(t *testing.T) {
	t.Parallel()

	poolDir := t.TempDir()
	goDir := filepath.Join(poolDir, "opencode_go")
	if err := os.MkdirAll(goDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(goDir, "one.json"), []byte(`{"api_key":"sk-one"}`), 0600); err != nil {
		t.Fatal(err)
	}

	goBase, _ := url.Parse("https://opencode.ai/zen/go/v1")
	registry := NewProviderRegistry(&CodexProvider{}, &ClaudeProvider{}, &GeminiProvider{}, NewOpencodeGoProvider(goBase))
	accounts, err := loadPool(poolDir, registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 {
		t.Fatalf("accounts = %d, want 1", len(accounts))
	}
	if accounts[0].Type != AccountTypeOpencodeGo || accounts[0].ID != "one" || accounts[0].AccessToken != "sk-one" {
		t.Fatalf("unexpected account: %#v", accounts[0])
	}
}

func TestOpencodeGoCatalogCoversLiveModels(t *testing.T) {
	t.Parallel()

	// Every live Go model ID must resolve to a catalog entry, prefixed or bare.
	for _, bare := range []string{
		"kimi-k2.7-code", "qwen3.7-max", "kimi-k3", "muse-spark-1.3-contributor",
		"deepseek-v4-flash", "omen-alpha", "mimo-v2.5", "grok-4.6", "grok-4.5",
		"deepseek-v4-pro", "qwen3.5-plus", "gpt-5.6-luna", "glm-5", "minimax-m3",
		"minimax-m2.7", "qwen3.8-max", "mimo-v2-pro", "qwen3.7-plus", "qwen3.8-flash",
		"glm-5.3", "kimi-k2.5", "glm-5.2", "minimax-m2.5", "mimo-v2-omni",
		"longcat-2.0", "qwen3.6-plus", "hy4-preview", "glm-5.1", "mimo-v2.5-pro",
		"hy3", "hy3-preview", "muse-spark-1.2-contributor", "kimi-k2.6",
		"deepseek-v4-flash-vision-exp", "glm-5.3-flash",
	} {
		if _, ok := modelForProvider(AccountTypeOpencodeGo, opencodeGoCatalogID(bare)); !ok {
			t.Errorf("no catalog entry for Go model %q", bare)
		}
	}
}
