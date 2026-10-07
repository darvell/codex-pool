package main

import (
	"bytes"
	"context"
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

func TestMistralBareIDAndCatalogID(t *testing.T) {
	t.Parallel()

	if bare, ok := mistralBareID("mistral/mistral-large-latest"); !ok || bare != "mistral-large-latest" {
		t.Fatalf("mistralBareID = %q, %v", bare, ok)
	}
	if bare, ok := mistralBareID("MISTRAL/Codestral-Latest"); !ok || bare != "Codestral-Latest" {
		t.Fatalf("mistralBareID case-insensitive prefix = %q, %v", bare, ok)
	}
	if _, ok := mistralBareID("mistral/"); ok {
		t.Fatal("empty upstream id should not be a valid Mistral model")
	}
	if _, ok := mistralBareID("mistral-large-latest"); ok {
		t.Fatal("bare id without namespace should not match")
	}
	if _, ok := mistralBareID("glm-5.3"); ok {
		t.Fatal("unrelated bare id should not match Mistral")
	}

	if got := mistralCatalogID("mistral-large-latest"); got != "mistral/mistral-large-latest" {
		t.Fatalf("mistralCatalogID = %q", got)
	}
	// mistralCatalogID is idempotent: passing an already-namespaced id does not
	// double-prefix it, since it strips any existing "mistral/" prefix first.
	if got := mistralCatalogID("mistral/mistral-large-latest"); got != "mistral/mistral-large-latest" {
		t.Fatalf("mistralCatalogID with pre-namespaced input = %q", got)
	}

	if !isMistralModel("mistral/mistral-large-latest") {
		t.Fatal("expected namespaced id to route to Mistral")
	}
	if isMistralModel("mistral-large-latest") {
		t.Fatal("bare id must never route to Mistral; the catalog overlaps other pools")
	}
	if isMistralModel("glm-5.3") {
		t.Fatal("unrelated bare id must not route to Mistral")
	}

	if got := mistralCanonicalModel("mistral/mistral-large-latest"); got != "mistral-large-latest" {
		t.Fatalf("mistralCanonicalModel = %q", got)
	}
	if got := mistralCanonicalModel("mistral-large-latest"); got != "mistral-large-latest" {
		t.Fatalf("mistralCanonicalModel passthrough = %q", got)
	}
}

func TestMistralProviderLoadAccount(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://api.mistral.ai")
	provider := NewMistralProvider(base)

	acc, err := provider.LoadAccount("work.json", "/pool/mistral/work.json", []byte(`{"api_key":"  sk-live  "}`))
	if err != nil {
		t.Fatal(err)
	}
	if acc == nil {
		t.Fatal("expected account, got nil")
	}
	if acc.Type != AccountTypeMistral || acc.ID != "work" || acc.AccessToken != "sk-live" || acc.PlanType != "mistral_api" {
		t.Fatalf("unexpected account: %#v", acc)
	}

	empty, err := provider.LoadAccount("empty.json", "/pool/mistral/empty.json", []byte(`{"api_key":"   "}`))
	if err != nil {
		t.Fatal(err)
	}
	if empty != nil {
		t.Fatalf("expected nil account for blank api_key, got %#v", empty)
	}

	deadAcc, err := provider.LoadAccount("dead.json", "/pool/mistral/dead.json", []byte(`{"api_key":"sk-dead","dead":true,"disabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if deadAcc == nil || !deadAcc.Dead || !deadAcc.Disabled {
		t.Fatalf("unexpected dead account: %#v", deadAcc)
	}

	if _, err := provider.LoadAccount("bad.json", "/pool/mistral/bad.json", []byte(`not json`)); err == nil {
		t.Fatal("expected parse error for malformed JSON")
	}
}

func TestMistralProviderAuthHeadersAndPathHandling(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://api.mistral.ai")
	provider := NewMistralProvider(base)
	acc := &Account{Type: AccountTypeMistral, AccessToken: "sk-test"}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	provider.SetAuthHeaders(req, acc)
	if got := req.Header.Get("Authorization"); got != "Bearer sk-test" {
		t.Fatalf("Authorization = %q", got)
	}

	if provider.MatchesPath("/v1/chat/completions") {
		t.Fatal("Mistral is model-routed, not path-routed")
	}
	if got := provider.UpstreamURL("/v1/chat/completions"); got != base {
		t.Fatalf("UpstreamURL = %v, want %v", got, base)
	}
	if got := provider.NormalizePath("/some/prefix/chat/completions/"); got != "/v1/chat/completions" {
		t.Fatalf("NormalizePath = %q", got)
	}
	if got := provider.NormalizePath("/v1/models"); got != "/v1/models" {
		t.Fatalf("NormalizePath should pass through non-chat paths unchanged, got %q", got)
	}
	if !provider.DetectsSSE("", "text/event-stream; charset=utf-8") {
		t.Fatal("expected SSE detection for text/event-stream content type")
	}
	if provider.DetectsSSE("", "application/json") {
		t.Fatal("did not expect SSE detection for application/json")
	}
	if err := provider.RefreshToken(nil, acc, nil); err != nil {
		t.Fatalf("RefreshToken should be a no-op for static keys: %v", err)
	}
}

func TestMistralProviderParseUsage(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://api.mistral.ai")
	provider := NewMistralProvider(base)

	usage := provider.ParseUsage(map[string]any{
		"model": "mistral-large-latest",
		"usage": map[string]any{
			"prompt_tokens":     float64(100),
			"completion_tokens": float64(20),
			"prompt_tokens_details": map[string]any{
				"cached_tokens": float64(30),
			},
		},
	})
	if usage == nil {
		t.Fatal("expected usage, got nil")
	}
	if usage.InputTokens != 100 || usage.OutputTokens != 20 || usage.CachedInputTokens != 30 {
		t.Fatalf("unexpected usage: %#v", usage)
	}
	if usage.BillableTokens != 90 { // 100 - 30 + 20
		t.Fatalf("BillableTokens = %d, want 90", usage.BillableTokens)
	}
	if usage.InputTokenMode != "inclusive" {
		t.Fatalf("InputTokenMode = %q, want inclusive", usage.InputTokenMode)
	}
	if usage.Model != "mistral/mistral-large-latest" {
		t.Fatalf("Model = %q, want namespaced public id", usage.Model)
	}

	// Falls back to input_tokens/output_tokens naming if prompt/completion absent.
	altNaming := provider.ParseUsage(map[string]any{
		"model": "codestral-latest",
		"usage": map[string]any{"input_tokens": float64(5), "output_tokens": float64(2)},
	})
	if altNaming == nil || altNaming.InputTokens != 5 || altNaming.OutputTokens != 2 {
		t.Fatalf("unexpected alt-naming usage: %#v", altNaming)
	}

	if got := provider.ParseUsage(map[string]any{"usage": map[string]any{}}); got != nil {
		t.Fatalf("expected nil usage for zero tokens, got %#v", got)
	}
	if got := provider.ParseUsage(map[string]any{}); got != nil {
		t.Fatalf("expected nil usage when usage field is absent, got %#v", got)
	}

	var headers http.Header
	provider.ParseUsageHeaders(&Account{}, headers) // must not panic; intentionally a no-op
}

func TestMistralReasoningEffortCollapsesToNoneOrHigh(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in        string
		want      string
		wantValid bool
	}{
		{"none", "none", true},
		{"low", "none", true},
		{"minimal", "none", true},
		{"Low", "none", true},
		{" LOW ", "none", true},
		{"medium", "high", true},
		{"high", "high", true},
		{"max", "high", true},
		{"", "", false},
		{"ultra", "", false},
	}
	for _, tc := range tests {
		got, valid := mistralReasoningEffort(tc.in)
		if got != tc.want || valid != tc.wantValid {
			t.Fatalf("mistralReasoningEffort(%q) = (%q, %v), want (%q, %v)", tc.in, got, valid, tc.want, tc.wantValid)
		}
	}
}

func TestRewriteMistralRequestBodyCanonicalizesModelStreamAndReasoning(t *testing.T) {
	t.Parallel()

	body := []byte(`{"model":"mistral/mistral-large-latest","stream":true,"reasoning_effort":"medium","messages":[{"role":"user","content":"hi"}]}`)
	rewritten := rewriteMistralRequestBody(body, "mistral/mistral-large-latest")

	var obj map[string]any
	if err := json.Unmarshal(rewritten, &obj); err != nil {
		t.Fatalf("rewritten body is not valid JSON: %v: %s", err, rewritten)
	}
	if obj["model"] != "mistral-large-latest" {
		t.Fatalf("model = %v, want canonical bare id", obj["model"])
	}
	options, _ := obj["stream_options"].(map[string]any)
	if options == nil || options["include_usage"] != true {
		t.Fatalf("stream_options = %v, want include_usage=true", obj["stream_options"])
	}
	if obj["reasoning_effort"] != "high" {
		t.Fatalf("reasoning_effort = %v, want collapsed to high", obj["reasoning_effort"])
	}

	// Pi's Chat Completions adapter sends developer messages and store:false;
	// Mistral rejects both unless the pool normalizes them.
	piBody := []byte(`{"model":"mistral/mistral-small-latest","store":false,"messages":[{"role":"developer","content":"instructions"},{"role":"user","content":"hi"}]}`)
	var piObj map[string]any
	if err := json.Unmarshal(rewriteMistralRequestBody(piBody, "mistral/mistral-small-latest"), &piObj); err != nil {
		t.Fatal(err)
	}
	if _, present := piObj["store"]; present {
		t.Fatal("Mistral rejects the OpenAI store field")
	}
	messages := piObj["messages"].([]any)
	if messages[0].(map[string]any)["role"] != "system" || messages[1].(map[string]any)["role"] != "user" {
		t.Fatalf("Pi message roles not normalized: %v", messages)
	}

	// low/minimal collapse to none.
	lowBody := []byte(`{"model":"mistral-large-latest","reasoning_effort":"low"}`)
	lowRewritten := rewriteMistralRequestBody(lowBody, "mistral-large-latest")
	var lowObj map[string]any
	if err := json.Unmarshal(lowRewritten, &lowObj); err != nil {
		t.Fatal(err)
	}
	if lowObj["reasoning_effort"] != "none" {
		t.Fatalf("reasoning_effort = %v, want none", lowObj["reasoning_effort"])
	}

	// Unknown effort values are dropped rather than forwarded verbatim.
	unknownBody := []byte(`{"model":"mistral-large-latest","reasoning_effort":"ultra"}`)
	unknownRewritten := rewriteMistralRequestBody(unknownBody, "mistral-large-latest")
	var unknownObj map[string]any
	if err := json.Unmarshal(unknownRewritten, &unknownObj); err != nil {
		t.Fatal(err)
	}
	if _, present := unknownObj["reasoning_effort"]; present {
		t.Fatalf("expected unrecognized reasoning_effort to be dropped, got %v", unknownObj["reasoning_effort"])
	}

	// No stream, no reasoning_effort: body is left otherwise untouched besides model.
	plainBody := []byte(`{"model":"mistral/codestral-latest","messages":[]}`)
	plainRewritten := rewriteMistralRequestBody(plainBody, "mistral/codestral-latest")
	var plainObj map[string]any
	if err := json.Unmarshal(plainRewritten, &plainObj); err != nil {
		t.Fatal(err)
	}
	if plainObj["model"] != "codestral-latest" {
		t.Fatalf("model = %v", plainObj["model"])
	}
	if _, present := plainObj["stream_options"]; present {
		t.Fatal("did not expect stream_options for a non-streaming request")
	}

	// Malformed JSON is returned unchanged rather than dropped.
	if got := rewriteMistralRequestBody([]byte("not json"), "mistral-large-latest"); string(got) != "not json" {
		t.Fatalf("malformed body should pass through unchanged, got %q", got)
	}
	if got := rewriteMistralRequestBody(nil, "mistral-large-latest"); got != nil {
		t.Fatalf("nil body should pass through unchanged, got %q", got)
	}
}

func TestRewriteMistralRequestBodyRestoresNativeReasoningForToolReplay(t *testing.T) {
	t.Parallel()

	body := []byte(`{"model":"mistral/magistral-medium-latest","messages":[{"role":"assistant","content":"I will inspect it.","reasoning_content":"check the file","tool_calls":[{"id":"call_7","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"notes.txt\"}"}}]},{"role":"tool","tool_call_id":"call_7","content":"hello"},{"role":"assistant","reasoning":"compare ","reasoning_text":"the result","content":[{"type":"thinking","thinking":[{"type":"text","text":"native thought"}]},{"type":"text","text":"done"},{"type":"image_url","image_url":{"url":"https://example.test/image.png"}}]},{"role":"assistant","content":null,"reasoning_content":"","reasoning_text":null}]}`)
	rewritten := rewriteMistralRequestBody(body, "mistral/magistral-medium-latest")

	var obj map[string]any
	if err := json.Unmarshal(rewritten, &obj); err != nil {
		t.Fatal(err)
	}
	messages := obj["messages"].([]any)
	toolCallMessage := messages[0].(map[string]any)
	for _, key := range []string{"reasoning_content", "reasoning", "reasoning_text"} {
		if _, present := toolCallMessage[key]; present {
			t.Fatalf("generic reasoning field %q was forwarded: %#v", key, toolCallMessage)
		}
	}
	content := toolCallMessage["content"].([]any)
	if len(content) != 2 {
		t.Fatalf("tool-call content = %#v, want thinking and text blocks", content)
	}
	thinking := content[0].(map[string]any)
	thinkingParts := thinking["thinking"].([]any)
	if thinking["type"] != "thinking" || thinkingParts[0].(map[string]any)["text"] != "check the file" {
		t.Fatalf("native thinking block = %#v", thinking)
	}
	if text := content[1].(map[string]any); text["type"] != "text" || text["text"] != "I will inspect it." {
		t.Fatalf("text block = %#v", text)
	}
	calls := toolCallMessage["tool_calls"].([]any)
	if calls[0].(map[string]any)["id"] != "call_7" {
		t.Fatalf("tool call ID changed: %#v", calls)
	}
	if result := messages[1].(map[string]any); result["tool_call_id"] != "call_7" || result["content"] != "hello" {
		t.Fatalf("tool result linkage changed: %#v", result)
	}

	structured := messages[2].(map[string]any)
	for _, key := range []string{"reasoning_content", "reasoning", "reasoning_text"} {
		if _, present := structured[key]; present {
			t.Fatalf("generic reasoning alias %q was forwarded: %#v", key, structured)
		}
	}
	structuredContent := structured["content"].([]any)
	if len(structuredContent) != 4 {
		t.Fatalf("structured content = %#v, want added thinking plus all three existing blocks", structuredContent)
	}
	aliasThinking := structuredContent[0].(map[string]any)["thinking"].([]any)
	if len(aliasThinking) != 2 || aliasThinking[0].(map[string]any)["text"] != "compare " || aliasThinking[1].(map[string]any)["text"] != "the result" {
		t.Fatalf("reasoning aliases were not preserved: %#v", aliasThinking)
	}
	if structuredContent[1].(map[string]any)["type"] != "thinking" || structuredContent[2].(map[string]any)["text"] != "done" || structuredContent[3].(map[string]any)["type"] != "image_url" {
		t.Fatalf("existing native/multimodal content changed: %#v", structuredContent)
	}
	if empty := messages[3].(map[string]any); empty["content"] != nil {
		t.Fatalf("empty reasoning should leave null content alone: %#v", empty)
	} else {
		for _, key := range []string{"reasoning_content", "reasoning_text"} {
			if _, present := empty[key]; present {
				t.Fatalf("empty generic reasoning field %q should be removed: %#v", key, empty)
			}
		}
	}

	// The generic fields are gone after the first pass, so replay normalization
	// is idempotent and cannot add a duplicate thinking block.
	twice := rewriteMistralRequestBody(rewritten, "mistral/magistral-medium-latest")
	if string(twice) != string(rewritten) {
		t.Fatalf("second rewrite changed normalized body:\nfirst:  %s\nsecond: %s", rewritten, twice)
	}
}

func TestMistralAssistantReasoningLeavesUnsupportedShapesUntouched(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`{"role":"user","content":"input","reasoning_content":"not assistant history"}`,
		`{"role":"tool","tool_call_id":"abcdef123","content":"result","reasoning":"not assistant history"}`,
		`{"role":"assistant","content":"answer","reasoning_content":{"opaque":"metadata"}}`,
		`{"role":"assistant","content":123,"reasoning_content":"retain reasoning"}`,
	} {
		var message map[string]any
		if err := json.Unmarshal([]byte(body), &message); err != nil {
			t.Fatal(err)
		}
		before, _ := json.Marshal(message)
		normalizeMistralAssistantReasoning(message)
		after, _ := json.Marshal(message)
		if string(before) != string(after) {
			t.Fatalf("unsupported input mutated: %s -> %s", before, after)
		}
	}
}

func TestModelRouteOverrideMistralUsesConfiguredBaseAndCanonicalModel(t *testing.T) {
	t.Parallel()

	mistralBase, _ := url.Parse("https://api.mistral.ai")
	handler := &proxyHandler{
		registry: NewProviderRegistry(
			&CodexProvider{},
			&ClaudeProvider{},
			&GeminiProvider{},
			NewMistralProvider(mistralBase),
		),
	}

	// modelRouteOverride only selects the provider/base; body rewriting (model
	// canonicalization, reasoning replay, stream_options, reasoning_effort
	// collapse) is deferred to the unconditional post-translation pass in
	// proxyRequest, since at this point a Claude-origin request has not been
	// translated to OpenAI shape yet.
	original := []byte(`{"model":"mistral/mistral-large-latest","stream":true,"reasoning_effort":"max"}`)
	provider, base, rewritten := handler.modelRouteOverride("/v1/chat/completions", "mistral/mistral-large-latest", original)
	if provider == nil || provider.Type() != AccountTypeMistral {
		t.Fatalf("expected Mistral override provider, got %v", provider)
	}
	if base == nil || base.String() != mistralBase.String() {
		t.Fatalf("base = %v, want %s", base, mistralBase)
	}
	if rewritten != nil {
		t.Fatalf("expected modelRouteOverride to leave the Mistral body untouched, got %s", rewritten)
	}

	// Bare ids must never be claimed by Mistral.
	if provider, _, _ := handler.modelRouteOverride("/v1/chat/completions", "mistral-large-latest", nil); provider != nil {
		t.Fatalf("bare model id must not route to Mistral, got provider %v", provider)
	}
}

func TestProxyRequestAppliesMistralReasoningCollapseAfterClaudeTranslation(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	mistralBase, _ := url.Parse("https://api.mistral.ai")
	claudeBase, _ := url.Parse("https://api.anthropic.com")
	codexBase, _ := url.Parse("https://chatgpt.com/backend-api/codex")
	acc := &Account{Type: AccountTypeMistral, ID: "mistral", AccessToken: "sk-upstream", PlanType: "mistral_api", Models: map[string]DiscoveredModel{
		"mistral-large-latest": {ID: "mistral-large-latest", DisplayName: "Mistral Large", CompletionChat: true},
	}}

	var upstreamBody map[string]any
	var upstreamAuth string

	h := &proxyHandler{
		cfg:     &config{maxAttempts: 1, maxInMemoryBodyBytes: 16 * 1024 * 1024},
		pool:    newPoolState([]*Account{acc}, false),
		metrics: newMetrics(),
		recent:  newRecentErrors(5),
		registry: NewProviderRegistry(
			NewCodexProvider(codexBase, codexBase, nil),
			NewClaudeProvider(claudeBase),
			NewGeminiProvider(claudeBase, claudeBase),
			NewMistralProvider(mistralBase),
		),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			upstreamAuth = req.Header.Get("Authorization")
			body, _ := io.ReadAll(req.Body)
			_ = json.Unmarshal(body, &upstreamBody)
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"id":"x","model":"mistral-large-latest","choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)),
			}, nil
		}),
	}

	// Simulate Cute Code: a Claude Messages request with a "low" thinking
	// effort, targeting a namespaced Mistral model.
	reqBody := []byte(`{"model":"mistral/mistral-large-latest","max_tokens":32,"stream":false,"reasoning_effort":"low","messages":[{"role":"user","content":"hi"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", ccAnthropicVersion)
	req.Header.Set("X-Api-Key", generateClaudePoolToken("test-secret", "mistral-user"))
	rr := httptest.NewRecorder()

	h.proxyRequest(rr, req, "req-mistral-claude")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if upstreamAuth != "Bearer sk-upstream" {
		t.Fatalf("Authorization = %q", upstreamAuth)
	}
	if upstreamBody["model"] != "mistral-large-latest" {
		t.Fatalf("upstream model = %v, want canonical bare id", upstreamBody["model"])
	}
	if upstreamBody["reasoning_effort"] != "none" {
		t.Fatalf("upstream reasoning_effort = %v, want none (collapsed from low after Claude->OpenAI translation)", upstreamBody["reasoning_effort"])
	}
}

func TestProxyRequestRestoresMistralNativeReasoningOnToolReplay(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	mistralBase, _ := url.Parse("https://api.mistral.ai")
	claudeBase, _ := url.Parse("https://api.anthropic.com")
	codexBase, _ := url.Parse("https://chatgpt.com/backend-api/codex")
	acc := &Account{Type: AccountTypeMistral, ID: "mistral", AccessToken: "sk-upstream", PlanType: "mistral_api", Models: map[string]DiscoveredModel{
		"magistral-medium-latest": {ID: "magistral-medium-latest", DisplayName: "Magistral Medium", CompletionChat: true},
	}}

	var upstreamBody map[string]any
	h := &proxyHandler{
		cfg:     &config{maxAttempts: 1, maxInMemoryBodyBytes: 16 * 1024 * 1024},
		pool:    newPoolState([]*Account{acc}, false),
		metrics: newMetrics(),
		recent:  newRecentErrors(5),
		registry: NewProviderRegistry(
			NewCodexProvider(codexBase, codexBase, nil),
			NewClaudeProvider(claudeBase),
			NewGeminiProvider(claudeBase, claudeBase),
			NewMistralProvider(mistralBase),
		),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			if err := json.Unmarshal(body, &upstreamBody); err != nil {
				t.Fatalf("upstream body is not JSON: %v: %s", err, body)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"id":"x","model":"magistral-medium-latest","choices":[{"message":{"role":"assistant","content":"done"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":1}}`)),
			}, nil
		}),
	}

	reqBody := []byte(`{"model":"mistral/magistral-medium-latest","messages":[{"role":"user","content":"read notes"},{"role":"assistant","content":null,"reasoning_content":"I should inspect the file","tool_calls":[{"id":"call_notes","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"notes.txt\"}"}}]},{"role":"tool","tool_call_id":"call_notes","content":"hello"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", generateClaudePoolToken("test-secret", "mistral-user"))
	rr := httptest.NewRecorder()

	h.proxyRequest(rr, req, "req-mistral-tool-replay")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	messages := upstreamBody["messages"].([]any)
	assistant := messages[1].(map[string]any)
	for _, key := range []string{"reasoning_content", "reasoning", "reasoning_text"} {
		if _, present := assistant[key]; present {
			t.Fatalf("unsupported generic field %q reached Mistral: %#v", key, assistant)
		}
	}
	content := assistant["content"].([]any)
	thinking := content[0].(map[string]any)
	parts := thinking["thinking"].([]any)
	if thinking["type"] != "thinking" || parts[0].(map[string]any)["type"] != "text" || parts[0].(map[string]any)["text"] != "I should inspect the file" {
		t.Fatalf("upstream native thinking block = %#v", content)
	}
	calls := assistant["tool_calls"].([]any)
	if calls[0].(map[string]any)["id"] != "call_notes" || messages[2].(map[string]any)["tool_call_id"] != "call_notes" {
		t.Fatalf("upstream tool linkage changed: %#v", messages)
	}
}

func TestLoadPoolLoadsMistralAccounts(t *testing.T) {
	t.Parallel()

	poolDir := t.TempDir()
	mistralDir := filepath.Join(poolDir, "mistral")
	if err := os.MkdirAll(mistralDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mistralDir, "one.json"), []byte(`{"api_key":"sk-one"}`), 0600); err != nil {
		t.Fatal(err)
	}

	mistralBase, _ := url.Parse("https://api.mistral.ai")
	registry := NewProviderRegistry(&CodexProvider{}, &ClaudeProvider{}, &GeminiProvider{}, NewMistralProvider(mistralBase))
	accounts, err := loadPool(poolDir, registry)
	if err != nil {
		t.Fatalf("loadPool: %v", err)
	}
	if len(accounts) != 1 {
		t.Fatalf("loaded %d accounts, want 1", len(accounts))
	}
	if accounts[0].Type != AccountTypeMistral || accounts[0].ID != "one" || accounts[0].AccessToken != "sk-one" || accounts[0].PlanType != "mistral_api" {
		t.Fatalf("unexpected Mistral account: %#v", accounts[0])
	}
}

func TestAccountDiscoveredModelRequiresNamespaceForMistral(t *testing.T) {
	t.Parallel()

	acc := &Account{
		Type: AccountTypeMistral,
		Models: map[string]DiscoveredModel{
			"mistral-large-latest": {ID: "mistral-large-latest"},
		},
	}
	if _, ok := accountDiscoveredModel(acc, "mistral-large-latest"); ok {
		t.Fatal("bare model name should not resolve for a Mistral account")
	}
	discovered, ok := accountDiscoveredModel(acc, "mistral/mistral-large-latest")
	if !ok || discovered.ID != "mistral-large-latest" {
		t.Fatalf("expected namespaced lookup to resolve, got %#v ok=%v", discovered, ok)
	}
	if _, ok := accountDiscoveredModel(acc, "mistral/unknown-model"); ok {
		t.Fatal("unknown upstream id should not resolve")
	}
}

func TestSaveAccountDispatchesMistralToAPIKeyPersistence(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "acct.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	acc := &Account{Type: AccountTypeMistral, ID: "acct", File: path, AccessToken: "sk-save"}
	if err := saveAccount(acc); err != nil {
		t.Fatalf("saveAccount: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved["api_key"] != "sk-save" {
		t.Fatalf("saved account = %#v", saved)
	}
}

func TestAccountUsesStaticAPIKeyIncludesMistral(t *testing.T) {
	t.Parallel()
	if !accountUsesStaticAPIKey(AccountTypeMistral) {
		t.Fatal("Mistral accounts use a static paid API key, not OAuth")
	}
}

func TestProviderTargetFormatMistralIsOpenAI(t *testing.T) {
	t.Parallel()
	if got := providerTargetFormat(AccountTypeMistral); got != FormatOpenAI {
		t.Fatalf("providerTargetFormat(Mistral) = %v, want FormatOpenAI", got)
	}
}

func TestParseMistralModelsFiltersNonChatCapableModels(t *testing.T) {
	t.Parallel()

	body := []byte(`{"data":[
		{"id":"mistral-large-latest","name":"Mistral Large","description":"Flagship model","max_context_length":128000,"capabilities":{"completion_chat":true,"function_calling":true,"reasoning":false,"vision":false}},
		{"id":"pixtral-large-latest","name":"Pixtral Large","max_context_length":128000,"capabilities":{"completion_chat":true,"vision":true}},
		{"id":"magistral-medium-latest","max_context_length":40000,"capabilities":{"completion_chat":true,"reasoning":true}},
		{"id":"mistral-embed","capabilities":{"completion_chat":false}},
		{"id":"mistral-moderation-latest","capabilities":{}},
		{"id":"  ","capabilities":{"completion_chat":true}}
	]}`)

	models, err := parseMistralModels(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 3 {
		t.Fatalf("models = %#v, want 3 chat-capable entries", models)
	}
	large, ok := models["mistral-large-latest"]
	if !ok {
		t.Fatal("mistral-large-latest missing")
	}
	if large.DisplayName != "Mistral Large" || large.Description != "Flagship model" || large.ContextWindow != 128000 {
		t.Fatalf("mistral-large-latest metadata = %#v", large)
	}
	if !large.Tools || large.Reasoning || !large.CompletionChat {
		t.Fatalf("mistral-large-latest capabilities = %#v", large)
	}
	if !containsString(large.Modalities, "text") || containsString(large.Modalities, "image") {
		t.Fatalf("mistral-large-latest modalities = %#v, want text only", large.Modalities)
	}

	pixtral, ok := models["pixtral-large-latest"]
	if !ok {
		t.Fatal("pixtral-large-latest missing")
	}
	if !containsString(pixtral.Modalities, "image") {
		t.Fatalf("pixtral modalities = %#v, want image capability", pixtral.Modalities)
	}
	if pixtral.DisplayName != "Pixtral Large" {
		t.Fatalf("pixtral display name = %q, want the catalog name", pixtral.DisplayName)
	}

	magistral, ok := models["magistral-medium-latest"]
	if !ok {
		t.Fatal("magistral-medium-latest missing")
	}
	if !magistral.Reasoning {
		t.Fatal("magistral should advertise reasoning capability")
	}
	if magistral.DisplayName != "magistral-medium-latest" {
		t.Fatalf("display name should fall back to id when the catalog omits name, got %q", magistral.DisplayName)
	}

	if _, ok := models["mistral-embed"]; ok {
		t.Fatal("non-chat embeddings model should be filtered out")
	}
	if _, ok := models["mistral-moderation-latest"]; ok {
		t.Fatal("model missing completion_chat capability should be filtered out")
	}
}

func TestParseMistralModelsRejectsEmptyChatCatalog(t *testing.T) {
	t.Parallel()

	_, err := parseMistralModels([]byte(`{"data":[{"id":"mistral-embed","capabilities":{"completion_chat":false}}]}`))
	if err == nil {
		t.Fatal("expected an error when no models advertise completion_chat")
	}
}

func TestProviderModelsURLUsesV1ModelsForMistral(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://api.mistral.ai")
	target, ok := providerModelsURL(NewMistralProvider(base))
	if !ok {
		t.Fatal("expected a Mistral model discovery URL")
	}
	if got := target.String(); got != "https://api.mistral.ai/v1/models" {
		t.Fatalf("discovery URL = %q", got)
	}
}

func TestFetchProviderModelsUsesMistralParser(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://api.mistral.ai")
	provider := NewMistralProvider(base)
	account := &Account{ID: "mistral", Type: AccountTypeMistral, AccessToken: "sk-secret"}
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://api.mistral.ai/v1/models" {
			t.Fatalf("model discovery URL = %s", req.URL)
		}
		if req.Header.Get("Authorization") != "Bearer sk-secret" {
			t.Fatalf("authorization header = %q", req.Header.Get("Authorization"))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"data":[{"id":"mistral-large-latest","capabilities":{"completion_chat":true}}]}`)),
			Header:     make(http.Header),
		}, nil
	})

	snapshot, err := fetchProviderModels(context.Background(), transport, provider, account)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snapshot.Models["mistral-large-latest"]; !ok {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestDiscoveredModelsForPoolNamespacesMistralPublicIDs(t *testing.T) {
	t.Parallel()

	account := &Account{
		ID:   "mistral",
		Type: AccountTypeMistral,
		Models: map[string]DiscoveredModel{
			"magistral-medium-latest": {
				ID:            "magistral-medium-latest",
				DisplayName:   "Magistral Medium",
				ContextWindow: 40000,
				Reasoning:     true,
				Tools:         true,
			},
		},
	}
	pool := newPoolState([]*Account{account}, false)

	var found *poolModelDescriptor
	for _, descriptor := range discoveredModelsForPool(pool) {
		if descriptor.Provider == string(AccountTypeMistral) {
			d := descriptor
			found = &d
			break
		}
	}
	if found == nil {
		t.Fatal("expected a discovered Mistral descriptor")
	}
	if found.ID != "mistral/magistral-medium-latest" {
		t.Fatalf("discovered descriptor ID = %q, want namespaced public id", found.ID)
	}
	if found.UpstreamID != "magistral-medium-latest" {
		t.Fatalf("discovered descriptor UpstreamID = %q, want bare upstream id", found.UpstreamID)
	}
	if found.Protocol != "anthropic" {
		t.Fatalf("discovered descriptor protocol = %q, want anthropic (Cute Code Messages bridge)", found.Protocol)
	}
	if !found.Capabilities["reasoning"] || !found.Capabilities["tools"] {
		t.Fatalf("discovered descriptor capabilities = %#v", found.Capabilities)
	}
	if !strings.Contains(found.Description, "Messages adapter") {
		t.Fatalf("discovered descriptor description = %q, want a Messages-adapter disclosure", found.Description)
	}
}

func TestPoolModelDescriptorsPinnedMistralEntriesUseAnthropicProtocol(t *testing.T) {
	t.Parallel()

	for _, descriptor := range poolModelDescriptors() {
		if descriptor.Provider != string(AccountTypeMistral) {
			continue
		}
		if !strings.HasPrefix(descriptor.ID, "mistral/") {
			t.Fatalf("pinned Mistral model %q is not namespaced", descriptor.ID)
		}
		if descriptor.Protocol != "anthropic" {
			t.Fatalf("pinned Mistral model %q protocol = %q, want anthropic", descriptor.ID, descriptor.Protocol)
		}
		if descriptor.Capabilities["tools"] {
			t.Fatalf("pinned Mistral model %q should default tools=false until discovery confirms function_calling", descriptor.ID)
		}
	}
}

func TestPoolModelDescriptorsOverlayDiscoveredMetadataOntoPinnedMistralEntry(t *testing.T) {
	t.Parallel()

	account := &Account{
		ID:   "mistral",
		Type: AccountTypeMistral,
		Models: map[string]DiscoveredModel{
			"mistral-large-latest": {
				ID:            "mistral-large-latest",
				DisplayName:   "Mistral Large (discovered)",
				ContextWindow: 256000,
				Reasoning:     false,
				Tools:         true,
				Modalities:    []string{"text", "image"},
			},
		},
	}
	pool := newPoolState([]*Account{account}, false)

	for _, descriptor := range poolModelDescriptors(pool) {
		if descriptor.ID != "mistral/mistral-large-latest" {
			continue
		}
		if descriptor.Name != "Mistral Large (discovered)" {
			t.Fatalf("Name = %q, want discovered display name", descriptor.Name)
		}
		if descriptor.ContextWindow != 256000 {
			t.Fatalf("ContextWindow = %d, want discovered value", descriptor.ContextWindow)
		}
		if !descriptor.Capabilities["tools"] {
			t.Fatal("expected discovered function_calling capability to enable tools")
		}
		if !containsString(descriptor.Modalities, "image") {
			t.Fatalf("Modalities = %#v, want discovered image modality", descriptor.Modalities)
		}
		return
	}
	t.Fatal("pinned mistral/mistral-large-latest descriptor missing")
}

func TestMistralPiModelsExportOpenAICompletionsProvider(t *testing.T) {
	t.Parallel()

	data, err := generatePiModelsJSON("https://pool.example.com", "codex-token", "claude-token")
	if err != nil {
		t.Fatal(err)
	}
	var cfg piModelsConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	mistral, ok := cfg.Providers["pool-mistral"]
	if !ok {
		t.Fatal("expected a pool-mistral provider entry in generated Pi config")
	}
	if mistral.API != "openai-completions" {
		t.Fatalf("mistral api = %q, want openai-completions", mistral.API)
	}
	if mistral.BaseURL != "https://pool.example.com/v1" {
		t.Fatalf("mistral baseUrl = %q", mistral.BaseURL)
	}
	if len(mistral.Models) == 0 {
		t.Fatal("expected pinned Mistral models in generated Pi config")
	}
	for _, model := range mistral.Models {
		if !strings.HasPrefix(model.ID, "mistral/") {
			t.Fatalf("pi model id = %q, want namespaced", model.ID)
		}
	}
}

func TestMistralCuteModelsExportAnthropicMessagesBridge(t *testing.T) {
	t.Parallel()

	data, err := generateCuteCodeSettingsJSON("https://pool.example.com", "pool-token")
	if err != nil {
		t.Fatal(err)
	}
	var settings cuteCodeSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, model := range settings.CustomModels {
		if !strings.HasPrefix(model.ID, "mistral/") {
			continue
		}
		found = true
		if model.Protocol != "anthropic" {
			t.Fatalf("mistral cute model protocol = %q, want anthropic", model.Protocol)
		}
		if model.BaseURL != "https://pool.example.com" {
			t.Fatalf("mistral cute model baseUrl = %q", model.BaseURL)
		}
		if !strings.Contains(model.Description, "Messages adapter") {
			t.Fatalf("mistral cute model description = %q, want a Messages-adapter disclosure", model.Description)
		}
	}
	if !found {
		t.Fatal("expected at least one namespaced Mistral custom model for Cute Code")
	}
}

// An inference-key provider must never fall through to the Codex WHAM poller.
// WHAM responds 401 to a Mistral key, and the generic poller retires it.
func TestMistralUsagePollerDoesNotRetireStaticKey(t *testing.T) {
	t.Parallel()
	acc := &Account{Type: AccountTypeMistral, ID: "mistral", AccessToken: "test-key", PlanType: "mistral_api"}
	h := &proxyHandler{
		cfg:  &config{usageRefresh: time.Minute},
		pool: newPoolState([]*Account{acc}, false),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			t.Fatalf("Mistral usage poll must not call %s %s", req.Method, req.URL)
			return nil, nil
		}),
	}
	h.pollUpstreamUsage()
	if acc.Dead {
		t.Fatal("Mistral key was retired by unrelated usage poll")
	}
}
