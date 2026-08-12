package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The upstream chat template accepts only low/high/max. Its JSON deserializer
// accepts a wider set (none/minimal/low/medium/high/xhigh/max), so unsupported
// values reach the template and 400 there. Verified against
// platform.adverserial.ai on 2026-08-10.
func TestClampAdverserialEffort(t *testing.T) {
	cases := map[string]string{
		"low":     "low",
		"high":    "high",
		"max":     "max",
		"none":    "low",
		"medium":  "high",
		"minimal": "high",
		"xhigh":   "high",
		"ultra":   "high",
		"":        "high",
		"  ":      "high",
		"HIGH":    "high",
		"  Max  ": "max",
		"bogus":   "high",
	}
	for input, want := range cases {
		if got := clampAdverserialEffort(input); got != want {
			t.Errorf("clampAdverserialEffort(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestClampAdverserialEffortOnlyEmitsSupportedValues(t *testing.T) {
	supported := map[string]bool{"low": true, "high": true, "max": true}
	for _, input := range []string{
		"none", "minimal", "low", "medium", "high", "xhigh", "max",
		"ultra", "", "junk", "HIGH", "Medium",
	} {
		if got := clampAdverserialEffort(input); !supported[got] {
			t.Fatalf("clampAdverserialEffort(%q) = %q, which upstream rejects", input, got)
		}
	}
}

// output_config.effort is what Claude Code and cute-code send, and it reaches
// the same chat-template validator as top-level reasoning_effort. Clamping only
// the top-level field would let every real client request 400.
func TestRewriteAndClampAdverserialRequestBodyClampsOutputConfig(t *testing.T) {
	body := []byte(`{"model":"cyberkimi","max_tokens":16,"output_config":{"effort":"medium","format":{"type":"json"}},"messages":[]}`)
	got := rewriteAndClampAdverserialRequestBody(body, "cyberkimi")

	var obj map[string]any
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if obj["model"] != "lordx64/cyberkimi" {
		t.Errorf("model = %v, want lordx64/cyberkimi", obj["model"])
	}
	outputConfig, ok := obj["output_config"].(map[string]any)
	if !ok {
		t.Fatalf("output_config missing: %s", got)
	}
	if outputConfig["effort"] != "high" {
		t.Errorf("output_config.effort = %v, want high", outputConfig["effort"])
	}
	if _, ok := outputConfig["format"]; !ok {
		t.Error("output_config.format was dropped; only effort should change")
	}
}

func TestRewriteAndClampAdverserialRequestBodyClampsReasoningEffort(t *testing.T) {
	body := []byte(`{"model":"lordx64/cyberkimi","reasoning_effort":"xhigh","messages":[]}`)
	got := rewriteAndClampAdverserialRequestBody(body, "lordx64/cyberkimi")

	var obj map[string]any
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if obj["reasoning_effort"] != "high" {
		t.Errorf("reasoning_effort = %v, want high", obj["reasoning_effort"])
	}
}

// Both carriers must be clamped in one pass: reasoning_effort wins upstream,
// but an unsupported value in either field fails the whole request.
func TestRewriteAndClampAdverserialRequestBodyClampsBothCarriers(t *testing.T) {
	body := []byte(`{"model":"cyberkimi","reasoning_effort":"minimal","output_config":{"effort":"xhigh"},"messages":[]}`)
	got := rewriteAndClampAdverserialRequestBody(body, "cyberkimi")

	var obj map[string]any
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if obj["reasoning_effort"] != "high" {
		t.Errorf("reasoning_effort = %v, want high", obj["reasoning_effort"])
	}
	outputConfig := obj["output_config"].(map[string]any)
	if outputConfig["effort"] != "high" {
		t.Errorf("output_config.effort = %v, want high", outputConfig["effort"])
	}
}

// `none` means the caller disabled thinking. Promoting it to high would
// override an explicit intent, so it becomes the cheapest supported effort.
func TestRewriteAndClampAdverserialRequestBodyMapsNoneToLow(t *testing.T) {
	body := []byte(`{"model":"cyberkimi","reasoning_effort":"none","output_config":{"effort":"none"},"messages":[]}`)
	got := rewriteAndClampAdverserialRequestBody(body, "cyberkimi")

	var obj map[string]any
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if obj["reasoning_effort"] != "low" {
		t.Errorf("reasoning_effort = %v, want low", obj["reasoning_effort"])
	}
	outputConfig := obj["output_config"].(map[string]any)
	if outputConfig["effort"] != "low" {
		t.Errorf("output_config.effort = %v, want low", outputConfig["effort"])
	}
}

// Absent effort must stay absent so the upstream default applies.
func TestRewriteAndClampAdverserialRequestBodyDoesNotInventEffort(t *testing.T) {
	body := []byte(`{"model":"lordx64/cyberkimi","max_tokens":16,"messages":[]}`)
	got := rewriteAndClampAdverserialRequestBody(body, "lordx64/cyberkimi")

	var obj map[string]any
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := obj["reasoning_effort"]; ok {
		t.Error("reasoning_effort was invented; upstream default should apply")
	}
	if _, ok := obj["output_config"]; ok {
		t.Error("output_config was invented; upstream default should apply")
	}
}

// A non-string effort cannot deserialize upstream and would 400. Drop it rather
// than forwarding a guaranteed failure.
func TestRewriteAndClampAdverserialRequestBodyDropsNonStringEffort(t *testing.T) {
	body := []byte(`{"model":"cyberkimi","reasoning_effort":42,"output_config":{"effort":{"a":1}},"messages":[]}`)
	got := rewriteAndClampAdverserialRequestBody(body, "cyberkimi")

	var obj map[string]any
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := obj["reasoning_effort"]; ok {
		t.Errorf("non-string reasoning_effort should be dropped: %s", got)
	}
	outputConfig := obj["output_config"].(map[string]any)
	if _, ok := outputConfig["effort"]; ok {
		t.Errorf("non-string output_config.effort should be dropped: %s", got)
	}
}

// reasoning.effort and thinking.* are ignored by this upstream. Rewriting them
// would imply an effect the endpoint does not have.
func TestRewriteAndClampAdverserialRequestBodyLeavesIgnoredFields(t *testing.T) {
	body := []byte(`{"model":"lordx64/cyberkimi","reasoning":{"effort":"medium"},"thinking":{"type":"enabled","budget_tokens":4096},"messages":[]}`)
	got := rewriteAndClampAdverserialRequestBody(body, "lordx64/cyberkimi")

	var obj map[string]any
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	reasoning := obj["reasoning"].(map[string]any)
	if reasoning["effort"] != "medium" {
		t.Errorf("reasoning.effort = %v, want untouched medium", reasoning["effort"])
	}
	thinking := obj["thinking"].(map[string]any)
	if thinking["budget_tokens"] != float64(4096) {
		t.Errorf("thinking.budget_tokens = %v, want untouched 4096", thinking["budget_tokens"])
	}
}

func TestRewriteAndClampAdverserialRequestBodyHandlesMalformedInput(t *testing.T) {
	for _, body := range [][]byte{nil, {}, []byte("not json"), []byte(`{"model":`)} {
		got := rewriteAndClampAdverserialRequestBody(body, "cyberkimi")
		if string(got) != string(body) {
			t.Errorf("malformed body %q was modified to %q", body, got)
		}
	}
}

func TestAdverserialModelRouting(t *testing.T) {
	for _, name := range []string{"lordx64/cyberkimi", "cyberkimi", "CyberKimi", "  cyberkimi  "} {
		if !isAdverserialModel(name) {
			t.Errorf("isAdverserialModel(%q) = false, want true", name)
		}
		if got := adverserialCanonicalModel(name); got != "lordx64/cyberkimi" {
			t.Errorf("adverserialCanonicalModel(%q) = %q, want lordx64/cyberkimi", name, got)
		}
	}
	for _, name := range []string{"kimi-for-coding", "glm-5.2", "gpt-5.6-sol", "mimo-v2.5-pro"} {
		if isAdverserialModel(name) {
			t.Errorf("isAdverserialModel(%q) = true, want false", name)
		}
	}
}

// Model routing must not collide with the existing Kimi provider: both catalogs
// contain "kimi"-flavored names.
func TestAdverserialModelDoesNotCollideWithKimi(t *testing.T) {
	if isKimiModel("lordx64/cyberkimi") || isKimiModel("cyberkimi") {
		t.Error("cyberkimi must not route to the Kimi provider")
	}
}

func TestAdverserialProviderIsModelRouted(t *testing.T) {
	base, _ := url.Parse("https://platform.adverserial.ai/api")
	p := NewAdverserialProvider(base)

	if p.Type() != AccountTypeAdverserial {
		t.Errorf("Type() = %v, want %v", p.Type(), AccountTypeAdverserial)
	}
	// Anthropic-protocol providers here are model-routed; winning path matching
	// would steal /v1/messages traffic from Claude.
	for _, path := range []string{"/v1/messages", "/v1/responses", "/responses"} {
		if p.MatchesPath(path) {
			t.Errorf("MatchesPath(%q) = true, want false", path)
		}
	}
	if got := p.UpstreamURL("/v1/messages").String(); got != "https://platform.adverserial.ai/api" {
		t.Errorf("UpstreamURL = %q", got)
	}
	if !p.DetectsSSE("/v1/messages", "text/event-stream") {
		t.Error("DetectsSSE should recognize text/event-stream")
	}
}

func TestAdverserialProviderLoadAccount(t *testing.T) {
	base, _ := url.Parse("https://platform.adverserial.ai/api")
	p := NewAdverserialProvider(base)

	acc, err := p.LoadAccount("cyberkimi.json", "/pool/adverserial/cyberkimi.json", []byte(`{"api_key":"sk-test"}`))
	if err != nil {
		t.Fatalf("LoadAccount: %v", err)
	}
	if acc == nil {
		t.Fatal("LoadAccount returned nil account")
	}
	if acc.Type != AccountTypeAdverserial || acc.ID != "cyberkimi" || acc.AccessToken != "sk-test" || acc.PlanType != "adverserial" {
		t.Errorf("unexpected account: %+v", acc)
	}

	// A file without an api_key belongs to another provider, not this one.
	acc, err = p.LoadAccount("other.json", "/pool/adverserial/other.json", []byte(`{"access_token":"x"}`))
	if err != nil {
		t.Fatalf("LoadAccount: %v", err)
	}
	if acc != nil {
		t.Errorf("expected nil account for non-matching file, got %+v", acc)
	}
}

func TestAdverserialProviderAuthHeaders(t *testing.T) {
	base, _ := url.Parse("https://platform.adverserial.ai/api")
	p := NewAdverserialProvider(base)
	acc := &Account{Type: AccountTypeAdverserial, AccessToken: "sk-test"}

	req, _ := http.NewRequest("POST", "https://platform.adverserial.ai/api/v1/messages", strings.NewReader("{}"))
	req.Header.Set("X-Api-Key", "client-supplied-key")
	p.SetAuthHeaders(req, acc)

	if got := req.Header.Get("Authorization"); got != "Bearer sk-test" {
		t.Errorf("Authorization = %q, want Bearer sk-test", got)
	}
	if got := req.Header.Get("X-Api-Key"); got != "" {
		t.Errorf("X-Api-Key should be stripped, got %q", got)
	}
}

func TestAdverserialProviderParseUsage(t *testing.T) {
	base, _ := url.Parse("https://platform.adverserial.ai/api")
	p := NewAdverserialProvider(base)

	start := map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"model": "lordx64/cyberkimi",
			"usage": map[string]any{"input_tokens": float64(100), "cache_read_input_tokens": float64(20)},
		},
	}
	ru := p.ParseUsage(start)
	if ru == nil {
		t.Fatal("ParseUsage(message_start) = nil")
	}
	if ru.InputTokens != 100 || ru.CachedInputTokens != 20 || ru.Model != "lordx64/cyberkimi" {
		t.Errorf("unexpected usage: %+v", ru)
	}

	delta := map[string]any{
		"type":  "message_delta",
		"usage": map[string]any{"output_tokens": float64(50)},
	}
	ru = p.ParseUsage(delta)
	if ru == nil || ru.OutputTokens != 50 || ru.BillableTokens != 50 {
		t.Errorf("unexpected delta usage: %+v", ru)
	}

	if got := p.ParseUsage(map[string]any{"type": "content_block_delta"}); got != nil {
		t.Errorf("non-usage event should return nil, got %+v", got)
	}
}

func TestAdverserialAccountUsesStaticAPIKey(t *testing.T) {
	// A proxied 401/403 must not retire a static-key account: model access and
	// request shape are rejected with the same status.
	if !accountUsesStaticAPIKey(AccountTypeAdverserial) {
		t.Error("adverserial accounts use static API keys")
	}
	acc := &Account{Type: AccountTypeAdverserial}
	if markedDead, _ := applyProxyAuthFailure(acc, false); markedDead {
		t.Error("a proxied auth failure must not mark a static-key account dead")
	}
}
