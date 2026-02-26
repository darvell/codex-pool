package main

import (
	"encoding/json"
	"net/http"
	"net/url"
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

func TestClaudeProviderParseUsageHeadersIgnored(t *testing.T) {
	acc := &Account{Type: AccountTypeClaude}
	provider := &ClaudeProvider{}
	retrievedAt := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	primaryReset := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	secondaryReset := time.Now().UTC().Add(3 * 24 * time.Hour).Truncate(time.Second)
	acc.Usage = UsageSnapshot{
		PrimaryUsedPercent:   0.25,
		SecondaryUsedPercent: 0.33,
		PrimaryUsed:          0.25,
		SecondaryUsed:        0.33,
		PrimaryResetAt:       primaryReset,
		SecondaryResetAt:     secondaryReset,
		RetrievedAt:          retrievedAt,
		Source:               "claude-api",
	}

	provider.ParseUsageHeaders(acc, mapToHeader(map[string]string{
		"anthropic-ratelimit-unified-tokens-utilization":   "99.9",
		"anthropic-ratelimit-unified-requests-utilization": "88.8",
		"anthropic-ratelimit-unified-tokens-reset":         "9999999999",
		"anthropic-ratelimit-unified-requests-reset":       "9999999999",
	}))

	if acc.Usage.PrimaryUsedPercent != 0.25 {
		t.Fatalf("primary percent = %v", acc.Usage.PrimaryUsedPercent)
	}
	if acc.Usage.SecondaryUsedPercent != 0.33 {
		t.Fatalf("secondary percent = %v", acc.Usage.SecondaryUsedPercent)
	}
	if acc.Usage.PrimaryResetAt.UTC().Unix() != primaryReset.Unix() {
		t.Fatalf("primary reset = %v want %v", acc.Usage.PrimaryResetAt.UTC(), primaryReset)
	}
	if acc.Usage.SecondaryResetAt.UTC().Unix() != secondaryReset.Unix() {
		t.Fatalf("secondary reset = %v want %v", acc.Usage.SecondaryResetAt.UTC(), secondaryReset)
	}
	if acc.Usage.RetrievedAt.UTC().Unix() != retrievedAt.Unix() {
		t.Fatalf("retrieved_at = %v want %v", acc.Usage.RetrievedAt.UTC(), retrievedAt)
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

// mapToHeader is a tiny helper to build http.Header in tests without importing net/http everywhere.
func mapToHeader(m map[string]string) http.Header {
	h := http.Header{}
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}
