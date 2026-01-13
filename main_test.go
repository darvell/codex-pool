package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
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

func TestClaudeProviderParseUsageHeadersPartialUnifiedFallback(t *testing.T) {
	acc := &Account{Type: AccountTypeClaude}
	provider := &ClaudeProvider{}
	now := time.Now().UTC()

	primaryReset := now.Add(2 * time.Hour).Truncate(time.Second)
	secondaryReset := now.Add(6 * 24 * time.Hour).Truncate(time.Second)

	provider.ParseUsageHeaders(acc, mapToHeader(map[string]string{
		// Unified only includes request utilization/reset (common for some responses).
		"anthropic-ratelimit-unified-requests-utilization": "6.0",
		"anthropic-ratelimit-unified-requests-reset":       strconv.FormatInt(secondaryReset.Unix(), 10),

		// Legacy tokens headers should still populate primary usage/reset.
		"anthropic-ratelimit-tokens-limit":     "100",
		"anthropic-ratelimit-tokens-remaining": "44",
		"anthropic-ratelimit-tokens-reset":     primaryReset.Format(time.RFC3339),
	}))

	if acc.Usage.PrimaryUsedPercent != 0.56 {
		t.Fatalf("primary percent = %v", acc.Usage.PrimaryUsedPercent)
	}
	if acc.Usage.SecondaryUsedPercent != 0.06 {
		t.Fatalf("secondary percent = %v", acc.Usage.SecondaryUsedPercent)
	}
	if acc.Usage.PrimaryResetAt.IsZero() {
		t.Fatalf("expected primary reset to be set")
	}
	if acc.Usage.SecondaryResetAt.IsZero() {
		t.Fatalf("expected secondary reset to be set")
	}
	// Match timestamps to the second (RFC3339 parse truncates to second precision here).
	if acc.Usage.PrimaryResetAt.UTC().Unix() != primaryReset.Unix() {
		t.Fatalf("primary reset = %v want %v", acc.Usage.PrimaryResetAt.UTC(), primaryReset)
	}
	if acc.Usage.SecondaryResetAt.UTC().Unix() != secondaryReset.Unix() {
		t.Fatalf("secondary reset = %v want %v", acc.Usage.SecondaryResetAt.UTC(), secondaryReset)
	}
}

func TestClaudeProviderParseUsageHeadersZeroUtilizationStillUpdatesReset(t *testing.T) {
	acc := &Account{Type: AccountTypeClaude}
	provider := &ClaudeProvider{}
	resetAt := time.Now().UTC().Add(5 * time.Hour).Truncate(time.Second)

	provider.ParseUsageHeaders(acc, mapToHeader(map[string]string{
		"anthropic-ratelimit-unified-tokens-utilization": "0",
		"anthropic-ratelimit-unified-tokens-reset":       strconv.FormatInt(resetAt.Unix(), 10),
	}))

	if acc.Usage.PrimaryUsedPercent != 0 {
		t.Fatalf("primary percent = %v", acc.Usage.PrimaryUsedPercent)
	}
	if acc.Usage.PrimaryResetAt.IsZero() {
		t.Fatalf("expected primary reset to be set")
	}
	if acc.Usage.PrimaryResetAt.UTC().Unix() != resetAt.Unix() {
		t.Fatalf("primary reset = %v want %v", acc.Usage.PrimaryResetAt.UTC(), resetAt)
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
