package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// KimiProvider handles Kimi API accounts.
type KimiProvider struct {
	kimiBase *url.URL
}

// NewKimiProvider creates a new Kimi provider.
func NewKimiProvider(kimiBase *url.URL) *KimiProvider {
	return &KimiProvider{
		kimiBase: kimiBase,
	}
}

func (p *KimiProvider) Type() AccountType {
	return AccountTypeKimi
}

// KimiAuthJSON is the format for Kimi auth files.
type KimiAuthJSON struct {
	APIKey string `json:"api_key"`
}

func (p *KimiProvider) LoadAccount(name, path string, data []byte) (*Account, error) {
	var kj KimiAuthJSON
	if err := json.Unmarshal(data, &kj); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if kj.APIKey == "" {
		return nil, nil
	}

	acc := &Account{
		Type:        AccountTypeKimi,
		ID:          strings.TrimSuffix(name, filepath.Ext(name)),
		File:        path,
		AccessToken: kj.APIKey,
		PlanType:    "kimi",
	}
	return acc, nil
}

func (p *KimiProvider) SetAuthHeaders(req *http.Request, acc *Account) {
	req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
}

func (p *KimiProvider) RefreshToken(ctx context.Context, acc *Account, transport http.RoundTripper) error {
	// API keys don't need refresh
	return nil
}

func (p *KimiProvider) ParseUsage(obj map[string]any) *RequestUsage {
	// Kimi proxies Anthropic/OpenAI-style responses, so parse both formats.

	// OpenAI-style usage object
	if usageMap, ok := obj["usage"].(map[string]any); ok {
		ru := &RequestUsage{Timestamp: time.Now()}
		ru.InputTokens = readInt64(usageMap, "prompt_tokens")
		if ru.InputTokens == 0 {
			ru.InputTokens = readInt64(usageMap, "input_tokens")
		}
		ru.OutputTokens = readInt64(usageMap, "completion_tokens")
		if ru.OutputTokens == 0 {
			ru.OutputTokens = readInt64(usageMap, "output_tokens")
		}
		ru.CachedInputTokens = readInt64(usageMap, "cached_tokens")
		if ru.InputTokens == 0 && ru.OutputTokens == 0 {
			return nil
		}
		ru.BillableTokens = ru.InputTokens + ru.OutputTokens
		if m, ok := obj["model"].(string); ok && m != "" {
			ru.Model = m
		}
		return ru
	}

	// Anthropic-style: message_start / message_delta
	eventType, _ := obj["type"].(string)
	if eventType == "message_delta" {
		usageMap, ok := obj["usage"].(map[string]any)
		if !ok {
			return nil
		}
		ru := &RequestUsage{Timestamp: time.Now()}
		ru.OutputTokens = readInt64(usageMap, "output_tokens")
		if ru.OutputTokens == 0 {
			return nil
		}
		ru.BillableTokens = ru.OutputTokens
		return ru
	}
	if eventType == "message_start" {
		msg, ok := obj["message"].(map[string]any)
		if !ok {
			return nil
		}
		usageMap, ok := msg["usage"].(map[string]any)
		if !ok {
			return nil
		}
		ru := &RequestUsage{Timestamp: time.Now()}
		ru.InputTokens = readInt64(usageMap, "input_tokens")
		ru.CachedInputTokens = readInt64(usageMap, "cache_read_input_tokens")
		if ru.InputTokens == 0 {
			return nil
		}
		if model, ok := msg["model"].(string); ok {
			ru.Model = model
		}
		ru.BillableTokens = clampNonNegative(ru.InputTokens - ru.CachedInputTokens)
		return ru
	}

	return nil
}

func (p *KimiProvider) ParseUsageHeaders(acc *Account, headers http.Header) {
	snap, ok := parseKimiResponseRateLimits(headers)
	if !ok {
		return
	}
	acc.mu.Lock()
	acc.Usage = mergeUsage(acc.Usage, snap)
	acc.mu.Unlock()
}

func (p *KimiProvider) UpstreamURL(path string) *url.URL {
	return p.kimiBase
}

func (p *KimiProvider) MatchesPath(path string) bool {
	// Kimi is routed by model name, not by path.
	// It never wins path-based routing.
	return false
}

func (p *KimiProvider) NormalizePath(path string) string {
	return path
}

func (p *KimiProvider) DetectsSSE(path string, contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/event-stream")
}

// kimiModels lists model names that should be routed to the Kimi provider.
// Pi's built-in kimi-coding provider exposes both short aliases and provider-native IDs.
var kimiModels = map[string]bool{
	"kimi-for-coding":  true,
	"kimi":             true,
	"k2p5":             true,
	"kimi-k2-thinking": true,
}

// isKimiModel returns true if the given model name should be routed to Kimi.
func isKimiModel(model string) bool {
	return kimiModels[strings.ToLower(strings.TrimSpace(model))]
}

func parseKimiResponseRateLimits(headers http.Header) (UsageSnapshot, bool) {
	if headers == nil {
		return UsageSnapshot{}, false
	}

	snap := UsageSnapshot{
		RetrievedAt: time.Now(),
		Source:      "headers",
	}
	hasPrimary := false
	hasSecondary := false

	if pct, ok := parseRateLimitPercent(headers.Get("x-ratelimit-requests-utilization")); ok {
		snap.PrimaryUsedPercent = pct
		snap.PrimaryUsed = pct
		hasPrimary = true
	} else if pct, ok := parseRateLimitUsageFromRemainingLimit(headers, "x-ratelimit-remaining-requests", "x-ratelimit-limit-requests"); ok {
		snap.PrimaryUsedPercent = pct
		snap.PrimaryUsed = pct
		hasPrimary = true
	} else if pct, ok := parseRateLimitUsageFromRemainingLimit(headers, "x-ratelimit-requests-remaining", "x-ratelimit-requests-limit"); ok {
		snap.PrimaryUsedPercent = pct
		snap.PrimaryUsed = pct
		hasPrimary = true
	} else if pct, ok := parseRateLimitUsageFromRemainingLimit(headers, "x-ratelimit-remaining", "x-ratelimit-limit"); ok {
		snap.PrimaryUsedPercent = pct
		snap.PrimaryUsed = pct
		hasPrimary = true
	}

	if pct, ok := parseRateLimitPercent(headers.Get("x-ratelimit-tokens-utilization")); ok {
		snap.SecondaryUsedPercent = pct
		snap.SecondaryUsed = pct
		hasSecondary = true
	} else if pct, ok := parseRateLimitUsageFromRemainingLimit(headers, "x-ratelimit-remaining-tokens", "x-ratelimit-limit-tokens"); ok {
		snap.SecondaryUsedPercent = pct
		snap.SecondaryUsed = pct
		hasSecondary = true
	}

	if !hasPrimary && !hasSecondary {
		return UsageSnapshot{}, false
	}

	requestsReset, ok := parseRateLimitReset(headers.Get("x-ratelimit-reset-requests"))
	if !ok {
		requestsReset, ok = parseRateLimitReset(headers.Get("x-ratelimit-requests-reset"))
	}
	if ok {
		snap.PrimaryResetAt = requestsReset
	}

	tokensReset, ok := parseRateLimitReset(headers.Get("x-ratelimit-reset-tokens"))
	if !ok {
		tokensReset, ok = parseRateLimitReset(headers.Get("x-ratelimit-tokens-reset"))
	}
	if ok {
		snap.SecondaryResetAt = tokensReset
	}

	return snap, true
}
