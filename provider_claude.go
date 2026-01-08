package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ClaudeProvider handles Anthropic Claude accounts.
type ClaudeProvider struct {
	claudeBase *url.URL
}

// NewClaudeProvider creates a new Claude provider.
func NewClaudeProvider(claudeBase *url.URL) *ClaudeProvider {
	return &ClaudeProvider{
		claudeBase: claudeBase,
	}
}

func (p *ClaudeProvider) Type() AccountType {
	return AccountTypeClaude
}

func (p *ClaudeProvider) LoadAccount(name, path string, data []byte) (*Account, error) {
	var cj ClaudeAuthJSON
	if err := json.Unmarshal(data, &cj); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	acc := &Account{
		Type: AccountTypeClaude,
		ID:   strings.TrimSuffix(name, filepath.Ext(name)),
		File: path,
	}

	// Load last_refresh from root level (for rate limiting across restarts)
	var root map[string]any
	if err := json.Unmarshal(data, &root); err == nil {
		if lr, ok := root["last_refresh"].(string); ok && lr != "" {
			if t, err := time.Parse(time.RFC3339Nano, lr); err == nil {
				acc.LastRefresh = t
			} else if t, err := time.Parse(time.RFC3339, lr); err == nil {
				acc.LastRefresh = t
			}
		}
	}

	// Check for OAuth format first (from Claude Code keychain)
	if cj.ClaudeAiOauth != nil && cj.ClaudeAiOauth.AccessToken != "" {
		acc.AccessToken = cj.ClaudeAiOauth.AccessToken
		acc.RefreshToken = cj.ClaudeAiOauth.RefreshToken
		if cj.ClaudeAiOauth.ExpiresAt > 0 {
			acc.ExpiresAt = time.UnixMilli(cj.ClaudeAiOauth.ExpiresAt)
		}
		acc.PlanType = cj.ClaudeAiOauth.SubscriptionType
		if acc.PlanType == "" {
			acc.PlanType = "claude"
		}
		return acc, nil
	}

	// Fall back to API key format
	if cj.APIKey == "" {
		return nil, nil
	}
	acc.AccessToken = cj.APIKey
	acc.PlanType = cj.PlanType
	if acc.PlanType == "" {
		acc.PlanType = "claude"
	}
	return acc, nil
}

func (p *ClaudeProvider) SetAuthHeaders(req *http.Request, acc *Account) {
	// Required header for Claude API
	req.Header.Set("anthropic-version", "2023-06-01")

	// OAuth tokens start with sk-ant-oat, API keys with sk-ant-api
	if strings.HasPrefix(acc.AccessToken, "sk-ant-oat") {
		req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
		// Required for OAuth tokens to work - tells Anthropic this is a browser/CLI client
		req.Header.Set("anthropic-dangerous-direct-browser-access", "true")
		// Beta features header - must include oauth-2025-04-20 for OAuth tokens
		req.Header.Set("anthropic-beta", "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27")
		// User-Agent must match Claude Code
		req.Header.Set("User-Agent", "claude-cli/2.0.76 (external, cli)")
		// X-App header identifies the client
		req.Header.Set("X-App", "cli")
		// Standard request headers
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Accept-Language", "*")
		req.Header.Set("Accept-Encoding", "gzip, br")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		// Stainless SDK headers (must match Claude Code client)
		req.Header.Set("x-stainless-lang", "js")
		req.Header.Set("x-stainless-package-version", "0.70.0")
		req.Header.Set("x-stainless-os", "MacOS")
		req.Header.Set("x-stainless-arch", "arm64")
		req.Header.Set("x-stainless-runtime", "node")
		req.Header.Set("x-stainless-runtime-version", "v24.3.0")
		req.Header.Set("x-stainless-retry-count", "0")
		req.Header.Set("x-stainless-timeout", "600")
		req.Header.Set("x-stainless-helper-method", "stream")
	} else {
		req.Header.Set("X-Api-Key", acc.AccessToken)
	}
}

func (p *ClaudeProvider) RefreshToken(ctx context.Context, acc *Account, transport *http.Transport) error {
	// Only OAuth tokens (not API keys) can be refreshed
	if !strings.HasPrefix(acc.AccessToken, "sk-ant-oat") {
		// API keys don't need refresh
		return nil
	}

	return RefreshClaudeAccountTokens(acc)
}

func (p *ClaudeProvider) ParseUsage(obj map[string]any) *RequestUsage {
	eventType, _ := obj["type"].(string)

	// Handle message_delta event (has final output tokens)
	if eventType == "message_delta" {
		usageMap, ok := obj["usage"].(map[string]any)
		if !ok || usageMap == nil {
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

	// Handle message_start event (has input tokens)
	if eventType == "message_start" {
		msg, ok := obj["message"].(map[string]any)
		if !ok || msg == nil {
			return nil
		}
		usageMap, ok := msg["usage"].(map[string]any)
		if !ok || usageMap == nil {
			return nil
		}
		ru := &RequestUsage{Timestamp: time.Now()}
		ru.InputTokens = readInt64(usageMap, "input_tokens")
		ru.CachedInputTokens = readInt64(usageMap, "cache_read_input_tokens")
		if ru.InputTokens == 0 {
			return nil
		}
		// Clamp to non-negative since cached can exceed input in Claude's API
		ru.BillableTokens = clampNonNegative(ru.InputTokens - ru.CachedInputTokens)
		return ru
	}

	return nil
}

func (p *ClaudeProvider) ParseUsageHeaders(acc *Account, headers http.Header) {
	acc.mu.Lock()
	defer acc.mu.Unlock()

	snap := acc.Usage
	snap.RetrievedAt = time.Now()
	snap.Source = "headers"

	// Try unified rate limit headers first (used by Claude Code CLI)
	// These have format: anthropic-ratelimit-unified-{type}-utilization (0-100)
	// and anthropic-ratelimit-unified-{type}-reset (Unix seconds)
	unifiedTypes := []string{"primary", "secondary", "tokens", "requests"}
	foundUnified := false

	for _, ut := range unifiedTypes {
		utilization := headers.Get("anthropic-ratelimit-unified-" + ut + "-utilization")
		reset := headers.Get("anthropic-ratelimit-unified-" + ut + "-reset")

		if utilization != "" {
			foundUnified = true
			if util, err := strconv.ParseFloat(utilization, 64); err == nil {
				// Utilization is 0-100, convert to 0-1
				normalized := util / 100.0
				if ut == "primary" || ut == "tokens" {
					snap.PrimaryUsedPercent = normalized
					snap.PrimaryUsed = normalized
				} else if ut == "secondary" || ut == "requests" {
					snap.SecondaryUsedPercent = normalized
					snap.SecondaryUsed = normalized
				}
			}
		}

		if reset != "" {
			if resetSec, err := strconv.ParseInt(reset, 10, 64); err == nil {
				resetTime := time.Unix(resetSec, 0)
				if ut == "primary" || ut == "tokens" {
					snap.PrimaryResetAt = resetTime
				} else if ut == "secondary" || ut == "requests" {
					snap.SecondaryResetAt = resetTime
				}
			}
		}
	}

	// Also check for unified status
	if status := headers.Get("anthropic-ratelimit-unified-status"); status != "" {
		// Status could be "ok", "warning", "exceeded" etc
		foundUnified = true
	}

	// Fall back to legacy anthropic-ratelimit-* headers
	if !foundUnified {
		tokensLimit := headers.Get("anthropic-ratelimit-tokens-limit")
		tokensRemaining := headers.Get("anthropic-ratelimit-tokens-remaining")

		// Parse token limits
		if tokensLimit != "" && tokensRemaining != "" {
			limit, err1 := strconv.ParseInt(tokensLimit, 10, 64)
			remaining, err2 := strconv.ParseInt(tokensRemaining, 10, 64)
			if err1 == nil && err2 == nil && limit > 0 {
				used := float64(limit-remaining) / float64(limit)
				snap.PrimaryUsedPercent = used
				snap.PrimaryUsed = used
			}
		}

		// Parse token reset time
		if v := headers.Get("anthropic-ratelimit-tokens-reset"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				snap.PrimaryResetAt = t
			}
		}

		// Parse request limits as secondary usage
		reqLimit := headers.Get("anthropic-ratelimit-requests-limit")
		reqRemaining := headers.Get("anthropic-ratelimit-requests-remaining")
		if reqLimit != "" && reqRemaining != "" {
			limit, err1 := strconv.ParseInt(reqLimit, 10, 64)
			remaining, err2 := strconv.ParseInt(reqRemaining, 10, 64)
			if err1 == nil && err2 == nil && limit > 0 {
				used := float64(limit-remaining) / float64(limit)
				snap.SecondaryUsedPercent = used
				snap.SecondaryUsed = used
			}
		}

		if v := headers.Get("anthropic-ratelimit-requests-reset"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				snap.SecondaryResetAt = t
			}
		}
	}

	// Only update if we found any usage data
	if snap.PrimaryUsedPercent > 0 || snap.SecondaryUsedPercent > 0 {
		acc.Usage = mergeUsage(acc.Usage, snap)
	}
}

func (p *ClaudeProvider) UpstreamURL(path string) *url.URL {
	return p.claudeBase
}

func (p *ClaudeProvider) MatchesPath(path string) bool {
	return strings.HasPrefix(path, "/v1/messages")
}

func (p *ClaudeProvider) NormalizePath(path string) string {
	// Claude paths don't need normalization
	return path
}

func (p *ClaudeProvider) DetectsSSE(path string, contentType string) bool {
	// Claude uses text/event-stream content type for SSE
	return strings.Contains(strings.ToLower(contentType), "text/event-stream")
}
