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
	// Only load files with claude_ prefix
	if !strings.HasPrefix(name, "claude_") {
		return nil, nil
	}

	var cj ClaudeAuthJSON
	if err := json.Unmarshal(data, &cj); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	acc := &Account{
		Type: AccountTypeClaude,
		ID:   strings.TrimSuffix(name, filepath.Ext(name)),
		File: path,
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
	} else {
		req.Header.Set("X-Api-Key", acc.AccessToken)
	}
}

func (p *ClaudeProvider) RefreshToken(ctx context.Context, acc *Account, transport *http.Transport) error {
	// Claude doesn't currently support token refresh via API
	// OAuth tokens from Claude Code need to be refreshed manually
	return nil
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
		ru.BillableTokens = ru.InputTokens - ru.CachedInputTokens
		return ru
	}

	return nil
}

func (p *ClaudeProvider) ParseUsageHeaders(acc *Account, headers http.Header) {
	// Claude uses anthropic-ratelimit-* headers
	tokensLimit := headers.Get("anthropic-ratelimit-tokens-limit")
	tokensRemaining := headers.Get("anthropic-ratelimit-tokens-remaining")

	if tokensLimit == "" {
		return
	}

	acc.mu.Lock()
	defer acc.mu.Unlock()

	snap := acc.Usage
	snap.RetrievedAt = time.Now()
	snap.Source = "headers"

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

	acc.Usage = mergeUsage(acc.Usage, snap)
}

func (p *ClaudeProvider) UpstreamURL() *url.URL {
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
