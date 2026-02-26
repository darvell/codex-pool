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
	// OAuth tokens start with sk-ant-oat, API keys with sk-ant-api
	if strings.HasPrefix(acc.AccessToken, "sk-ant-oat") {
		req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
	} else {
		req.Header.Set("X-Api-Key", acc.AccessToken)
	}
}

func (p *ClaudeProvider) RefreshToken(ctx context.Context, acc *Account, transport http.RoundTripper) error {
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
		// Extract model from message object (e.g., "claude-sonnet-4-5-20250929")
		if model, ok := msg["model"].(string); ok {
			ru.Model = model
		}
		// Clamp to non-negative since cached can exceed input in Claude's API
		ru.BillableTokens = clampNonNegative(ru.InputTokens - ru.CachedInputTokens)
		return ru
	}

	return nil
}

func (p *ClaudeProvider) ParseUsageHeaders(acc *Account, headers http.Header) {
	// Claude usage should come from the periodic /api/oauth/usage poller only.
	_ = acc
	_ = headers
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
