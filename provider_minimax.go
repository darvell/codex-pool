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

// MinimaxProvider handles MiniMax API accounts.
type MinimaxProvider struct {
	minimaxBase *url.URL
}

// NewMinimaxProvider creates a new MiniMax provider.
func NewMinimaxProvider(minimaxBase *url.URL) *MinimaxProvider {
	return &MinimaxProvider{
		minimaxBase: minimaxBase,
	}
}

func (p *MinimaxProvider) Type() AccountType {
	return AccountTypeMinimax
}

// MinimaxAuthJSON is the format for MiniMax auth files.
type MinimaxAuthJSON struct {
	APIKey string `json:"api_key"`
}

func (p *MinimaxProvider) LoadAccount(name, path string, data []byte) (*Account, error) {
	var mj MinimaxAuthJSON
	if err := json.Unmarshal(data, &mj); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if mj.APIKey == "" {
		return nil, nil
	}

	acc := &Account{
		Type:        AccountTypeMinimax,
		ID:          strings.TrimSuffix(name, filepath.Ext(name)),
		File:        path,
		AccessToken: mj.APIKey,
		PlanType:    "minimax",
	}
	return acc, nil
}

func (p *MinimaxProvider) SetAuthHeaders(req *http.Request, acc *Account) {
	req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
}

func (p *MinimaxProvider) RefreshToken(ctx context.Context, acc *Account, transport http.RoundTripper) error {
	return nil
}

func (p *MinimaxProvider) ParseUsage(obj map[string]any) *RequestUsage {
	// MiniMax uses the Anthropic API format since the base URL is /anthropic
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

func (p *MinimaxProvider) ParseUsageHeaders(acc *Account, headers http.Header) {
	applyMinimaxRateLimits(acc, headers, time.Now())
}

func (p *MinimaxProvider) UpstreamURL(path string) *url.URL {
	return p.minimaxBase
}

func (p *MinimaxProvider) MatchesPath(path string) bool {
	// MiniMax is routed by model name, not by path.
	return false
}

func (p *MinimaxProvider) NormalizePath(path string) string {
	return path
}

func (p *MinimaxProvider) DetectsSSE(path string, contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/event-stream")
}

// minimaxModels maps request model names to the canonical model name sent upstream.
var minimaxModels = map[string]string{
	"minimax":                "MiniMax-M2.5",
	"minimax-m2":             "MiniMax-M2",
	"minimax-m2.1":           "MiniMax-M2.1",
	"minimax-m2.5":           "MiniMax-M2.5",
	"minimax-m2.7":           "MiniMax-M2.7",
	"minimax-m2.7-highspeed": "MiniMax-M2.7-highspeed",
}

// isMinimaxModel returns true if the given model name should be routed to MiniMax.
func isMinimaxModel(model string) bool {
	_, ok := minimaxModels[strings.ToLower(strings.TrimSpace(model))]
	return ok
}

// minimaxCanonicalModel returns the canonical upstream model name for a MiniMax alias.
func minimaxCanonicalModel(model string) string {
	if canonical, ok := minimaxModels[strings.ToLower(strings.TrimSpace(model))]; ok {
		return canonical
	}
	return model
}
