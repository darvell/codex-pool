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

// ZAIProvider handles Z.ai GLM Coding Plan accounts through the Anthropic-compatible API.
type ZAIProvider struct {
	zaiBase *url.URL
}

// NewZAIProvider creates a new Z.ai provider.
func NewZAIProvider(zaiBase *url.URL) *ZAIProvider {
	return &ZAIProvider{
		zaiBase: zaiBase,
	}
}

func (p *ZAIProvider) Type() AccountType {
	return AccountTypeZAI
}

type ZAIAuthJSON struct {
	APIKey string `json:"api_key"`
}

func (p *ZAIProvider) LoadAccount(name, path string, data []byte) (*Account, error) {
	var zj ZAIAuthJSON
	if err := json.Unmarshal(data, &zj); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if zj.APIKey == "" {
		return nil, nil
	}

	acc := &Account{
		Type:        AccountTypeZAI,
		ID:          strings.TrimSuffix(name, filepath.Ext(name)),
		File:        path,
		AccessToken: zj.APIKey,
		PlanType:    "zai",
	}
	return acc, nil
}

func (p *ZAIProvider) SetAuthHeaders(req *http.Request, acc *Account) {
	req.Header.Set("X-Api-Key", acc.AccessToken)
}

func (p *ZAIProvider) RefreshToken(ctx context.Context, acc *Account, transport http.RoundTripper) error {
	return nil
}

func (p *ZAIProvider) ParseUsage(obj map[string]any) *RequestUsage {
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

func (p *ZAIProvider) ParseUsageHeaders(acc *Account, headers http.Header) {
	// Z.ai's Anthropic-compatible endpoint does not currently expose quota headers.
}

func (p *ZAIProvider) UpstreamURL(path string) *url.URL {
	return p.zaiBase
}

func (p *ZAIProvider) MatchesPath(path string) bool {
	// Z.ai is model-routed.
	return false
}

func (p *ZAIProvider) NormalizePath(path string) string {
	return path
}

func (p *ZAIProvider) DetectsSSE(path string, contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/event-stream")
}

var zaiModels = map[string]string{
	"glm-5.1": "glm-5.1",
}

func isZAIModel(model string) bool {
	_, ok := zaiModels[strings.ToLower(strings.TrimSpace(model))]
	return ok
}

func zaiCanonicalModel(model string) string {
	if canonical, ok := zaiModels[strings.ToLower(strings.TrimSpace(model))]; ok {
		return canonical
	}
	return model
}
