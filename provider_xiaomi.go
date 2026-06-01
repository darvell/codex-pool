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

// XiaomiProvider handles Xiaomi MiMo Token Plan accounts through the Anthropic-compatible API.
type XiaomiProvider struct {
	xiaomiBase *url.URL
}

// NewXiaomiProvider creates a new Xiaomi MiMo provider.
func NewXiaomiProvider(xiaomiBase *url.URL) *XiaomiProvider {
	return &XiaomiProvider{xiaomiBase: xiaomiBase}
}

func (p *XiaomiProvider) Type() AccountType {
	return AccountTypeXiaomi
}

type XiaomiAuthJSON struct {
	APIKey   string `json:"api_key"`
	Dead     bool   `json:"dead"`
	Disabled bool   `json:"disabled"`
}

func (p *XiaomiProvider) LoadAccount(name, path string, data []byte) (*Account, error) {
	var xj XiaomiAuthJSON
	if err := json.Unmarshal(data, &xj); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if xj.APIKey == "" {
		return nil, nil
	}

	acc := &Account{
		Type:        AccountTypeXiaomi,
		ID:          strings.TrimSuffix(name, filepath.Ext(name)),
		File:        path,
		AccessToken: xj.APIKey,
		PlanType:    "xiaomi",
		Dead:        xj.Dead,
		Disabled:    xj.Disabled,
	}
	return acc, nil
}

func (p *XiaomiProvider) SetAuthHeaders(req *http.Request, acc *Account) {
	req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
}

func (p *XiaomiProvider) RefreshToken(ctx context.Context, acc *Account, transport http.RoundTripper) error {
	return nil
}

func (p *XiaomiProvider) ParseUsage(obj map[string]any) *RequestUsage {
	if usageMap, ok := obj["usage"].(map[string]any); ok {
		ru := xiaomiUsageFromMap(usageMap)
		if ru == nil {
			return nil
		}
		if model, ok := obj["model"].(string); ok {
			ru.Model = model
		}
		return ru
	}

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
		ru := xiaomiUsageFromMap(usageMap)
		if ru == nil {
			return nil
		}
		if model, ok := msg["model"].(string); ok {
			ru.Model = model
		}
		return ru
	}

	return nil
}

func xiaomiUsageFromMap(usageMap map[string]any) *RequestUsage {
	ru := &RequestUsage{Timestamp: time.Now()}
	ru.InputTokens = readInt64(usageMap, "input_tokens")
	ru.OutputTokens = readInt64(usageMap, "output_tokens")
	ru.CachedInputTokens = readInt64(usageMap, "cache_read_input_tokens")
	if ru.InputTokens == 0 && ru.OutputTokens == 0 {
		return nil
	}
	ru.BillableTokens = clampNonNegative(ru.InputTokens - ru.CachedInputTokens + ru.OutputTokens)
	return ru
}

func (p *XiaomiProvider) ParseUsageHeaders(acc *Account, headers http.Header) {
}

func (p *XiaomiProvider) UpstreamURL(path string) *url.URL {
	return p.xiaomiBase
}

func (p *XiaomiProvider) MatchesPath(path string) bool {
	return false
}

func (p *XiaomiProvider) NormalizePath(path string) string {
	return path
}

func (p *XiaomiProvider) DetectsSSE(path string, contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/event-stream")
}

var xiaomiModels = map[string]string{
	"mimo-v2.5-pro":     "mimo-v2.5-pro",
	"mimo-v2.5-pro[1m]": "mimo-v2.5-pro",
}

func isXiaomiModel(model string) bool {
	_, ok := xiaomiModels[strings.ToLower(strings.TrimSpace(model))]
	return ok
}

func xiaomiCanonicalModel(model string) string {
	if canonical, ok := xiaomiModels[strings.ToLower(strings.TrimSpace(model))]; ok {
		return canonical
	}
	return model
}
