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

// AdverserialProvider handles platform.adverserial.ai accounts through its
// Anthropic-compatible API.
type AdverserialProvider struct {
	adverserialBase *url.URL
}

func NewAdverserialProvider(adverserialBase *url.URL) *AdverserialProvider {
	return &AdverserialProvider{adverserialBase: adverserialBase}
}

func (p *AdverserialProvider) Type() AccountType {
	return AccountTypeAdverserial
}

type AdverserialAuthJSON struct {
	APIKey   string `json:"api_key"`
	Dead     bool   `json:"dead"`
	Disabled bool   `json:"disabled"`
}

func (p *AdverserialProvider) LoadAccount(name, path string, data []byte) (*Account, error) {
	var aj AdverserialAuthJSON
	if err := json.Unmarshal(data, &aj); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if aj.APIKey == "" {
		return nil, nil
	}

	acc := &Account{
		Type:        AccountTypeAdverserial,
		ID:          strings.TrimSuffix(name, filepath.Ext(name)),
		File:        path,
		AccessToken: aj.APIKey,
		PlanType:    "adverserial",
		Dead:        aj.Dead,
		Disabled:    aj.Disabled,
	}
	return acc, nil
}

func (p *AdverserialProvider) SetAuthHeaders(req *http.Request, acc *Account) {
	req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
	// The upstream authenticates on the bearer token alone. A stale X-Api-Key
	// forwarded from the client must not reach it.
	req.Header.Del("X-Api-Key")
}

func (p *AdverserialProvider) RefreshToken(ctx context.Context, acc *Account, transport http.RoundTripper) error {
	return nil
}

func (p *AdverserialProvider) ParseUsage(obj map[string]any) *RequestUsage {
	if usageMap, ok := obj["usage"].(map[string]any); ok {
		ru := adverserialUsageFromMap(usageMap)
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
		ru := adverserialUsageFromMap(usageMap)
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

func adverserialUsageFromMap(usageMap map[string]any) *RequestUsage {
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

func (p *AdverserialProvider) ParseUsageHeaders(acc *Account, headers http.Header) {
}

func (p *AdverserialProvider) UpstreamURL(path string) *url.URL {
	return p.adverserialBase
}

func (p *AdverserialProvider) MatchesPath(path string) bool {
	return false
}

func (p *AdverserialProvider) NormalizePath(path string) string {
	return path
}

func (p *AdverserialProvider) DetectsSSE(path string, contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/event-stream")
}

func isAdverserialModel(model string) bool {
	_, ok := modelForProvider(AccountTypeAdverserial, model)
	return ok
}

func adverserialCanonicalModel(model string) string {
	if found, ok := modelForProvider(AccountTypeAdverserial, model); ok {
		return found.ID
	}
	return model
}

// clampAdverserialEffort maps a requested reasoning effort onto the values the
// upstream chat template actually accepts.
//
// The endpoint validates effort twice and the two layers disagree. Its JSON
// deserializer accepts none/minimal/low/medium/high/xhigh/max, but the chat
// template then rejects everything except low, high, and max with a 400
// ("unsupported thinking_effort"). `none` is the one exception: it
// short-circuits ahead of the template and returns a response with no thinking
// block.
//
// Clients legitimately ask for medium and xhigh, so silently mapping the
// unsupported values to high keeps those requests working. `none` means "the
// caller turned thinking off" — promoting it to high would override an explicit
// intent, so it becomes the cheapest supported effort instead.
func clampAdverserialEffort(effort string) string {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "low", "high", "max":
		return strings.ToLower(strings.TrimSpace(effort))
	case "none":
		return "low"
	default:
		return "high"
	}
}

// rewriteAndClampAdverserialRequestBody canonicalizes the model name and clamps
// every effort field the upstream honors.
//
// Effort arrives on two distinct fields and both reach the chat template:
// top-level `reasoning_effort`, and `output_config.effort` (what Claude Code
// and cute-code send). `reasoning_effort` wins when both are present, but an
// unsupported value in either one fails the request, so both are clamped.
// `reasoning.effort` and `thinking.*` are ignored by this upstream and are left
// untouched.
func rewriteAndClampAdverserialRequestBody(body []byte, model string) []byte {
	canonical := adverserialCanonicalModel(model)
	if len(body) == 0 {
		return body
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	changed := false
	if current, _ := obj["model"].(string); current != canonical {
		obj["model"] = canonical
		changed = true
	}
	if clampAdverserialEffortObject(obj) {
		changed = true
	}
	if !changed {
		return body
	}
	rewritten, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return rewritten
}

// clampAdverserialEffortObject clamps effort in place. Absent fields are left
// absent: the upstream has its own default, and inventing one here would
// override it for every request that never asked for an effort.
func clampAdverserialEffortObject(obj map[string]any) bool {
	changed := false
	if raw, ok := obj["reasoning_effort"]; ok {
		if effort, ok := raw.(string); ok {
			if clamped := clampAdverserialEffort(effort); clamped != effort {
				obj["reasoning_effort"] = clamped
				changed = true
			}
		} else if raw != nil {
			// A non-string, non-null value cannot deserialize upstream.
			delete(obj, "reasoning_effort")
			changed = true
		}
	}
	if outputConfig, ok := obj["output_config"].(map[string]any); ok {
		if raw, ok := outputConfig["effort"]; ok {
			if effort, ok := raw.(string); ok {
				if clamped := clampAdverserialEffort(effort); clamped != effort {
					outputConfig["effort"] = clamped
					changed = true
				}
			} else if raw != nil {
				delete(outputConfig, "effort")
				changed = true
			}
		}
	}
	return changed
}
