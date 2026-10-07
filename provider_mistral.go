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

// MistralProvider handles ordinary paid Mistral API keys. Public model IDs are
// always namespaced as mistral/<upstream-id>; bare IDs are intentionally never
// claimed because Mistral's catalog overlaps other pool providers.
type MistralProvider struct {
	mistralBase *url.URL
}

func NewMistralProvider(mistralBase *url.URL) *MistralProvider {
	return &MistralProvider{mistralBase: mistralBase}
}

func (p *MistralProvider) Type() AccountType { return AccountTypeMistral }

type MistralAuthJSON struct {
	APIKey   string `json:"api_key"`
	Dead     bool   `json:"dead"`
	Disabled bool   `json:"disabled"`
}

func (p *MistralProvider) LoadAccount(name, path string, data []byte) (*Account, error) {
	var auth MistralAuthJSON
	if err := json.Unmarshal(data, &auth); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	auth.APIKey = strings.TrimSpace(auth.APIKey)
	if auth.APIKey == "" {
		return nil, nil
	}
	return &Account{
		Type: AccountTypeMistral, ID: strings.TrimSuffix(name, filepath.Ext(name)), File: path,
		AccessToken: auth.APIKey, PlanType: "mistral_api", Dead: auth.Dead, Disabled: auth.Disabled,
	}, nil
}

func (p *MistralProvider) SetAuthHeaders(req *http.Request, acc *Account) {
	req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
}

func (p *MistralProvider) RefreshToken(context.Context, *Account, http.RoundTripper) error {
	return nil
}

func (p *MistralProvider) ParseUsage(obj map[string]any) *RequestUsage {
	usage, ok := obj["usage"].(map[string]any)
	if !ok {
		return nil
	}
	ru := &RequestUsage{Timestamp: time.Now(), InputTokenMode: "inclusive"}
	ru.InputTokens = readInt64(usage, "prompt_tokens")
	if ru.InputTokens == 0 {
		ru.InputTokens = readInt64(usage, "input_tokens")
	}
	ru.OutputTokens = readInt64(usage, "completion_tokens")
	if ru.OutputTokens == 0 {
		ru.OutputTokens = readInt64(usage, "output_tokens")
	}
	if details, ok := usage["prompt_tokens_details"].(map[string]any); ok {
		ru.CachedInputTokens = readInt64(details, "cached_tokens")
	}
	ru.BillableTokens = clampNonNegative(ru.InputTokens - ru.CachedInputTokens + ru.OutputTokens)
	if ru.InputTokens == 0 && ru.OutputTokens == 0 {
		return nil
	}
	if model, ok := obj["model"].(string); ok {
		ru.Model = mistralCatalogID(model)
	}
	return ru
}

// Mistral's rate-limit headers describe short request/token windows. They are
// deliberately not copied into UsageSnapshot, whose percentages drive
// subscription-quota routing and would mislabel minute limits as monthly spend.
func (p *MistralProvider) ParseUsageHeaders(*Account, http.Header) {}

func (p *MistralProvider) UpstreamURL(string) *url.URL { return p.mistralBase }
func (p *MistralProvider) MatchesPath(string) bool     { return false }

func (p *MistralProvider) NormalizePath(path string) string {
	trimmed := strings.TrimRight(path, "/")
	if strings.HasSuffix(trimmed, "/chat/completions") {
		return "/v1/chat/completions"
	}
	return path
}

func (p *MistralProvider) DetectsSSE(_ string, contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/event-stream")
}

func mistralBareID(model string) (string, bool) {
	trimmed := strings.TrimSpace(model)
	if len(trimmed) <= len("mistral/") || !strings.EqualFold(trimmed[:len("mistral/")], "mistral/") {
		return "", false
	}
	bare := strings.TrimSpace(trimmed[len("mistral/"):])
	return bare, bare != ""
}

func mistralCatalogID(upstream string) string {
	if bare, ok := mistralBareID(upstream); ok {
		return "mistral/" + bare
	}
	return "mistral/" + strings.TrimSpace(upstream)
}

func isMistralModel(model string) bool {
	_, ok := mistralBareID(model)
	return ok
}

func mistralCanonicalModel(model string) string {
	if isMistralVibeModel(model) {
		return strings.TrimSpace(strings.TrimSpace(model)[len("mistral-vibe/"):])
	}
	if bare, ok := mistralBareID(model); ok {
		return bare
	}
	return strings.TrimSpace(model)
}

// mistralReasoningEffort collapses an OpenAI-style four-level reasoning
// effort onto the two-value enum Mistral's Chat Completions API accepts.
// Mistral Vibe (github.com/mistralai/mistral-vibe, adapters/mistral.py)
// maps its own low/medium/high/max thinking levels the same way: only the
// weakest level turns reasoning off, everything else asks for "high".
func mistralReasoningEffort(effort string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "none":
		return "none", true
	case "minimal", "low":
		return "none", true
	case "medium", "high", "max":
		return "high", true
	default:
		return "", false
	}
}

// normalizeMistralAssistantReasoning converts the generic reasoning fields
// used by OpenAI-compatible clients back into Mistral's native Chat
// Completions content block. Mistral returns that block on the preceding tool
// call turn, so it must survive a client round trip when the tool result is
// submitted. Existing content blocks and tool-call fields remain untouched.
func normalizeMistralAssistantReasoning(message map[string]any) {
	if message["role"] != "assistant" {
		return
	}

	// Gather before mutating: if content has an unexpected shape, retaining the
	// generic fields is safer than silently discarding reasoning or content.
	var thinking []any
	var converted []string
	for _, key := range []string{"reasoning_content", "reasoning", "reasoning_text"} {
		value, present := message[key]
		if !present {
			continue
		}
		if value == nil {
			converted = append(converted, key)
			continue
		}
		text, ok := value.(string)
		if !ok {
			continue
		}
		converted = append(converted, key)
		if text != "" {
			thinking = append(thinking, map[string]any{"type": "text", "text": text})
		}
	}
	if len(converted) == 0 {
		return
	}
	if len(thinking) == 0 {
		for _, key := range converted {
			delete(message, key)
		}
		return
	}

	var content []any
	if rawContent, present := message["content"]; present && rawContent != nil {
		switch value := rawContent.(type) {
		case string:
			content = []any{map[string]any{"type": "text", "text": value}}
		case []any:
			content = value
		default:
			return
		}
	}
	content = append([]any{map[string]any{"type": "thinking", "thinking": thinking}}, content...)
	message["content"] = content
	for _, key := range converted {
		delete(message, key)
	}
}

// rewriteMistralRequestBody keeps the OpenAI-compatible request conservative.
// The Messages adapter has already dropped Anthropic-only fields; this final
// pass canonicalizes the model, restores replayed reasoning to Mistral's
// native content shape, asks Mistral to include stream usage, and collapses
// any four-level reasoning_effort onto Mistral's accepted enum.
func rewriteMistralRequestBody(body []byte, model string) []byte {
	var obj map[string]any
	if len(body) == 0 || json.Unmarshal(body, &obj) != nil {
		return body
	}
	obj["model"] = mistralCanonicalModel(model)
	// Pi's OpenAI Chat Completions adapter emits OpenAI-only fields and a
	// developer role. Mistral rejects developer messages and the store field
	// with 422, even when store is false.
	delete(obj, "store")
	if messages, ok := obj["messages"].([]any); ok {
		for _, raw := range messages {
			if message, ok := raw.(map[string]any); ok {
				if message["role"] == "developer" {
					message["role"] = "system"
				}
				normalizeMistralAssistantReasoning(message)
			}
		}
	}
	if stream, _ := obj["stream"].(bool); stream {
		options, _ := obj["stream_options"].(map[string]any)
		if options == nil {
			options = map[string]any{}
		}
		options["include_usage"] = true
		obj["stream_options"] = options
	}
	if effort, ok := obj["reasoning_effort"].(string); ok {
		if mapped, valid := mistralReasoningEffort(effort); valid {
			obj["reasoning_effort"] = mapped
		} else {
			delete(obj, "reasoning_effort")
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}
