package main

import (
	"encoding/json"
	"log"
	"time"
)

// clampNonNegative ensures a value is never negative.
// This prevents issues where CachedInputTokens > InputTokens produces negative billable tokens.
func clampNonNegative(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}

// parseTokenCountEvent extracts usage from Codex token_count SSE events.
// Format: {type: "token_count", info: {last_token_usage: {...}, total_token_usage: {...}}, rate_limits: {...}}
func parseTokenCountEvent(obj map[string]any) *RequestUsage {
	info, ok := obj["info"].(map[string]any)
	if !ok || info == nil {
		return nil
	}

	// Prefer last_token_usage (per-request) over total_token_usage (cumulative)
	var usageMap map[string]any
	if ltu, ok := info["last_token_usage"].(map[string]any); ok {
		usageMap = ltu
	} else if ttu, ok := info["total_token_usage"].(map[string]any); ok {
		usageMap = ttu
	}
	if usageMap == nil {
		return nil
	}

	ru := &RequestUsage{Timestamp: time.Now()}
	ru.InputTokens = readInt64(usageMap, "input_tokens")
	ru.CachedInputTokens = readInt64(usageMap, "cached_input_tokens")
	ru.OutputTokens = readInt64(usageMap, "output_tokens")
	ru.ReasoningTokens = readInt64(usageMap, "reasoning_output_tokens")

	// Calculate billable tokens (input - cached + output)
	// Clamp to non-negative since cached can exceed input in some cases
	ru.BillableTokens = clampNonNegative(ru.InputTokens - ru.CachedInputTokens + ru.OutputTokens)

	if ru.InputTokens == 0 && ru.OutputTokens == 0 {
		return nil
	}

	// Extract rate limits for capacity tracking
	if rl, ok := obj["rate_limits"].(map[string]any); ok {
		if primary, ok := rl["primary"].(map[string]any); ok {
			ru.PrimaryUsedPct = readFloat64(primary, "used_percent") / 100.0
		}
		if secondary, ok := rl["secondary"].(map[string]any); ok {
			ru.SecondaryUsedPct = readFloat64(secondary, "used_percent") / 100.0
		}
	}

	return ru
}

func (h *proxyHandler) recordUsage(a *Account, ru RequestUsage) {
	if a == nil {
		return
	}
	a.applyRequestUsage(ru)
	if h.store != nil {
		_ = h.store.record(ru)
	}
	if h.cfg.debug {
		log.Printf("token_count: account=%s plan=%s user=%s in=%d cached=%d out=%d reasoning=%d billable=%d primary=%.1f%% secondary=%.1f%%",
			ru.AccountID, ru.PlanType, ru.UserID, ru.InputTokens, ru.CachedInputTokens, ru.OutputTokens, ru.ReasoningTokens, ru.BillableTokens,
			ru.PrimaryUsedPct*100, ru.SecondaryUsedPct*100)
	}
}

func parseRequestUsage(obj map[string]any) *RequestUsage {
	usageMap, ok := obj["usage"].(map[string]any)
	if !ok {
		return nil
	}
	ru := &RequestUsage{Timestamp: time.Now()}
	ru.InputTokens = readInt64(usageMap, "input_tokens")
	ru.CachedInputTokens = readInt64(usageMap, "cached_input_tokens")
	if ru.CachedInputTokens == 0 {
		ru.CachedInputTokens = readInt64(usageMap, "cache_read_input_tokens")
	}
	ru.OutputTokens = readInt64(usageMap, "output_tokens")
	ru.ReasoningTokens = readInt64(usageMap, "reasoning_output_tokens")
	ru.BillableTokens = readInt64(usageMap, "billable_tokens")
	if ru.BillableTokens == 0 {
		ru.BillableTokens = clampNonNegative(ru.InputTokens - ru.CachedInputTokens + ru.OutputTokens)
	}
	if ru.InputTokens == 0 && ru.OutputTokens == 0 && ru.BillableTokens == 0 {
		return nil
	}
	if v, ok := obj["prompt_cache_key"].(string); ok {
		ru.PromptCacheKey = v
	}
	return ru
}

// parseResponseUsage extracts usage from Codex SSE response events.
// Format: {"usage": {"input_tokens": N, "input_tokens_details": {"cached_tokens": N}, "output_tokens": N, "output_tokens_details": {"reasoning_tokens": N}}}
func parseResponseUsage(obj map[string]any) *RequestUsage {
	// Usage can be at top level or nested in response object
	usageMap, ok := obj["usage"].(map[string]any)
	if !ok || usageMap == nil {
		// Check if usage is nested in response
		if resp, ok := obj["response"].(map[string]any); ok {
			usageMap, ok = resp["usage"].(map[string]any)
			if !ok || usageMap == nil {
				return nil
			}
		} else {
			return nil
		}
	}

	ru := &RequestUsage{Timestamp: time.Now()}
	ru.InputTokens = readInt64(usageMap, "input_tokens")
	ru.OutputTokens = readInt64(usageMap, "output_tokens")

	// Extract cached tokens from input_tokens_details (OpenAI/Codex format)
	if details, ok := usageMap["input_tokens_details"].(map[string]any); ok {
		ru.CachedInputTokens = readInt64(details, "cached_tokens")
	}
	// Also check for Claude format: cache_read_input_tokens at top level
	if ru.CachedInputTokens == 0 {
		ru.CachedInputTokens = readInt64(usageMap, "cache_read_input_tokens")
	}

	// Extract reasoning tokens from output_tokens_details
	if details, ok := usageMap["output_tokens_details"].(map[string]any); ok {
		ru.ReasoningTokens = readInt64(details, "reasoning_tokens")
	}

	// Calculate billable tokens (clamped to non-negative)
	ru.BillableTokens = clampNonNegative(ru.InputTokens - ru.CachedInputTokens + ru.OutputTokens)

	if ru.InputTokens == 0 && ru.OutputTokens == 0 {
		return nil
	}

	// Extract prompt cache key if present
	if v, ok := obj["prompt_cache_key"].(string); ok {
		ru.PromptCacheKey = v
	}

	return ru
}

// parseClaudeUsage extracts usage from Claude SSE response events.
// Claude sends usage in two events:
// - message_start: {"type": "message_start", "message": {"usage": {"input_tokens": N, "output_tokens": 1}}}
// - message_delta: {"type": "message_delta", "usage": {"output_tokens": N}} (cumulative)
// We extract from message_delta which has the final output token count.
func parseClaudeUsage(obj map[string]any) *RequestUsage {
	eventType, _ := obj["type"].(string)

	// Handle message_delta event (has final output tokens)
	if eventType == "message_delta" {
		usageMap, ok := obj["usage"].(map[string]any)
		if !ok || usageMap == nil {
			return nil
		}
		ru := &RequestUsage{Timestamp: time.Now()}
		ru.OutputTokens = readInt64(usageMap, "output_tokens")
		// message_delta doesn't have input_tokens, we'll get those from message_start
		// For now, just return output tokens - the caller should accumulate
		if ru.OutputTokens == 0 {
			return nil
		}
		ru.BillableTokens = ru.OutputTokens // Will be updated when combined with input
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

// parseGeminiUsage extracts usage from Gemini SSE response events.
// Format: {"usageMetadata": {"promptTokenCount": N, "candidatesTokenCount": N, "totalTokenCount": N, "cachedContentTokenCount": N}}
func parseGeminiUsage(obj map[string]any) *RequestUsage {
	usageMap, ok := obj["usageMetadata"].(map[string]any)
	if !ok || usageMap == nil {
		return nil
	}

	ru := &RequestUsage{Timestamp: time.Now()}
	ru.InputTokens = readInt64(usageMap, "promptTokenCount")
	ru.OutputTokens = readInt64(usageMap, "candidatesTokenCount")
	ru.CachedInputTokens = readInt64(usageMap, "cachedContentTokenCount")

	// Calculate billable tokens (clamped to non-negative)
	ru.BillableTokens = clampNonNegative(ru.InputTokens - ru.CachedInputTokens + ru.OutputTokens)

	if ru.InputTokens == 0 && ru.OutputTokens == 0 {
		return nil
	}

	return ru
}

func readInt64(m map[string]any, key string) int64 {
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case float64:
			return int64(t)
		case int64:
			return t
		case int:
			return int64(t)
		case json.Number:
			if n, err := t.Int64(); err == nil {
				return n
			}
		}
	}
	return 0
}

func readFloat64(m map[string]any, key string) float64 {
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case float64:
			return t
		case int64:
			return float64(t)
		case int:
			return float64(t)
		case json.Number:
			if f, err := t.Float64(); err == nil {
				return f
			}
		}
	}
	return 0
}
