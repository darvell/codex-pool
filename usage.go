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
