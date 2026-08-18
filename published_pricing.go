package main

import "time"

var forcePublishedPricing = map[string]bool{
	"claude-sonnet-5":           true, // Time-limited introductory rate through August 31, 2026.
	"k3":                        true,
	"kimi-for-coding":           true,
	"kimi-for-coding-highspeed": true,
	"MiniMax-M3":                true,
	"MiniMax-M2.7":              true,
	"MiniMax-M2.7-highspeed":    true,
	"glm-5.3":                   true,
	"mimo-v2.5-pro":             true,
	"grok-4.5":                  true,
	"lordx64/cyberkimi":         true,
}

// publishedModelPricing is the source of truth for models the pool advertises
// itself or whose pool-facing ID is not present in LiteLLM's catalog. Values
// are USD per token; advertisedModelCost converts them to the per-million-token
// units used by client model catalogs.
//
// Sources verified 2026-08-18:
//   - OpenAI: https://developers.openai.com/api/docs/models
//   - Anthropic: https://platform.claude.com/docs/en/about-claude/pricing
//   - Kimi: https://platform.kimi.ai/docs/pricing/chat
//   - MiniMax: https://platform.minimax.io/subscribe/token-plan?tab=api-enterprise
//   - Z.ai: https://docs.z.ai/guides/overview/pricing
//   - Xiaomi: https://mimo.mi.com/docs/zh-CN/price/pay-as-you-go
//   - xAI: https://docs.x.ai/developers/models/grok-4.5
//   - Google: https://ai.google.dev/gemini-api/docs/pricing
func publishedModelPricing(now time.Time) map[string]ModelPricing {
	prices := map[string]ModelPricing{
		"gpt-5.6-sol":         tieredPricing(5, 30, 0.5, 6.25, 272000, 10, 45, 1, 12.5),
		"gpt-5.6-terra":       tieredPricing(2, 12, 0.2, 2.5, 272000, 4, 18, 0.4, 5),
		"gpt-5.6-luna":        tieredPricing(0.2, 1.2, 0.02, 0.25, 272000, 0.4, 1.8, 0.04, 0.5),
		"gpt-5.5":             tieredPricing(5, 30, 0.5, 0, 272000, 10, 45, 1, 0),
		"gpt-5.4":             tieredPricing(2.5, 15, 0.25, 0, 272000, 5, 22.5, 0.5, 0),
		"gpt-5.4-mini":        flatPricing(0.75, 4.5, 0.075, 0),
		"gpt-5.3-codex-spark": flatPricing(1.75, 14, 0.175, 0),

		"claude-fable-5":             flatPricing(10, 50, 1, 12.5),
		"claude-opus-5":              flatPricing(5, 25, 0.5, 6.25),
		"claude-opus-4-8":            flatPricing(5, 25, 0.5, 6.25),
		"claude-opus-4-7":            flatPricing(5, 25, 0.5, 6.25),
		"claude-opus-4-6":            flatPricing(5, 25, 0.5, 6.25),
		"claude-opus-4-5-20251101":   flatPricing(5, 25, 0.5, 6.25),
		"claude-opus-4-1-20250805":   flatPricing(15, 75, 1.5, 18.75),
		"claude-sonnet-4-6":          flatPricing(3, 15, 0.3, 3.75),
		"claude-sonnet-4-5-20250929": flatPricing(3, 15, 0.3, 3.75),
		"claude-haiku-4-5-20251001":  flatPricing(1, 5, 0.1, 1.25),

		"k3":                        flatPricing(3, 15, 0.3, 0),
		"kimi-for-coding":           flatPricing(0.95, 4, 0.19, 0),
		"kimi-for-coding-highspeed": flatPricing(1.9, 8, 0.38, 0),
		"MiniMax-M3":                tieredPricing(0.3, 1.2, 0.06, 0, 512000, 0.6, 2.4, 0.12, 0),
		"MiniMax-M2.7":              flatPricing(0.3, 1.2, 0.06, 0.375),
		"MiniMax-M2.7-highspeed":    flatPricing(0.6, 2.4, 0.06, 0.375),
		"glm-5.3":                   flatPricing(1.4, 4.4, 0.26, 0),
		"mimo-v2.5-pro":             flatPricing(0.435, 0.87, 0.0036, 0),
		"grok-4.5":                  flatPricing(2, 6, 0.3, 0),
		"lordx64/cyberkimi":         flatPricing(3, 15, 0.3, 0), // Kimi K3 API-equivalent value; provider has no public rate.

		"gemini-3.1-pro-preview": tieredPricing(2, 12, 0.2, 0, 200000, 4, 18, 0.4, 0),
		"gemini-3-flash-preview": flatPricing(0.5, 3, 0.05, 0),
		"gemini-3.5-flash":       flatPricing(1.5, 9, 0.15, 0),
		"gemini-3.5-flash-lite":  flatPricing(0.3, 2.5, 0.03, 0),
		"gemini-3.6-flash":       flatPricing(1.5, 7.5, 0.15, 0),
		"gemini-3.7-flash":       flatPricing(0.75, 3.75, 0.075, 0),
	}

	// Anthropic's introductory Sonnet 5 rate ends after August 31, 2026.
	sonnet5 := flatPricing(2, 10, 0.2, 2.5)
	if !now.Before(time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)) {
		sonnet5 = flatPricing(3, 15, 0.3, 3.75)
	}
	prices["claude-sonnet-5"] = sonnet5
	return prices
}

func flatPricing(input, output, cacheRead, cacheWrite float64) ModelPricing {
	return ModelPricing{
		InputCostPerToken:  input / 1_000_000,
		OutputCostPerToken: output / 1_000_000,
		CacheReadCost:      cacheRead / 1_000_000,
		CacheWriteCost:     cacheWrite / 1_000_000,
	}
}

func tieredPricing(input, output, cacheRead, cacheWrite float64, threshold int64, longInput, longOutput, longCacheRead, longCacheWrite float64) ModelPricing {
	pricing := flatPricing(input, output, cacheRead, cacheWrite)
	pricing.LongContextThreshold = threshold
	pricing.LongInputCost = longInput / 1_000_000
	pricing.LongOutputCost = longOutput / 1_000_000
	pricing.LongCacheReadCost = longCacheRead / 1_000_000
	pricing.LongCacheWriteCost = longCacheWrite / 1_000_000
	return pricing
}

func advertisedModelCost(model string, now time.Time) *piModelCost {
	pricing, ok := publishedModelPricing(now)[canonicalPricingModel(model)]
	if !ok {
		return &piModelCost{}
	}
	return &piModelCost{
		Input:      pricing.InputCostPerToken * 1_000_000,
		Output:     pricing.OutputCostPerToken * 1_000_000,
		CacheRead:  pricing.CacheReadCost * 1_000_000,
		CacheWrite: pricing.CacheWriteCost * 1_000_000,
	}
}
