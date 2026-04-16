package main

import (
	"encoding/json"
	"strings"
)

type piModelsConfig struct {
	Providers map[string]piProviderConfig `json:"providers"`
}

type piProviderConfig struct {
	BaseURL string          `json:"baseUrl,omitempty"`
	APIKey  string          `json:"apiKey,omitempty"`
	API     string          `json:"api,omitempty"`
	Models  []piModelConfig `json:"models,omitempty"`
}

type piModelConfig struct {
	ID            string       `json:"id"`
	Name          string       `json:"name,omitempty"`
	Reasoning     *bool        `json:"reasoning,omitempty"`
	Input         []string     `json:"input,omitempty"`
	ContextWindow int          `json:"contextWindow,omitempty"`
	MaxTokens     int          `json:"maxTokens,omitempty"`
	Cost          *piModelCost `json:"cost,omitempty"`
}

type piModelCost struct {
	Input      float64 `json:"input"`
	Output     float64 `json:"output"`
	CacheRead  float64 `json:"cacheRead"`
	CacheWrite float64 `json:"cacheWrite"`
}

func generatePiModelsJSON(publicURL, codexAPIKey, anthropicAPIKey string) ([]byte, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(publicURL), "/")
	cfg := piModelsConfig{
		Providers: map[string]piProviderConfig{
			"codex": {
				BaseURL: baseURL + "/backend-api",
				APIKey:  codexAPIKey,
				API:     "openai-codex-responses",
				Models: []piModelConfig{
					piTextModel("gpt-5.4", "GPT-5.4", true, 1050000, 128000),
					piTextModel("gpt-5.3-codex", "GPT-5.3 Codex", true, 400000, 128000),
					piTextModel("gpt-5.3-codex-spark", "GPT-5.3 Codex Spark", true, 128000, 128000),
					piTextModel("gpt-5.2-codex", "GPT-5.2 Codex", true, 400000, 128000),
					piTextModel("gpt-5.1-codex-max", "GPT-5.1 Codex Max", true, 400000, 128000),
					piTextModel("gpt-5.2", "GPT-5.2", true, 400000, 128000),
					piTextModel("gpt-5.1-codex-mini", "GPT-5.1 Codex Mini", true, 400000, 128000),
				},
			},
			"claude": {
				BaseURL: baseURL,
				APIKey:  anthropicAPIKey,
				API:     "anthropic-messages",
				Models: []piModelConfig{
					piClaudeAlias("claude-haiku-4-5", "Claude Haiku 4.5", 200000, 64000, 1, 5, 0.1, 1.25),
					piClaudeAlias("claude-sonnet-4-6", "Claude Sonnet 4.6", 1000000, 64000, 3, 15, 0.3, 3.75),
					piClaudeAlias("claude-sonnet-4-6 [1m]", "Claude Sonnet 4.6 [1m]", 1000000, 64000, 3, 15, 0.3, 3.75),
					piClaudeAlias("claude-opus-4-7", "Claude Opus 4.7", 1000000, 128000, 5, 25, 0.5, 6.25),
					piClaudeAlias("claude-opus-4-7 [1m]", "Claude Opus 4.7 [1m]", 1000000, 128000, 5, 25, 0.5, 6.25),
					piClaudeAlias("claude-opus-4-6", "Claude Opus 4.6", 1000000, 128000, 5, 25, 0.5, 6.25),
					piClaudeAlias("claude-opus-4-6 [1m]", "Claude Opus 4.6 [1m]", 1000000, 128000, 5, 25, 0.5, 6.25),
				},
			},
			"kimi": {
				BaseURL: baseURL,
				APIKey:  anthropicAPIKey,
				API:     "anthropic-messages",
				Models: []piModelConfig{
					{
						ID:            "k2p5",
						Name:          "Kimi K2.5",
						Reasoning:     boolPtr(true),
						Input:         []string{"text", "image"},
						ContextWindow: 262144,
						MaxTokens:     32768,
						Cost:          &piModelCost{},
					},
					{
						ID:            "kimi-k2-thinking",
						Name:          "Kimi K2 Thinking",
						Reasoning:     boolPtr(true),
						Input:         []string{"text", "image"},
						ContextWindow: 262144,
						MaxTokens:     32768,
						Cost:          &piModelCost{},
					},
				},
			},
			"minimax": {
				BaseURL: baseURL,
				APIKey:  anthropicAPIKey,
				API:     "anthropic-messages",
				Models: []piModelConfig{
					{
						ID:            "MiniMax-M2.7",
						Name:          "MiniMax M2.7",
						Reasoning:     boolPtr(true),
						Input:         []string{"text", "image"},
						ContextWindow: 204800,
						MaxTokens:     131072,
						Cost: &piModelCost{
							Input:      0.3,
							Output:     1.2,
							CacheRead:  0.06,
							CacheWrite: 0.375,
						},
					},
					{
						ID:            "MiniMax-M2.7-highspeed",
						Name:          "MiniMax M2.7 Highspeed",
						Reasoning:     boolPtr(true),
						Input:         []string{"text", "image"},
						ContextWindow: 204800,
						MaxTokens:     131072,
						Cost: &piModelCost{
							Input:      0.6,
							Output:     2.4,
							CacheRead:  0.06,
							CacheWrite: 0.375,
						},
					},
				},
			},
			"zai": {
				BaseURL: baseURL,
				APIKey:  anthropicAPIKey,
				API:     "anthropic-messages",
				Models: []piModelConfig{
					{
						ID:            "glm-5.1",
						Name:          "GLM 5.1",
						Reasoning:     boolPtr(true),
						Input:         []string{"text", "image"},
						ContextWindow: 128000,
						MaxTokens:     65536,
						Cost:          &piModelCost{},
					},
				},
			},
		},
	}

	return json.MarshalIndent(cfg, "", "  ")
}

func piTextModel(id, name string, reasoning bool, contextWindow, maxTokens int) piModelConfig {
	return piModelConfig{
		ID:            id,
		Name:          name,
		Reasoning:     boolPtr(reasoning),
		Input:         []string{"text", "image"},
		ContextWindow: contextWindow,
		MaxTokens:     maxTokens,
		Cost:          &piModelCost{},
	}
}

func piClaudeAlias(id, name string, contextWindow, maxTokens int, inputCost, outputCost, cacheReadCost, cacheWriteCost float64) piModelConfig {
	return piModelConfig{
		ID:            id,
		Name:          name,
		Reasoning:     boolPtr(true),
		Input:         []string{"text", "image"},
		ContextWindow: contextWindow,
		MaxTokens:     maxTokens,
		Cost: &piModelCost{
			Input:      inputCost,
			Output:     outputCost,
			CacheRead:  cacheReadCost,
			CacheWrite: cacheWriteCost,
		},
	}
}

func boolPtr(v bool) *bool {
	return &v
}
