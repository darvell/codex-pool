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

type cuteCodeSettings struct {
	Model            string                `json:"model,omitempty"`
	OpenAIBaseURL    string                `json:"openaiBaseUrl"`
	OpenAIAPIKey     string                `json:"openaiApiKey"`
	AnthropicBaseURL string                `json:"anthropicBaseUrl"`
	AnthropicAPIKey  string                `json:"anthropicApiKey"`
	CustomModels     []cuteCodeModelConfig `json:"customModels"`
	CodexPool        cuteCodePoolConfig    `json:"codexPool"`
}

type cuteCodePoolConfig struct {
	URL string `json:"url"`
}

type cuteCodeModelConfig struct {
	ID            string `json:"id"`
	Name          string `json:"name,omitempty"`
	Protocol      string `json:"protocol"`
	BaseURL       string `json:"baseUrl,omitempty"`
	ContextWindow int    `json:"contextWindow,omitempty"`
	Description   string `json:"description,omitempty"`
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
					piTextModel("gpt-5.5", "GPT-5.5", true, 272000, 128000),
					piTextModel("gpt-5.4", "GPT-5.4", true, 1000000, 128000),
					piTextModel("gpt-5.3-codex", "GPT-5.3 Codex", true, 272000, 128000),
					piTextModel("gpt-5.3-codex-spark", "GPT-5.3 Codex Spark", true, 128000, 128000),
					piTextModel("gpt-5.2-codex", "GPT-5.2 Codex", true, 272000, 128000),
					piTextModel("gpt-5.1-codex-max", "GPT-5.1 Codex Max", true, 272000, 128000),
					piTextModel("gpt-5.2", "GPT-5.2", true, 272000, 128000),
					piTextModel("gpt-5.1-codex-mini", "GPT-5.1 Codex Mini", true, 272000, 128000),
				},
			},
			"claude": {
				BaseURL: baseURL,
				APIKey:  anthropicAPIKey,
				API:     "anthropic-messages",
				Models: []piModelConfig{
					piClaudeAlias("claude-haiku-4-5", "Claude Haiku 4.5", 200000, 64000, 1, 5, 0.1, 1.25),
					piClaudeAlias("claude-sonnet-5", "Claude Sonnet 5", 1000000, 64000, 3, 15, 0.3, 3.75),
					piClaudeAlias("claude-sonnet-5 [1m]", "Claude Sonnet 5 [1m]", 1000000, 64000, 3, 15, 0.3, 3.75),
					piClaudeAlias("claude-sonnet-4-6", "Claude Sonnet 4.6", 1000000, 64000, 3, 15, 0.3, 3.75),
					piClaudeAlias("claude-sonnet-4-6 [1m]", "Claude Sonnet 4.6 [1m]", 1000000, 64000, 3, 15, 0.3, 3.75),
					piClaudeAlias("claude-fable-5", "Claude Fable 5", 1000000, 128000, 5, 25, 0.5, 6.25),
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
						ID:            "MiniMax-M3",
						Name:          "MiniMax M3",
						Reasoning:     boolPtr(true),
						Input:         []string{"text", "image"},
						ContextWindow: 1000000,
						MaxTokens:     131072,
						Cost:          &piModelCost{},
					},
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
					{
						ID:            "glm-5.2",
						Name:          "GLM 5.2",
						Reasoning:     boolPtr(true),
						Input:         []string{"text", "image"},
						ContextWindow: 1000000,
						MaxTokens:     65536,
						Cost:          &piModelCost{},
					},
				},
			},
			"grok": {
				BaseURL: baseURL,
				APIKey:  codexAPIKey,
				API:     "openai-responses",
				Models:  grokPiModels(),
			},
		},
	}

	return json.MarshalIndent(cfg, "", "  ")
}

func generateCuteCodeSettingsJSON(publicURL, apiKey string) ([]byte, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(publicURL), "/")
	settings := cuteCodeSettings{
		Model:            "gpt-5.5",
		OpenAIBaseURL:    baseURL,
		OpenAIAPIKey:     apiKey,
		AnthropicBaseURL: baseURL,
		AnthropicAPIKey:  apiKey,
		CodexPool: cuteCodePoolConfig{
			URL: baseURL,
		},
		CustomModels: []cuteCodeModelConfig{
			cuteOpenAIModel(baseURL, "gpt-5.5", "GPT-5.5", 272000, "Default GPT/Codex pool model"),
			cuteOpenAIModel(baseURL, "gpt-5.4", "GPT-5.4", 1000000, "Long-context GPT model for remote compaction and large tasks"),
			cuteOpenAIModel(baseURL, "gpt-5.3-codex", "GPT-5.3 Codex", 272000, "Codex reasoning model"),
			cuteOpenAIModel(baseURL, "gpt-5.3-codex-spark", "GPT-5.3 Codex Spark", 128000, "Fast Codex model"),
			cuteOpenAIModel(baseURL, "gpt-5.2-codex", "GPT-5.2 Codex", 272000, "Codex reasoning model"),
			cuteOpenAIModel(baseURL, "gpt-5.1-codex-max", "GPT-5.1 Codex Max", 272000, "High-capability Codex model"),
			cuteOpenAIModel(baseURL, "gpt-5.2", "GPT-5.2", 272000, "GPT reasoning model"),
			cuteOpenAIModel(baseURL, "gpt-5.1-codex-mini", "GPT-5.1 Codex Mini", 272000, "Small Codex model"),
			cuteAnthropicModel(baseURL, "claude-haiku-4-5", "Claude Haiku 4.5", 200000, "Fast Claude model through the pool"),
			cuteAnthropicModel(baseURL, "claude-sonnet-5", "Claude Sonnet 5", 1000000, "Claude Sonnet through the pool"),
			cuteAnthropicModel(baseURL, "claude-sonnet-5 [1m]", "Claude Sonnet 5 [1m]", 1000000, "Claude Sonnet with 1m context routing"),
			cuteAnthropicModel(baseURL, "claude-sonnet-4-6", "Claude Sonnet 4.6", 1000000, "Claude Sonnet through the pool"),
			cuteAnthropicModel(baseURL, "claude-sonnet-4-6 [1m]", "Claude Sonnet 4.6 [1m]", 1000000, "Claude Sonnet with 1m context routing"),
			cuteAnthropicModel(baseURL, "claude-fable-5", "Claude Fable 5", 1000000, "Claude Fable through the pool"),
			cuteAnthropicModel(baseURL, "claude-opus-4-7", "Claude Opus 4.7", 1000000, "Claude Opus through the pool"),
			cuteAnthropicModel(baseURL, "claude-opus-4-7 [1m]", "Claude Opus 4.7 [1m]", 1000000, "Claude Opus with 1m context routing"),
			cuteAnthropicModel(baseURL, "claude-opus-4-6", "Claude Opus 4.6", 1000000, "Claude Opus through the pool"),
			cuteAnthropicModel(baseURL, "claude-opus-4-6 [1m]", "Claude Opus 4.6 [1m]", 1000000, "Claude Opus with 1m context routing"),
			cuteAnthropicModel(baseURL, "k2p5", "Kimi K2.5", 262144, "Kimi model routed through Anthropic-compatible pool API"),
			cuteAnthropicModel(baseURL, "kimi-k2-thinking", "Kimi K2 Thinking", 262144, "Kimi thinking model routed through the pool"),
			cuteAnthropicModel(baseURL, "MiniMax-M3", "MiniMax M3", 1000000, "1M-context MiniMax model routed through the pool"),
			cuteAnthropicModel(baseURL, "MiniMax-M2.7", "MiniMax M2.7", 204800, "MiniMax model routed through the pool"),
			cuteAnthropicModel(baseURL, "MiniMax-M2.7-highspeed", "MiniMax M2.7 Highspeed", 204800, "High-speed MiniMax route through the pool"),
			cuteAnthropicModel(baseURL, "glm-5.1", "GLM 5.1", 128000, "GLM model routed through the pool"),
			cuteAnthropicModel(baseURL, "glm-5.2", "GLM 5.2", 1000000, "1M-context GLM model routed through the pool"),
		},
	}
	settings.CustomModels = append(settings.CustomModels, grokCuteModels(baseURL)...)
	return json.MarshalIndent(settings, "", "  ")
}

func grokPiModels() []piModelConfig {
	models := make([]piModelConfig, 0, len(grokModelCatalog))
	for _, model := range grokModelCatalog {
		models = append(models, piTextModel(model.ID, model.Name, model.Reasoning, model.ContextWindow, model.MaxTokens))
	}
	return models
}

func grokCuteModels(baseURL string) []cuteCodeModelConfig {
	models := make([]cuteCodeModelConfig, 0, len(grokModelCatalog))
	for _, model := range grokModelCatalog {
		models = append(models, cuteOpenAIModel(baseURL, model.ID, model.Name, model.ContextWindow, "Grok model routed through the pool"))
	}
	return models
}

func cuteOpenAIModel(baseURL, id, name string, contextWindow int, description string) cuteCodeModelConfig {
	return cuteCodeModelConfig{
		ID:            id,
		Name:          name,
		Protocol:      "openai",
		BaseURL:       baseURL,
		ContextWindow: contextWindow,
		Description:   description,
	}
}

func cuteAnthropicModel(baseURL, id, name string, contextWindow int, description string) cuteCodeModelConfig {
	return cuteCodeModelConfig{
		ID:            id,
		Name:          name,
		Protocol:      "anthropic",
		BaseURL:       baseURL,
		ContextWindow: contextWindow,
		Description:   description,
	}
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
