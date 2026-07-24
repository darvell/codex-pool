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
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	Reasoning        *bool             `json:"reasoning,omitempty"`
	ThinkingLevelMap map[string]string `json:"thinkingLevelMap,omitempty"`
	Input            []string          `json:"input,omitempty"`
	ContextWindow    int               `json:"contextWindow,omitempty"`
	MaxTokens        int               `json:"maxTokens,omitempty"`
	Cost             *piModelCost      `json:"cost,omitempty"`
	Compat           *piModelCompat    `json:"compat,omitempty"`
}

type piModelCompat struct {
	ForceAdaptiveThinking bool `json:"forceAdaptiveThinking,omitempty"`
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
	APIKey        string `json:"apiKey,omitempty"`
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
				Models:  piModelsForProvider(AccountTypeCodex),
			},
			"claude": {
				BaseURL: baseURL,
				APIKey:  anthropicAPIKey,
				API:     "anthropic-messages",
				Models:  piModelsForProvider(AccountTypeClaude),
			},
			"antigravity": {
				BaseURL: baseURL,
				APIKey:  codexAPIKey,
				API:     "openai-completions",
				Models:  antigravityPiModels(),
			},
			"kimi": {
				BaseURL: baseURL,
				APIKey:  anthropicAPIKey,
				API:     "anthropic-messages",
				Models:  piModelsForProvider(AccountTypeKimi),
			},
			"minimax": {
				BaseURL: baseURL,
				APIKey:  anthropicAPIKey,
				API:     "anthropic-messages",
				Models:  piModelsForProvider(AccountTypeMinimax),
			},
			"zai": {
				BaseURL: baseURL,
				APIKey:  anthropicAPIKey,
				API:     "anthropic-messages",
				Models:  piModelsForProvider(AccountTypeZAI),
			},
			"xiaomi": {
				BaseURL: baseURL,
				APIKey:  anthropicAPIKey,
				API:     "anthropic-messages",
				Models:  piModelsForProvider(AccountTypeXiaomi),
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
		Model:            "gpt-5.6-sol",
		OpenAIBaseURL:    baseURL,
		OpenAIAPIKey:     apiKey,
		AnthropicBaseURL: baseURL,
		AnthropicAPIKey:  apiKey,
		CodexPool: cuteCodePoolConfig{
			URL: baseURL,
		},
	}
	for _, accountType := range []AccountType{AccountTypeCodex, AccountTypeClaude, AccountTypeKimi, AccountTypeMinimax, AccountTypeZAI, AccountTypeXiaomi} {
		settings.CustomModels = append(settings.CustomModels, cuteModelsForProvider(baseURL, apiKey, accountType)...)
	}
	settings.CustomModels = append(settings.CustomModels, grokCuteModels(baseURL, apiKey)...)
	settings.CustomModels = append(settings.CustomModels, antigravityCuteModels(baseURL, apiKey)...)
	return json.MarshalIndent(settings, "", "  ")
}

func antigravityPiModels() []piModelConfig {
	models := antigravityModels.Models(nil)
	result := make([]piModelConfig, 0, len(models))
	for _, model := range models {
		input := []string{"text"}
		if model.SupportsImages {
			input = append(input, "image")
		}
		result = append(result, piModelConfig{ID: "antigravity/" + model.ID, Name: model.DisplayName, Reasoning: boolPtr(model.SupportsThinking), Input: input, ContextWindow: model.MaxTokens, MaxTokens: model.MaxOutputTokens, Cost: &piModelCost{}})
	}
	return result
}

func antigravityCuteModels(baseURL, apiKey string) []cuteCodeModelConfig {
	models := antigravityModels.Models(nil)
	result := make([]cuteCodeModelConfig, 0, len(models))
	for _, model := range models {
		result = append(result, cuteOpenAIModel(baseURL, apiKey, "antigravity/"+model.ID, model.DisplayName, model.MaxTokens, "Google Antigravity"))
	}
	return result
}

func grokPiModels() []piModelConfig {
	models := make([]piModelConfig, 0, len(grokModelCatalog))
	for _, model := range grokModelCatalog {
		models = append(models, piTextModel(model.ID, model.Name, model.Reasoning, model.ContextWindow, model.MaxTokens))
	}
	return models
}

func grokCuteModels(baseURL, apiKey string) []cuteCodeModelConfig {
	models := make([]cuteCodeModelConfig, 0, len(grokModelCatalog))
	for _, model := range grokModelCatalog {
		models = append(models, cuteOpenAIModel(baseURL, apiKey, model.ID, model.Name, model.ContextWindow, ""))
	}
	return models
}

func cuteModelsForProvider(baseURL, apiKey string, accountType AccountType) []cuteCodeModelConfig {
	models := modelsForProvider(accountType)
	result := make([]cuteCodeModelConfig, 0, len(models))
	for _, model := range models {
		protocol := "anthropic"
		if accountType == AccountTypeCodex {
			protocol = "openai"
		}
		result = append(result, cuteCodeModelConfig{
			ID:            model.ID,
			Name:          model.DisplayName,
			Protocol:      protocol,
			BaseURL:       baseURL,
			APIKey:        apiKey,
			ContextWindow: model.ContextWindow,
			Description:   model.Description,
		})
	}
	return result
}

func cuteOpenAIModel(baseURL, apiKey, id, name string, contextWindow int, description string) cuteCodeModelConfig {
	return cuteCodeModelConfig{
		ID:            id,
		Name:          name,
		Protocol:      "openai",
		BaseURL:       baseURL,
		APIKey:        apiKey,
		ContextWindow: contextWindow,
		Description:   description,
	}
}

func cuteAnthropicModel(baseURL, apiKey, id, name string, contextWindow int, description string) cuteCodeModelConfig {
	return cuteCodeModelConfig{
		ID:            id,
		Name:          name,
		Protocol:      "anthropic",
		BaseURL:       baseURL,
		APIKey:        apiKey,
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

func piCodexModel(id, name string, contextWindow, maxTokens int) piModelConfig {
	model := piTextModel(id, name, true, contextWindow, maxTokens)
	if id == "gpt-5.6" || strings.HasPrefix(id, "gpt-5.6-") {
		model.ThinkingLevelMap = map[string]string{"xhigh": "xhigh", "max": "max"}
	}
	return model
}

func piClaudeAlias(id, name string, contextWindow, maxTokens int, inputCost, outputCost, cacheReadCost, cacheWriteCost float64) piModelConfig {
	model := piModelConfig{
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
	if ccModelSupportsEffort(id) {
		model.ThinkingLevelMap = map[string]string{"max": "max"}
		model.Compat = &piModelCompat{ForceAdaptiveThinking: true}
		canonical := ccCanonicalClaudeModel(id)
		if strings.Contains(canonical, "opus-5") || strings.Contains(canonical, "opus-4-7") || strings.Contains(canonical, "fable-5") || strings.Contains(canonical, "sonnet-5") {
			model.ThinkingLevelMap["xhigh"] = "xhigh"
		}
	}
	return model
}

func boolPtr(v bool) *bool {
	return &v
}

func piModelsForProvider(accountType AccountType) []piModelConfig {
	models := modelsForProvider(accountType)
	result := make([]piModelConfig, 0, len(models))
	for _, model := range models {
		config := piModelConfig{
			ID:            model.ID,
			Name:          model.DisplayName,
			Reasoning:     boolPtr(model.Reasoning),
			Input:         append([]string(nil), model.Input...),
			ContextWindow: model.ContextWindow,
			MaxTokens:     model.MaxTokens,
			Cost:          cloneModelCost(model.Cost),
		}
		if accountType == AccountTypeCodex && strings.HasPrefix(model.ID, "gpt-5.6-") {
			config.ThinkingLevelMap = map[string]string{"xhigh": "xhigh", "max": "max"}
		}
		if accountType == AccountTypeClaude && ccModelSupportsEffort(model.ID) {
			config.ThinkingLevelMap = map[string]string{"max": "max"}
			config.Compat = &piModelCompat{ForceAdaptiveThinking: true}
			canonical := ccCanonicalClaudeModel(model.ID)
			if strings.Contains(canonical, "opus-5") || strings.Contains(canonical, "opus-4-7") || strings.Contains(canonical, "fable-5") || strings.Contains(canonical, "sonnet-5") {
				config.ThinkingLevelMap["xhigh"] = "xhigh"
			}
		}
		result = append(result, config)
	}
	return result
}

func cloneModelCost(cost *piModelCost) *piModelCost {
	if cost == nil {
		return &piModelCost{}
	}
	cloned := *cost
	return &cloned
}
