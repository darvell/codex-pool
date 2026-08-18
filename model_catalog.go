package main

import "strings"

type poolModel struct {
	AccountType   AccountType
	ID            string
	DisplayName   string
	Description   string
	Aliases       []string
	ContextWindow int
	MaxTokens     int
	Reasoning     bool
	WebSearch     bool
	Input         []string
}

var poolModels = []poolModel{
	{AccountType: AccountTypeCodex, ID: "gpt-5.6-sol", DisplayName: "GPT-5.6-Sol", Description: "Latest frontier agentic coding model.", ContextWindow: 372000, MaxTokens: 128000, Reasoning: true, WebSearch: true, Input: []string{"text", "image"}, Aliases: []string{"gpt-5.6"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.6-sol[1m]", DisplayName: "GPT-5.6-Sol (1M)", Description: "Latest frontier agentic coding model with a 1M context window.", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, WebSearch: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.6-terra", DisplayName: "GPT-5.6-Terra", Description: "Balanced agentic coding model for everyday work.", ContextWindow: 372000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.6-terra[1m]", DisplayName: "GPT-5.6-Terra (1M)", Description: "Balanced agentic coding model with a 1M context window.", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.6-luna", DisplayName: "GPT-5.6-Luna", Description: "Fast and affordable agentic coding model.", ContextWindow: 372000, MaxTokens: 128000, Reasoning: true, WebSearch: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.6-luna[1m]", DisplayName: "GPT-5.6-Luna (1M)", Description: "Fast and affordable agentic coding model with a 1M context window.", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, WebSearch: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.5", DisplayName: "GPT-5.5", Description: "Frontier model for complex coding, research, and real-world work.", ContextWindow: 272000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.4", DisplayName: "GPT-5.4", Description: "Strong model for everyday coding.", ContextWindow: 272000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.4-mini", DisplayName: "GPT-5.4-Mini", Description: "Small, fast, and cost-efficient model for simpler coding tasks.", ContextWindow: 272000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.3-codex-spark", DisplayName: "GPT-5.3-Codex-Spark", Description: "Ultra-fast coding model.", ContextWindow: 128000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},

	{AccountType: AccountTypeClaude, ID: "claude-sonnet-5", DisplayName: "Claude Sonnet 5", ContextWindow: 1000000, MaxTokens: 64000, Reasoning: true, WebSearch: true, Input: []string{"text", "image"}, Aliases: []string{"sonnet"}},
	{AccountType: AccountTypeClaude, ID: "claude-fable-5", DisplayName: "Claude Fable 5", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}, Aliases: []string{"fable"}},
	{AccountType: AccountTypeClaude, ID: "claude-opus-5", DisplayName: "Claude Opus 5", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}, Aliases: []string{"opus"}},
	{AccountType: AccountTypeClaude, ID: "claude-opus-4-8", DisplayName: "Claude Opus 4.8", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeClaude, ID: "claude-opus-4-7", DisplayName: "Claude Opus 4.7", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeClaude, ID: "claude-sonnet-4-6", DisplayName: "Claude Sonnet 4.6", ContextWindow: 1000000, MaxTokens: 64000, Reasoning: true, WebSearch: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeClaude, ID: "claude-opus-4-6", DisplayName: "Claude Opus 4.6", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeClaude, ID: "claude-opus-4-5-20251101", DisplayName: "Claude Opus 4.5", ContextWindow: 200000, MaxTokens: 64000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeClaude, ID: "claude-haiku-4-5-20251001", DisplayName: "Claude Haiku 4.5", ContextWindow: 200000, MaxTokens: 64000, Reasoning: true, Input: []string{"text", "image"}, Aliases: []string{"haiku", "claude-haiku-4-5"}},
	{AccountType: AccountTypeClaude, ID: "claude-sonnet-4-5-20250929", DisplayName: "Claude Sonnet 4.5", ContextWindow: 200000, MaxTokens: 64000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeClaude, ID: "claude-opus-4-1-20250805", DisplayName: "Claude Opus 4.1", ContextWindow: 200000, MaxTokens: 32000, Reasoning: true, Input: []string{"text", "image"}},

	{AccountType: AccountTypeKimi, ID: "k3", DisplayName: "Kimi K3", Description: "Kimi's flagship model for coding, games, 3D, and knowledge tasks.", ContextWindow: 1048576, MaxTokens: 32768, Reasoning: true, WebSearch: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeKimi, ID: "kimi-for-coding", DisplayName: "kimi-for-coding", ContextWindow: 262144, MaxTokens: 32768, Reasoning: true, Input: []string{"text", "image"}, Aliases: []string{"kimi", "k2p5", "kimi-k2-thinking"}},
	{AccountType: AccountTypeKimi, ID: "kimi-for-coding-highspeed", DisplayName: "kimi-for-coding-highspeed", ContextWindow: 262144, MaxTokens: 32768, Reasoning: true, Input: []string{"text", "image"}},

	{AccountType: AccountTypeMinimax, ID: "MiniMax-M3", DisplayName: "MiniMax-M3", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text", "image"}, Aliases: []string{"minimax", "minimax-m3"}},
	{AccountType: AccountTypeMinimax, ID: "MiniMax-M2.7", DisplayName: "MiniMax-M2.7", ContextWindow: 204800, MaxTokens: 131072, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeMinimax, ID: "MiniMax-M2.7-highspeed", DisplayName: "MiniMax-M2.7-Highspeed", ContextWindow: 204800, MaxTokens: 131072, Reasoning: true, Input: []string{"text", "image"}},

	// GLM-5.3 replaces GLM-5.2 for Coding Plan users. Keep the previous ID as
	// an alias so existing installed configurations migrate at the proxy.
	{AccountType: AccountTypeZAI, ID: "glm-5.3", DisplayName: "GLM-5.3", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}, Aliases: []string{"glm-5.2"}},

	{AccountType: AccountTypeXiaomi, ID: "mimo-v2.5-pro", DisplayName: "MiMo-V2.5-Pro", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}, Aliases: []string{"mimo-v2.5-pro[1m]"}},

	// Upstream advertises max_model_len 524288 and enforces it: a 600k-token
	// prompt is rejected with "maximum context length is 524288 tokens".
	{AccountType: AccountTypeAdverserial, ID: "lordx64/cyberkimi", DisplayName: "CyberKimi", Description: "Security-focused Kimi variant via adverserial.ai.", ContextWindow: 524288, MaxTokens: 32768, Reasoning: true, Input: []string{"text"}, Aliases: []string{"cyberkimi"}},
}

func modelsForProvider(accountType AccountType) []poolModel {
	var models []poolModel
	for _, model := range poolModels {
		if model.AccountType == accountType {
			models = append(models, model)
		}
	}
	return models
}

func modelForProvider(accountType AccountType, name string) (poolModel, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, model := range poolModels {
		if model.AccountType != accountType {
			continue
		}
		if strings.EqualFold(model.ID, name) {
			return model, true
		}
		for _, alias := range model.Aliases {
			if strings.EqualFold(alias, name) {
				return model, true
			}
		}
	}
	return poolModel{}, false
}
