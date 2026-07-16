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
	Input         []string
	Cost          *piModelCost
}

var poolModels = []poolModel{
	{AccountType: AccountTypeCodex, ID: "gpt-5.6-sol", DisplayName: "GPT-5.6-Sol", Description: "Latest frontier agentic coding model.", ContextWindow: 372000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}, Aliases: []string{"gpt-5.6"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.6-terra", DisplayName: "GPT-5.6-Terra", Description: "Balanced agentic coding model for everyday work.", ContextWindow: 372000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.6-luna", DisplayName: "GPT-5.6-Luna", Description: "Fast and affordable agentic coding model.", ContextWindow: 372000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.5", DisplayName: "GPT-5.5", Description: "Frontier model for complex coding, research, and real-world work.", ContextWindow: 272000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.4", DisplayName: "GPT-5.4", Description: "Strong model for everyday coding.", ContextWindow: 272000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.4-mini", DisplayName: "GPT-5.4-Mini", Description: "Small, fast, and cost-efficient model for simpler coding tasks.", ContextWindow: 272000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.3-codex-spark", DisplayName: "GPT-5.3-Codex-Spark", Description: "Ultra-fast coding model.", ContextWindow: 128000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},

	{AccountType: AccountTypeClaude, ID: "claude-sonnet-5", DisplayName: "Claude Sonnet 5", ContextWindow: 1000000, MaxTokens: 64000, Reasoning: true, Input: []string{"text", "image"}, Aliases: []string{"sonnet"}, Cost: &piModelCost{Input: 2, Output: 10, CacheRead: 0.2, CacheWrite: 2.5}},
	{AccountType: AccountTypeClaude, ID: "claude-fable-5", DisplayName: "Claude Fable 5", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}, Aliases: []string{"fable"}, Cost: &piModelCost{Input: 10, Output: 50, CacheRead: 1, CacheWrite: 12.5}},
	{AccountType: AccountTypeClaude, ID: "claude-opus-4-8", DisplayName: "Claude Opus 4.8", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}, Aliases: []string{"opus"}, Cost: &piModelCost{Input: 5, Output: 25, CacheRead: 0.5, CacheWrite: 6.25}},
	{AccountType: AccountTypeClaude, ID: "claude-opus-4-7", DisplayName: "Claude Opus 4.7", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}, Cost: &piModelCost{Input: 5, Output: 25, CacheRead: 0.5, CacheWrite: 6.25}},
	{AccountType: AccountTypeClaude, ID: "claude-sonnet-4-6", DisplayName: "Claude Sonnet 4.6", ContextWindow: 1000000, MaxTokens: 64000, Reasoning: true, Input: []string{"text", "image"}, Cost: &piModelCost{Input: 3, Output: 15, CacheRead: 0.3, CacheWrite: 3.75}},
	{AccountType: AccountTypeClaude, ID: "claude-opus-4-6", DisplayName: "Claude Opus 4.6", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}, Cost: &piModelCost{Input: 5, Output: 25, CacheRead: 0.5, CacheWrite: 6.25}},
	{AccountType: AccountTypeClaude, ID: "claude-opus-4-5-20251101", DisplayName: "Claude Opus 4.5", ContextWindow: 200000, MaxTokens: 64000, Reasoning: true, Input: []string{"text", "image"}, Cost: &piModelCost{Input: 5, Output: 25, CacheRead: 0.5, CacheWrite: 6.25}},
	{AccountType: AccountTypeClaude, ID: "claude-haiku-4-5-20251001", DisplayName: "Claude Haiku 4.5", ContextWindow: 200000, MaxTokens: 64000, Reasoning: true, Input: []string{"text", "image"}, Aliases: []string{"haiku", "claude-haiku-4-5"}, Cost: &piModelCost{Input: 1, Output: 5, CacheRead: 0.1, CacheWrite: 1.25}},
	{AccountType: AccountTypeClaude, ID: "claude-sonnet-4-5-20250929", DisplayName: "Claude Sonnet 4.5", ContextWindow: 200000, MaxTokens: 64000, Reasoning: true, Input: []string{"text", "image"}, Cost: &piModelCost{Input: 3, Output: 15, CacheRead: 0.3, CacheWrite: 3.75}},
	{AccountType: AccountTypeClaude, ID: "claude-opus-4-1-20250805", DisplayName: "Claude Opus 4.1", ContextWindow: 200000, MaxTokens: 32000, Reasoning: true, Input: []string{"text", "image"}, Cost: &piModelCost{Input: 15, Output: 75, CacheRead: 1.5, CacheWrite: 18.75}},

	{AccountType: AccountTypeKimi, ID: "kimi-for-coding", DisplayName: "kimi-for-coding", ContextWindow: 262144, MaxTokens: 32768, Reasoning: true, Input: []string{"text", "image"}, Aliases: []string{"kimi", "k2p5", "kimi-k2-thinking"}},
	{AccountType: AccountTypeKimi, ID: "kimi-for-coding-highspeed", DisplayName: "kimi-for-coding-highspeed", ContextWindow: 262144, MaxTokens: 32768, Reasoning: true, Input: []string{"text", "image"}},

	{AccountType: AccountTypeMinimax, ID: "MiniMax-M3", DisplayName: "MiniMax-M3", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text", "image"}, Aliases: []string{"minimax", "minimax-m3"}},
	{AccountType: AccountTypeMinimax, ID: "MiniMax-M2.7", DisplayName: "MiniMax-M2.7", ContextWindow: 204800, MaxTokens: 131072, Reasoning: true, Input: []string{"text", "image"}, Cost: &piModelCost{Input: 0.3, Output: 1.2, CacheRead: 0.06, CacheWrite: 0.375}},
	{AccountType: AccountTypeMinimax, ID: "MiniMax-M2.7-highspeed", DisplayName: "MiniMax-M2.7-Highspeed", ContextWindow: 204800, MaxTokens: 131072, Reasoning: true, Input: []string{"text", "image"}, Cost: &piModelCost{Input: 0.6, Output: 2.4, CacheRead: 0.06, CacheWrite: 0.375}},

	{AccountType: AccountTypeZAI, ID: "glm-5.2", DisplayName: "GLM-5.2", ContextWindow: 1000000, MaxTokens: 65536, Reasoning: true, Input: []string{"text"}},

	{AccountType: AccountTypeXiaomi, ID: "mimo-v2.5-pro", DisplayName: "MiMo-V2.5-Pro", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}, Aliases: []string{"mimo-v2.5-pro[1m]"}},
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
