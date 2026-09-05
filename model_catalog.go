package main

import "strings"

const defaultCodexModel = "gpt-6-astra"

type poolModel struct {
	RequiresDiscovery bool
	AccountType       AccountType
	ID                string
	DisplayName       string
	Description       string
	Aliases           []string
	ContextWindow     int
	MaxTokens         int
	Reasoning         bool
	WebSearch         bool
	Input             []string
}

// Codex discovery reports context_window 272000 and max_context_window 872000
// for the GPT-6 family (GET /backend-api/codex/models, 2026-09-04); the [1m]
// entries are client-facing 1M context profiles routed to the base model ID.
var poolModels = []poolModel{
	{AccountType: AccountTypeCodex, ID: defaultCodexModel, DisplayName: "GPT-6-Astra", Description: "Frontier model for complex, demanding work.", ContextWindow: 272000, MaxTokens: 128000, Reasoning: true, WebSearch: true, Input: []string{"text", "image"}, RequiresDiscovery: true},
	{AccountType: AccountTypeCodex, ID: "gpt-6-astra[1m]", DisplayName: "GPT-6-Astra (1M)", Description: "This is really fucking expensive.", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, WebSearch: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.6-sol", DisplayName: "GPT-5.6-Sol", Description: "Frontier agentic coding model.", ContextWindow: 372000, MaxTokens: 128000, Reasoning: true, WebSearch: true, Input: []string{"text", "image"}, Aliases: []string{"gpt-5.6"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.6-sol[1m]", DisplayName: "GPT-5.6-Sol (1M)", Description: "Frontier agentic coding model with a 1M context window.", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, WebSearch: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.6-terra", DisplayName: "GPT-5.6-Terra", Description: "Balanced agentic coding model for everyday work.", ContextWindow: 372000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.6-terra[1m]", DisplayName: "GPT-5.6-Terra (1M)", Description: "Balanced agentic coding model with a 1M context window.", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.6-luna", DisplayName: "GPT-5.6-Luna", Description: "Fast and affordable agentic coding model.", ContextWindow: 372000, MaxTokens: 128000, Reasoning: true, WebSearch: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.6-luna[1m]", DisplayName: "GPT-5.6-Luna (1M)", Description: "Fast and affordable agentic coding model with a 1M context window.", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, WebSearch: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.5", DisplayName: "GPT-5.5", Description: "Frontier model for complex coding, research, and real-world work.", ContextWindow: 272000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.4", DisplayName: "GPT-5.4", Description: "Strong model for everyday coding.", ContextWindow: 272000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.4-mini", DisplayName: "GPT-5.4-Mini", Description: "Small, fast, and cost-efficient model for simpler coding tasks.", ContextWindow: 272000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeCodex, ID: "gpt-5.3-codex-spark", DisplayName: "GPT-5.3-Codex-Spark", Description: "Ultra-fast coding model.", ContextWindow: 128000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},

	{AccountType: AccountTypeGemini, ID: "gemini-3.7-flash", DisplayName: "Gemini 3.7 Flash", ContextWindow: 1048576, MaxTokens: 65536, Reasoning: true, Input: []string{"text", "image", "video", "audio"}},
	{AccountType: AccountTypeGemini, ID: "gemini-3.5-flash", DisplayName: "Gemini 3.5 Flash", ContextWindow: 1048576, MaxTokens: 65536, Reasoning: true, Input: []string{"text", "image", "video", "audio"}},
	{AccountType: AccountTypeGemini, ID: "gemini-3.1-pro-preview", DisplayName: "Gemini 3.1 Pro", ContextWindow: 1048576, MaxTokens: 65536, Reasoning: true, Input: []string{"text", "image", "video", "audio"}},
	{AccountType: AccountTypeGemini, ID: "gemini-3.1-flash-lite", DisplayName: "Gemini 3.1 Flash Lite", ContextWindow: 1048576, MaxTokens: 65535, Reasoning: true, Input: []string{"text", "image", "video", "audio"}},

	{AccountType: AccountTypeClaude, ID: "claude-sonnet-5", DisplayName: "Claude Sonnet 5", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, WebSearch: true, Input: []string{"text", "image"}, Aliases: []string{"sonnet"}},
	{AccountType: AccountTypeClaude, ID: "claude-fable-5-1", DisplayName: "Claude Fable 5.1", Description: "Demanding reasoning and long-horizon agentic work.", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}, Aliases: []string{"fable"}},
	{AccountType: AccountTypeClaude, ID: "claude-fable-5", DisplayName: "Claude Fable 5", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeClaude, ID: "claude-opus-5", DisplayName: "Claude Opus 5", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}, Aliases: []string{"opus"}},
	{AccountType: AccountTypeClaude, ID: "claude-opus-4-8", DisplayName: "Claude Opus 4.8", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeClaude, ID: "claude-opus-4-7", DisplayName: "Claude Opus 4.7", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeClaude, ID: "claude-sonnet-4-6", DisplayName: "Claude Sonnet 4.6", ContextWindow: 1000000, MaxTokens: 64000, Reasoning: true, WebSearch: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeClaude, ID: "claude-opus-4-6", DisplayName: "Claude Opus 4.6", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeClaude, ID: "claude-opus-4-5-20251101", DisplayName: "Claude Opus 4.5", ContextWindow: 200000, MaxTokens: 64000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeClaude, ID: "claude-haiku-4-5-20251001", DisplayName: "Claude Haiku 4.5", ContextWindow: 200000, MaxTokens: 64000, Reasoning: true, Input: []string{"text", "image"}, Aliases: []string{"haiku", "claude-haiku-4-5"}},
	{AccountType: AccountTypeClaude, ID: "claude-sonnet-4-5-20250929", DisplayName: "Claude Sonnet 4.5", ContextWindow: 200000, MaxTokens: 64000, Reasoning: true, Input: []string{"text", "image"}},

	{AccountType: AccountTypeKimi, ID: "k3", DisplayName: "Kimi K3", Description: "Kimi's flagship model for long-horizon coding and knowledge work.", ContextWindow: 1048576, MaxTokens: 32768, Reasoning: true, WebSearch: true, Input: []string{"text", "image", "video"}},
	{AccountType: AccountTypeKimi, ID: "k3-256k", DisplayName: "Kimi K3-256K", Description: "Kimi K3 with a smaller context window and lower latency.", ContextWindow: 262144, MaxTokens: 32768, Reasoning: true, WebSearch: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeKimi, ID: "kimi-for-coding", DisplayName: "K2.7 Coding", ContextWindow: 262144, MaxTokens: 32768, Reasoning: true, Input: []string{"text", "image", "video"}, Aliases: []string{"kimi", "k2p5", "kimi-k2-thinking"}},
	{AccountType: AccountTypeKimi, ID: "kimi-for-coding-highspeed", DisplayName: "K2.7 Coding Highspeed", ContextWindow: 262144, MaxTokens: 32768, Reasoning: true, Input: []string{"text", "image", "video"}},

	{AccountType: AccountTypeMinimax, ID: "MiniMax-M3", DisplayName: "MiniMax-M3", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text", "image", "video"}, Aliases: []string{"minimax", "minimax-m3"}},
	{AccountType: AccountTypeMinimax, ID: "MiniMax-M2.7", DisplayName: "MiniMax-M2.7", ContextWindow: 204800, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeMinimax, ID: "MiniMax-M2.7-highspeed", DisplayName: "MiniMax-M2.7-Highspeed", ContextWindow: 204800, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},

	// GLM-5.3 replaces GLM-5.2 for Coding Plan users. Keep the previous ID as
	// an alias so existing installed configurations migrate at the proxy.
	{AccountType: AccountTypeZAI, ID: "glm-5.3", DisplayName: "GLM-5.3", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, WebSearch: true, Input: []string{"text"}, Aliases: []string{"glm-5.2"}},
	{AccountType: AccountTypeZAI, ID: "glm-5.3-flash", DisplayName: "GLM-5.3-Flash", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, WebSearch: true, Input: []string{"text"}},

	{AccountType: AccountTypeXiaomi, ID: "mimo-v2.5-pro", DisplayName: "MiMo-V2.5-Pro", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, WebSearch: true, Input: []string{"text"}, Aliases: []string{"mimo-v2.5-pro[1m]"}},
	{AccountType: AccountTypeXiaomi, ID: "mimo-v2.5", DisplayName: "MiMo-V2.5", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text", "image", "video", "audio"}},

	// Upstream advertises max_model_len 524288 and enforces it: a 600k-token
	// prompt is rejected with "maximum context length is 524288 tokens".
	{AccountType: AccountTypeAdverserial, ID: "lordx64/cyberkimi", DisplayName: "CyberKimi", Description: "Security-focused Kimi variant via adverserial.ai.", ContextWindow: 524288, MaxTokens: 32768, Reasoning: true, Input: []string{"text"}, Aliases: []string{"cyberkimi"}},

	// OpenCode Go subscription models (https://opencode.ai/zen/go/v1).
	// Canonical pool IDs use the `opencode-go/<id>` prefix, matching OpenCode's
	// own config convention. Bare IDs route here only when no other provider
	// claims them (see isOpencodeGoModel). Context windows and output limits
	// follow models.dev; outputs are capped at 131072.
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/kimi-k2.7-code", DisplayName: "Kimi K2.7 Code (Go)", ContextWindow: 262144, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/qwen3.7-max", DisplayName: "Qwen3.7 Max (Go)", ContextWindow: 1000000, MaxTokens: 65536, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/kimi-k3", DisplayName: "Kimi K3 (Go)", ContextWindow: 1048576, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/muse-spark-1.3-contributor", DisplayName: "Muse Spark 1.3 Contributor (Go)", ContextWindow: 1048576, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/deepseek-v4-flash", DisplayName: "DeepSeek V4 Flash (Go)", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/omen-alpha", DisplayName: "Omen Alpha (Go)", ContextWindow: 500000, MaxTokens: 128000, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/mimo-v2.5", DisplayName: "MiMo V2.5 (Go)", ContextWindow: 1000000, MaxTokens: 128000, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/grok-4.6", DisplayName: "Grok 4.6 (Go)", ContextWindow: 500000, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/grok-4.5", DisplayName: "Grok 4.5 (Go)", ContextWindow: 500000, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/deepseek-v4-pro", DisplayName: "DeepSeek V4 Pro (Go)", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/qwen3.5-plus", DisplayName: "Qwen3.5 Plus (Go)", ContextWindow: 262144, MaxTokens: 65536, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/gpt-5.6-luna", DisplayName: "GPT-5.6 Luna (Go)", ContextWindow: 1050000, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/glm-5", DisplayName: "GLM-5 (Go)", ContextWindow: 202752, MaxTokens: 32768, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/minimax-m3", DisplayName: "MiniMax M3 (Go)", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/minimax-m2.7", DisplayName: "MiniMax M2.7 (Go)", ContextWindow: 204800, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/qwen3.8-max", DisplayName: "Qwen3.8 Max (Go)", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/mimo-v2-pro", DisplayName: "MiMo V2 Pro (Go)", ContextWindow: 1048576, MaxTokens: 128000, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/qwen3.7-plus", DisplayName: "Qwen3.7 Plus (Go)", ContextWindow: 1000000, MaxTokens: 65536, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/qwen3.8-flash", DisplayName: "Qwen3.8 Flash (Go)", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/glm-5.3", DisplayName: "GLM-5.3 (Go)", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/kimi-k2.5", DisplayName: "Kimi K2.5 (Go)", ContextWindow: 262144, MaxTokens: 65536, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/glm-5.2", DisplayName: "GLM-5.2 (Go)", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/minimax-m2.5", DisplayName: "MiniMax M2.5 (Go)", ContextWindow: 204800, MaxTokens: 65536, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/mimo-v2-omni", DisplayName: "MiMo V2 Omni (Go)", ContextWindow: 262144, MaxTokens: 128000, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/longcat-2.0", DisplayName: "LongCat-2.0 (Go)", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/qwen3.6-plus", DisplayName: "Qwen3.6 Plus (Go)", ContextWindow: 1000000, MaxTokens: 65536, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/hy4-preview", DisplayName: "Hy4 preview (Go)", ContextWindow: 1024000, MaxTokens: 64000, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/glm-5.1", DisplayName: "GLM-5.1 (Go)", ContextWindow: 202752, MaxTokens: 32768, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/mimo-v2.5-pro", DisplayName: "MiMo V2.5 Pro (Go)", ContextWindow: 1048576, MaxTokens: 128000, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/hy3", DisplayName: "Hy3 (Go)", ContextWindow: 256000, MaxTokens: 128000, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/hy3-preview", DisplayName: "Hy3 Preview (Go)", ContextWindow: 256000, MaxTokens: 128000, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/muse-spark-1.2-contributor", DisplayName: "Muse Spark 1.2 Contributor (Go)", ContextWindow: 1048576, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/kimi-k2.6", DisplayName: "Kimi K2.6 (Go)", ContextWindow: 262144, MaxTokens: 65536, Reasoning: true, Input: []string{"text"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/deepseek-v4-flash-vision-exp", DisplayName: "DeepSeek V4 Flash Vision Exp (Go)", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text", "image"}},
	{AccountType: AccountTypeOpencodeGo, ID: "opencode-go/glm-5.3-flash", DisplayName: "GLM-5.3-Flash (Go)", ContextWindow: 1000000, MaxTokens: 131072, Reasoning: true, Input: []string{"text"}},
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
