package main

import "strings"

func modelProtocol(provider AccountType, id string) string {
	switch provider {
	case AccountTypeCodex, AccountTypeGrok:
		return "openai"
	case AccountTypeGemini:
		return "gemini"
	case AccountTypeOpencodeGo:
		if strings.HasPrefix(strings.ToLower(id), "opencode/") {
			return "openai"
		}
		return opencodeGoClientProtocol(id)
	default:
		return "anthropic"
	}
}

func projectModel(provider AccountType, publicID, upstreamID string, model DiscoveredModel) poolModelDescriptor {
	protocol := modelProtocol(provider, publicID)
	description := model.Description
	if isMistralType(provider) {
		adapter := "Mistral Chat Completions through the codex-pool Messages adapter"
		if strings.TrimSpace(description) == "" {
			description = adapter
		} else {
			description += ". " + adapter
		}
	}
	capabilities := map[string]bool{"reasoning": model.Reasoning, "tools": model.Tools}
	if model.WebSearch {
		capabilities["web_search"] = true
	}
	return poolModelDescriptor{
		ID: publicID, Name: model.DisplayName, Description: description,
		Protocol: protocol, Protocols: []string{protocol}, Provider: string(provider), UpstreamID: upstreamID,
		ContextWindow: model.ContextWindow, MaxOutputTokens: model.MaxOutputTokens,
		Modalities: append([]string(nil), model.Modalities...), Capabilities: capabilities,
		NativeTools: nativeWebSearchTools(provider, model.WebSearch),
	}
}
