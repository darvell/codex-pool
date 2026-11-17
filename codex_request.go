package main

import (
	"strings"
)

func mapResponsesPath(in string) string {
	// Only public/v1 Responses paths map to ChatGPT's /responses join form.
	// /backend-api/codex/responses must keep the /codex/responses suffix so
	// CodexProvider.NormalizePath + whamBase still produce
	// https://chatgpt.com/backend-api/codex/responses (not /backend-api/responses).
	switch {
	case strings.HasPrefix(in, "/v1/responses/compact") || strings.HasPrefix(in, "/responses/compact"):
		return "/responses/compact"
	case in == "/v1/responses" || in == "/responses":
		return "/responses"
	default:
		return ""
	}
}

// isCodexResponsesPath reports Codex-shaped Responses endpoints, including the
// private ChatGPT backend path clients often configure as OPENAI_BASE_URL.
// Oversized/chunked requests on these paths must still model-route: without
// that, Grok/Kimi/etc. are forwarded to ChatGPT and fail with
// "not supported when using Codex with a ChatGPT account".
func isCodexResponsesPath(path string) bool {
	path = normalizeNoopPath(path)
	if path == "/responses" || path == "/v1/responses" ||
		strings.HasPrefix(path, "/responses/") || strings.HasPrefix(path, "/v1/responses/") {
		return true
	}
	if path == "/backend-api/codex/responses" || strings.HasPrefix(path, "/backend-api/codex/responses/") {
		return true
	}
	if path == "/api/codex/responses" || strings.HasPrefix(path, "/api/codex/responses/") {
		return true
	}
	return false
}

func isStreamedModelRoutePath(path string) bool {
	path = normalizeNoopPath(path)
	return path == "/v1/messages" || isCodexResponsesPath(path)
}

func codexPassthroughNeedsBodyRewrite(path string) bool {
	return strings.HasPrefix(path, "/v1/messages") ||
		strings.HasPrefix(path, "/v1/chat/completions") ||
		strings.HasPrefix(path, "/v1/completions")
}

func prepareResponsesObject(obj map[string]any) {
	if _, ok := obj["instructions"]; !ok {
		obj["instructions"] = ""
	}
	obj["store"] = false
	obj["stream"] = true
	prepareCodexSchemasInBody(obj)
	sanitizeCodexResponsesParams(obj)
	if input, ok := obj["input"].(string); ok {
		obj["input"] = []any{
			map[string]any{
				"type": "message",
				"role": "user",
				"content": []any{
					map[string]any{"type": "input_text", "text": input},
				},
			},
		}
	}
	stripHostedMCPFromResponsesRequest(obj)
}

func prepareCodexSchemasInBody(obj map[string]any) {
	if text, _ := obj["text"].(map[string]any); text != nil {
		if format, _ := text["format"].(map[string]any); format != nil {
			if schema, _ := format["schema"].(map[string]any); schema != nil {
				format["schema"] = prepareCodexJSONSchema(schema)
			}
		}
	}
	if tools, ok := obj["tools"].([]any); ok {
		for _, raw := range tools {
			tool, _ := raw.(map[string]any)
			if tool == nil {
				continue
			}
			if params, _ := tool["parameters"].(map[string]any); params != nil {
				tool["parameters"] = prepareCodexJSONSchema(params)
			}
			if fn, _ := tool["function"].(map[string]any); fn != nil {
				if params, _ := fn["parameters"].(map[string]any); params != nil {
					fn["parameters"] = prepareCodexJSONSchema(params)
				}
			}
		}
	}
}

func sanitizeCodexResponsesParams(obj map[string]any) {
	for key := range codexResponsesDroppedFields {
		delete(obj, key)
	}
}

func valueHasImageGenerationTool(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		if typ, _ := x["type"].(string); typ == "image_generation" {
			return true
		}
		for _, child := range x {
			if valueHasImageGenerationTool(child) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if valueHasImageGenerationTool(child) {
				return true
			}
		}
	}
	return false
}

func codexPassthroughRewrite(path string, body []byte) (rewrittenPath string, rewrittenBody []byte, err error) {
	switch {
	case strings.HasPrefix(path, "/v1/messages"):
		rewritten, err := translateClaudeToResponsesRequest(body)
		if err != nil {
			return path, nil, err
		}
		return "/v1/responses", rewritten, nil
	case strings.HasPrefix(path, "/v1/chat/completions"):
		rewritten, err := translateChatCompletionsToResponses(body)
		if err != nil {
			return path, nil, err
		}
		return "/v1/responses", rewritten, nil
	case strings.HasPrefix(path, "/v1/completions"):
		rewritten, err := translateCompletionsToResponses(body)
		if err != nil {
			return path, nil, err
		}
		return "/v1/responses", rewritten, nil
	default:
		return path, body, nil
	}
}
