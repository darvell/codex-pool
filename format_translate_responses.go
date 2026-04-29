package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// translateChatCompletionsToResponses converts an OpenAI Chat Completions request
// body to the Responses API format used by the Codex backend.
func translateChatCompletionsToResponses(body []byte) ([]byte, error) {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("parse chat completions request: %w", err)
	}

	out := map[string]any{}

	// model -> model
	if m, ok := req["model"].(string); ok {
		out["model"] = m
	}

	// messages -> input + instructions
	messages, _ := req["messages"].([]any)
	var input []any
	var instructions string
	for _, msg := range messages {
		m, ok := msg.(map[string]any)
		if !ok {
			continue
		}
		role, _ := m["role"].(string)

		switch role {
		case "system", "developer":
			// System messages become instructions
			if text := extractTextContent(m); text != "" {
				if instructions != "" {
					instructions += "\n"
				}
				instructions += text
			}

		case "user":
			item := map[string]any{
				"type": "message",
				"role": "user",
			}
			content := convertOAIContentToResponsesContent(m["content"])
			item["content"] = content
			input = append(input, item)

		case "assistant":
			if text := extractTextContent(m); text != "" {
				input = append(input, map[string]any{
					"type": "message",
					"role": "assistant",
					"content": []any{
						map[string]any{"type": "output_text", "text": text},
					},
				})
			}
			if toolCalls, ok := m["tool_calls"].([]any); ok && len(toolCalls) > 0 {
				for _, tc := range toolCalls {
					call, ok := tc.(map[string]any)
					if !ok {
						continue
					}
					fn, _ := call["function"].(map[string]any)
					if fn == nil {
						continue
					}
					callID, _ := call["id"].(string)
					name, _ := fn["name"].(string)
					args, _ := fn["arguments"].(string)
					input = append(input, map[string]any{
						"type":      "function_call",
						"call_id":   callID,
						"name":      name,
						"arguments": args,
					})
				}
			} else if fn, ok := m["function_call"].(map[string]any); ok && fn != nil {
				name, _ := fn["name"].(string)
				args, _ := fn["arguments"].(string)
				input = append(input, map[string]any{
					"type":      "function_call",
					"call_id":   "fc_" + name,
					"name":      name,
					"arguments": args,
				})
			} else if extractTextContent(m) == "" {
				input = append(input, map[string]any{
					"type":    "message",
					"role":    "assistant",
					"content": convertOAIContentToResponsesContent(m["content"]),
				})
			}

		case "tool":
			// Tool result -> function_call_output
			callID, _ := m["tool_call_id"].(string)
			text := extractTextContent(m)
			input = append(input, map[string]any{
				"type":    "function_call_output",
				"call_id": callID,
				"output":  text,
			})
		case "function":
			name, _ := m["name"].(string)
			text := extractTextContent(m)
			input = append(input, map[string]any{
				"type":    "function_call_output",
				"call_id": "fc_" + name,
				"output":  text,
			})
		}
	}

	// Codex backend requires the instructions field, even if empty.
	out["instructions"] = instructions
	if len(input) > 0 {
		out["input"] = input
	}

	// Codex backend requires stream=true always; the proxy handles
	// non-streaming by buffering SSE events and assembling a final response.
	out["stream"] = true

	// temperature -> temperature
	if v, ok := req["temperature"]; ok {
		out["temperature"] = v
	}

	// top_p -> top_p
	if v, ok := req["top_p"]; ok {
		out["top_p"] = v
	}

	// NOTE: max_tokens / max_completion_tokens intentionally NOT mapped to
	// max_output_tokens — the Codex backend rejects that parameter.

	// tools/functions -> Responses tools
	if responsesTools := convertOpenAIToolsToResponses(req); len(responsesTools) > 0 {
		out["tools"] = responsesTools
	}

	// tool_choice -> Responses tool_choice
	if v, ok := req["tool_choice"]; ok {
		if choice := convertOpenAIToolChoiceToResponses(v); choice != nil {
			out["tool_choice"] = choice
		}
	}

	// stop -> stop (pass through if present, but Responses API doesn't typically use it)

	// Codex backend requires store=false
	out["store"] = false

	// Pass through any Codex-specific fields
	for _, key := range []string{"conversation_id", "prompt_cache_key", "previous_response_id"} {
		if v, ok := req[key]; ok {
			out[key] = v
		}
	}

	return json.Marshal(out)
}

func convertOpenAIToolsToResponses(req map[string]any) []any {
	var responsesTools []any
	if tools, ok := req["tools"].([]any); ok {
		for _, t := range tools {
			tool, ok := t.(map[string]any)
			if !ok {
				continue
			}
			if hosted := normalizeOpenAIHostedWebSearchTool(tool); hosted != nil {
				responsesTools = append(responsesTools, hosted)
				continue
			}
			if typ, _ := tool["type"].(string); typ != "function" {
				continue
			}
			fn, _ := tool["function"].(map[string]any)
			if fn == nil {
				continue
			}
			if rt := convertOpenAIFunctionTool(fn); rt != nil {
				responsesTools = append(responsesTools, rt)
			}
		}
	}
	if functions, ok := req["functions"].([]any); ok {
		for _, raw := range functions {
			fn, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if rt := convertOpenAIFunctionTool(fn); rt != nil {
				responsesTools = append(responsesTools, rt)
			}
		}
	}
	return responsesTools
}

func convertOpenAIFunctionTool(fn map[string]any) map[string]any {
	name, _ := fn["name"].(string)
	if name == "" {
		return nil
	}
	rt := map[string]any{"type": "function", "name": name}
	if desc, _ := fn["description"].(string); desc != "" {
		rt["description"] = desc
	}
	if params, _ := fn["parameters"].(map[string]any); params != nil {
		rt["parameters"] = normalizeOpenAIToolSchema(params)
	}
	return rt
}

func normalizeOpenAIToolSchema(schema map[string]any) map[string]any {
	if typ, _ := schema["type"].(string); typ == "object" {
		if _, ok := schema["properties"]; !ok {
			copy := make(map[string]any, len(schema)+1)
			for k, v := range schema {
				copy[k] = v
			}
			copy["properties"] = map[string]any{}
			return copy
		}
	}
	return schema
}

func normalizeOpenAIHostedWebSearchTool(tool map[string]any) map[string]any {
	typ, _ := tool["type"].(string)
	if typ != "web_search" && typ != "web_search_preview" {
		return nil
	}
	out := map[string]any{"type": "web_search"}
	if size, _ := tool["search_context_size"].(string); size == "low" || size == "medium" || size == "high" {
		out["search_context_size"] = size
	}
	if loc, ok := tool["user_location"].(map[string]any); ok {
		out["user_location"] = loc
	}
	return out
}

func convertOpenAIToolChoiceToResponses(choice any) any {
	switch c := choice.(type) {
	case string:
		return c
	case map[string]any:
		if typ, _ := c["type"].(string); typ == "web_search" || typ == "web_search_preview" {
			return map[string]any{"type": "web_search"}
		}
		fn, _ := c["function"].(map[string]any)
		name, _ := fn["name"].(string)
		if name == "" {
			return nil
		}
		return map[string]any{"type": "function", "name": name}
	default:
		return nil
	}
}

// convertOAIContentToResponsesContent converts OpenAI message content to Responses API content format.
func convertOAIContentToResponsesContent(content any) []any {
	switch c := content.(type) {
	case string:
		return []any{
			map[string]any{"type": "input_text", "text": c},
		}
	case []any:
		var result []any
		for _, part := range c {
			p, ok := part.(map[string]any)
			if !ok {
				continue
			}
			partType, _ := p["type"].(string)
			switch partType {
			case "text":
				text, _ := p["text"].(string)
				result = append(result, map[string]any{"type": "input_text", "text": text})
			case "image_url":
				var url string
				switch imageURL := p["image_url"].(type) {
				case string:
					url = imageURL
				case map[string]any:
					url, _ = imageURL["url"].(string)
				}
				if url != "" {
					result = append(result, map[string]any{
						"type":      "input_image",
						"image_url": url,
					})
				}
			default:
				// Pass through unknown types
				result = append(result, p)
			}
		}
		return result
	default:
		return []any{}
	}
}

// translateResponsesToChatCompletions converts a non-streaming Responses API response
// to an OpenAI Chat Completions response.
func translateResponsesToChatCompletions(body []byte) ([]byte, error) {
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse responses api response: %w", err)
	}

	id, _ := resp["id"].(string)
	model, _ := resp["model"].(string)

	// Build the message from output items
	var contentText string
	var toolCalls []any
	toolCallIdx := 0

	if output, ok := resp["output"].([]any); ok {
		for _, item := range output {
			o, ok := item.(map[string]any)
			if !ok {
				continue
			}
			itemType, _ := o["type"].(string)
			switch itemType {
			case "message":
				if content, ok := o["content"].([]any); ok {
					for _, c := range content {
						block, ok := c.(map[string]any)
						if !ok {
							continue
						}
						if blockType, _ := block["type"].(string); blockType == "output_text" {
							if text, ok := block["text"].(string); ok {
								contentText += text
							}
						}
					}
				}
			case "function_call":
				callID, _ := o["call_id"].(string)
				name, _ := o["name"].(string)
				args, _ := o["arguments"].(string)
				toolCalls = append(toolCalls, map[string]any{
					"id":    callID,
					"type":  "function",
					"index": toolCallIdx,
					"function": map[string]any{
						"name":      name,
						"arguments": args,
					},
				})
				toolCallIdx++
			}
		}
	}

	// Determine finish reason
	finishReason := "stop"
	if status, ok := resp["status"].(string); ok {
		switch status {
		case "completed":
			finishReason = "stop"
		case "incomplete":
			if details, ok := resp["incomplete_details"].(map[string]any); ok {
				if r, _ := details["reason"].(string); r == "max_output_tokens" {
					finishReason = "length"
				}
			}
		}
	}
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
	}

	message := map[string]any{
		"role":    "assistant",
		"content": contentText,
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}

	// Build usage
	var usage map[string]any
	if u, ok := resp["usage"].(map[string]any); ok {
		usage = map[string]any{
			"prompt_tokens":     toInt64(u["input_tokens"]),
			"completion_tokens": toInt64(u["output_tokens"]),
			"total_tokens":      toInt64(u["total_tokens"]),
		}
	}

	out := map[string]any{
		"id":     id,
		"object": "chat.completion",
		"model":  model,
		"choices": []any{
			map[string]any{
				"index":         0,
				"message":       message,
				"finish_reason": finishReason,
			},
		},
	}
	if usage != nil {
		out["usage"] = usage
	}

	return json.Marshal(out)
}

// translateResponsesToClaudeRequest converts a Responses API request body
// to Claude Messages API format. Used when Codex CLI sends to /responses
// but the model is routed to a Claude account.
func translateResponsesToClaudeRequest(body []byte) ([]byte, error) {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("parse responses request: %w", err)
	}

	claude := map[string]any{}

	// model
	if m, ok := req["model"].(string); ok {
		claude["model"] = m
	}

	// instructions -> system
	if instr, ok := req["instructions"].(string); ok && instr != "" {
		claude["system"] = instr
	}

	// input -> messages
	var claudeMsgs []map[string]any
	var developerTexts []string
	switch inp := req["input"].(type) {
	case string:
		// Simple string input
		claudeMsgs = append(claudeMsgs, map[string]any{
			"role":    "user",
			"content": inp,
		})
	case []any:
		for _, item := range inp {
			it, ok := item.(map[string]any)
			if !ok {
				continue
			}
			itemType, _ := it["type"].(string)
			switch itemType {
			case "message":
				role, _ := it["role"].(string)
				// developer/system messages go into Claude's system prompt
				if role == "developer" || role == "system" {
					if content, ok := it["content"].(string); ok && content != "" {
						developerTexts = append(developerTexts, content)
					} else if content, ok := it["content"].([]any); ok {
						for _, part := range content {
							p, ok := part.(map[string]any)
							if !ok {
								continue
							}
							if t, _ := p["type"].(string); t == "input_text" || t == "output_text" || t == "text" {
								if text, ok := p["text"].(string); ok && text != "" {
									developerTexts = append(developerTexts, text)
								}
							}
						}
					}
					continue
				}
				msg := map[string]any{"role": role}
				if content, ok := it["content"].([]any); ok {
					msg["content"] = convertResponsesContentToClaude(content, role)
				} else if content, ok := it["content"].(string); ok {
					msg["content"] = content
				}
				claudeMsgs = append(claudeMsgs, msg)
			case "function_call":
				// Append as tool_use block to the previous assistant message,
				// or create a new assistant message.
				callID, _ := it["call_id"].(string)
				name, _ := it["name"].(string)
				argsStr, _ := it["arguments"].(string)
				var argsObj any
				if json.Unmarshal([]byte(argsStr), &argsObj) != nil {
					argsObj = map[string]any{}
				}
				block := map[string]any{
					"type":  "tool_use",
					"id":    callID,
					"name":  "mcp_" + name,
					"input": argsObj,
				}
				// Try to merge into previous assistant message
				merged := false
				if len(claudeMsgs) > 0 {
					last := claudeMsgs[len(claudeMsgs)-1]
					if lastRole, _ := last["role"].(string); lastRole == "assistant" {
						if blocks, ok := last["content"].([]any); ok {
							last["content"] = append(blocks, block)
							merged = true
						}
					}
				}
				if !merged {
					claudeMsgs = append(claudeMsgs, map[string]any{
						"role":    "assistant",
						"content": []any{block},
					})
				}
			case "function_call_output":
				callID, _ := it["call_id"].(string)
				output, _ := it["output"].(string)
				block := map[string]any{
					"type":        "tool_result",
					"tool_use_id": callID,
					"content":     output,
				}
				// Merge into previous user message with tool_result blocks
				merged := false
				if len(claudeMsgs) > 0 {
					last := claudeMsgs[len(claudeMsgs)-1]
					if lastRole, _ := last["role"].(string); lastRole == "user" {
						if blocks, ok := last["content"].([]any); ok {
							last["content"] = append(blocks, block)
							merged = true
						}
					}
				}
				if !merged {
					claudeMsgs = append(claudeMsgs, map[string]any{
						"role":    "user",
						"content": []any{block},
					})
				}
			}
		}
	}
	claude["messages"] = claudeMsgs

	// Set system prompt for Claude Code compatibility.
	// The developer messages from Codex CLI contain agent instructions that
	// are useful context, so we prepend the Claude Code identifier and include them.
	{
		const claudeCodePrefix = "You are Claude Code, Anthropic's official CLI for Claude."
		var systemParts []string
		systemParts = append(systemParts, claudeCodePrefix)

		// Include the original instructions field if present
		if sysPrompt, ok := claude["system"].(string); ok && sysPrompt != "" {
			systemParts = append(systemParts, sysPrompt)
		}
		// Include developer message content (agent instructions from Codex)
		if len(developerTexts) > 0 {
			systemParts = append(systemParts, strings.Join(developerTexts, "\n\n"))
		}
		claude["system"] = strings.Join(systemParts, "\n\n")
	}

	// max_output_tokens -> max_tokens
	if v, ok := req["max_output_tokens"]; ok {
		claude["max_tokens"] = v
	} else {
		claude["max_tokens"] = 16384
	}

	// Direct copy
	for _, key := range []string{"temperature", "top_p", "stream"} {
		if v, ok := req[key]; ok {
			claude[key] = v
		}
	}

	// tools -> convert from Responses API format to Claude format
	if tools, ok := req["tools"].([]any); ok && len(tools) > 0 {
		var claudeTools []any
		for _, t := range tools {
			tool, ok := t.(map[string]any)
			if !ok {
				continue
			}
			name, _ := tool["name"].(string)
			if name == "" {
				// Skip non-function tools (code_interpreter, web_search, etc.)
				continue
			}
			desc, _ := tool["description"].(string)
			params, _ := tool["parameters"].(map[string]any)
			ct := map[string]any{
				"name": "mcp_" + name,
			}
			if desc != "" {
				ct["description"] = desc
			}
			if params != nil {
				ct["input_schema"] = params
			} else {
				ct["input_schema"] = map[string]any{"type": "object"}
			}
			claudeTools = append(claudeTools, ct)
		}
		claude["tools"] = claudeTools
	}

	return json.Marshal(claude)
}

// convertResponsesContentToClaude converts Responses API content blocks to Claude content blocks.
func convertResponsesContentToClaude(content []any, role string) []any {
	var blocks []any
	for _, part := range content {
		p, ok := part.(map[string]any)
		if !ok {
			continue
		}
		partType, _ := p["type"].(string)
		switch partType {
		case "input_text":
			text, _ := p["text"].(string)
			blocks = append(blocks, map[string]any{"type": "text", "text": text})
		case "output_text":
			text, _ := p["text"].(string)
			blocks = append(blocks, map[string]any{"type": "text", "text": text})
		default:
			blocks = append(blocks, p)
		}
	}
	return blocks
}

// translateClaudeRespToResponses converts a non-streaming Claude Messages API response
// to Responses API format.
func translateClaudeRespToResponses(body []byte) ([]byte, error) {
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse claude response: %w", err)
	}

	id, _ := resp["id"].(string)
	model, _ := resp["model"].(string)

	var output []any
	if content, ok := resp["content"].([]any); ok {
		var textParts []string
		for _, c := range content {
			block, ok := c.(map[string]any)
			if !ok {
				continue
			}
			blockType, _ := block["type"].(string)
			switch blockType {
			case "text":
				text, _ := block["text"].(string)
				textParts = append(textParts, text)
			case "tool_use":
				toolID, _ := block["id"].(string)
				name, _ := block["name"].(string)
				name = strings.TrimPrefix(name, "mcp_")
				inputObj, _ := block["input"].(map[string]any)
				argsBytes, _ := json.Marshal(inputObj)
				output = append(output, map[string]any{
					"type":      "function_call",
					"call_id":   toolID,
					"name":      name,
					"arguments": string(argsBytes),
				})
			}
		}
		if len(textParts) > 0 {
			msgItem := map[string]any{
				"type": "message",
				"role": "assistant",
				"content": []any{
					map[string]any{"type": "output_text", "text": joinStrings(textParts)},
				},
			}
			// Insert message item before function_calls
			output = append([]any{msgItem}, output...)
		}
	}

	status := "completed"
	stopReason, _ := resp["stop_reason"].(string)
	if stopReason == "max_tokens" {
		status = "incomplete"
	}

	result := map[string]any{
		"id":     id,
		"object": "response",
		"model":  model,
		"status": status,
		"output": output,
	}

	if usage, ok := resp["usage"].(map[string]any); ok {
		result["usage"] = map[string]any{
			"input_tokens":  toInt64(usage["input_tokens"]),
			"output_tokens": toInt64(usage["output_tokens"]),
			"total_tokens":  toInt64(usage["input_tokens"]) + toInt64(usage["output_tokens"]),
		}
	}

	return json.Marshal(result)
}

// translateClaudeToResponsesRequest converts a Claude Messages API request body
// to the Responses API format used by the Codex backend. Used when Claude Code
// sends /v1/messages with a Codex model (e.g. gpt-5.3-codex).
func translateClaudeToResponsesRequest(body []byte) ([]byte, error) {
	var claude map[string]any
	if err := json.Unmarshal(body, &claude); err != nil {
		return nil, fmt.Errorf("parse claude request: %w", err)
	}

	out := map[string]any{}

	// model
	if m, ok := claude["model"].(string); ok {
		out["model"] = m
	}

	// system -> instructions
	if sys := extractClaudeSystem(claude["system"]); sys != "" {
		out["instructions"] = sys
	} else {
		out["instructions"] = ""
	}

	// messages -> input
	var input []any
	if rawMsgs, ok := claude["messages"].([]any); ok {
		for _, rm := range rawMsgs {
			m, ok := rm.(map[string]any)
			if !ok {
				continue
			}
			role, _ := m["role"].(string)
			content := m["content"]

			switch role {
			case "user":
				item := map[string]any{
					"type": "message",
					"role": "user",
				}
				item["content"] = convertClaudeContentToResponsesInput(content)
				input = append(input, item)

			case "assistant":
				blocks, isArray := content.([]any)
				if !isArray {
					// String content
					if s, ok := content.(string); ok && s != "" {
						item := map[string]any{
							"type": "message",
							"role": "assistant",
							"content": []any{
								map[string]any{"type": "output_text", "text": s},
							},
						}
						input = append(input, item)
					}
					continue
				}
				// Array of content blocks - separate text and tool_use
				var textParts []string
				var toolUseBlocks []map[string]any
				for _, b := range blocks {
					block, ok := b.(map[string]any)
					if !ok {
						continue
					}
					blockType, _ := block["type"].(string)
					switch blockType {
					case "text":
						if t, ok := block["text"].(string); ok && t != "" {
							textParts = append(textParts, t)
						}
					case "tool_use":
						toolUseBlocks = append(toolUseBlocks, block)
					case "thinking", "redacted_thinking":
						// Skip thinking blocks
					}
				}
				// Emit assistant message with text if present
				if len(textParts) > 0 {
					item := map[string]any{
						"type": "message",
						"role": "assistant",
						"content": []any{
							map[string]any{"type": "output_text", "text": joinStrings(textParts)},
						},
					}
					input = append(input, item)
				}
				// Emit function_call items for each tool_use
				for _, tu := range toolUseBlocks {
					callID, _ := tu["id"].(string)
					name, _ := tu["name"].(string)
					inputObj := tu["input"]
					argsBytes, _ := json.Marshal(inputObj)
					input = append(input, map[string]any{
						"type":      "function_call",
						"call_id":   callID,
						"name":      name,
						"arguments": string(argsBytes),
					})
				}
			}

			// Handle tool_result content blocks in user messages
			if role == "user" {
				if blocks, ok := content.([]any); ok {
					hasToolResult := false
					for _, b := range blocks {
						block, ok := b.(map[string]any)
						if !ok {
							continue
						}
						if blockType, _ := block["type"].(string); blockType == "tool_result" {
							hasToolResult = true
							break
						}
					}
					if hasToolResult {
						// Remove the last user message we just added (it was for the whole content)
						// and instead emit individual items
						if len(input) > 0 {
							input = input[:len(input)-1]
						}
						for _, b := range blocks {
							block, ok := b.(map[string]any)
							if !ok {
								continue
							}
							blockType, _ := block["type"].(string)
							switch blockType {
							case "tool_result":
								callID, _ := block["tool_use_id"].(string)
								resultContent := extractToolResultContent(block["content"])
								input = append(input, map[string]any{
									"type":    "function_call_output",
									"call_id": callID,
									"output":  resultContent,
								})
							case "text":
								if t, ok := block["text"].(string); ok && t != "" {
									input = append(input, map[string]any{
										"type": "message",
										"role": "user",
										"content": []any{
											map[string]any{"type": "input_text", "text": t},
										},
									})
								}
							}
						}
					}
				}
			}
		}
	}

	if len(input) > 0 {
		out["input"] = input
	}

	// Codex backend requires stream=true always
	out["stream"] = true

	// temperature -> temperature
	if v, ok := claude["temperature"]; ok {
		out["temperature"] = v
	}
	if v, ok := claude["top_p"]; ok {
		out["top_p"] = v
	}

	if effort := extractClaudeReasoningEffort(claude); effort != "" {
		out["reasoning"] = map[string]any{"effort": effort}
	}

	// tools -> convert from Claude format to Responses API format
	if tools, ok := claude["tools"].([]any); ok && len(tools) > 0 {
		var responsesTools []any
		for _, t := range tools {
			tool, ok := t.(map[string]any)
			if !ok {
				continue
			}
			name, _ := tool["name"].(string)
			if name == "" {
				continue
			}
			desc, _ := tool["description"].(string)
			params, _ := tool["input_schema"].(map[string]any)
			rt := map[string]any{
				"type": "function",
				"name": name,
			}
			if desc != "" {
				rt["description"] = desc
			}
			if params != nil {
				rt["parameters"] = params
			}
			responsesTools = append(responsesTools, rt)
		}
		out["tools"] = responsesTools
	}

	// Codex backend requires store=false
	out["store"] = false

	return json.Marshal(out)
}

func extractClaudeReasoningEffort(claude map[string]any) string {
	if effort, ok := claude["reasoning_effort"].(string); ok {
		return normalizeResponsesReasoningEffort(effort)
	}
	if reasoning, ok := claude["reasoning"].(map[string]any); ok {
		if effort, ok := reasoning["effort"].(string); ok {
			return normalizeResponsesReasoningEffort(effort)
		}
	}
	if outputConfig, ok := claude["output_config"].(map[string]any); ok {
		if effort, ok := outputConfig["effort"].(string); ok {
			return normalizeResponsesReasoningEffort(effort)
		}
	}
	if thinking, ok := claude["thinking"].(map[string]any); ok {
		if effort, ok := thinking["effort"].(string); ok {
			return normalizeResponsesReasoningEffort(effort)
		}
		if budget := numericAny(thinking["budget_tokens"]); budget > 0 {
			return reasoningEffortFromBudget(budget)
		}
	}
	return ""
}

func normalizeResponsesReasoningEffort(effort string) string {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "minimal", "low", "medium", "high":
		return strings.ToLower(strings.TrimSpace(effort))
	default:
		return ""
	}
}

func reasoningEffortFromBudget(budget float64) string {
	switch {
	case budget >= 10000:
		return "high"
	case budget <= 2000:
		return "low"
	default:
		return "medium"
	}
}

func numericAny(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	default:
		return 0
	}
}

// convertClaudeContentToResponsesInput converts Claude message content
// (string or content blocks) to Responses API input content format.
func convertClaudeContentToResponsesInput(content any) []any {
	switch c := content.(type) {
	case string:
		return []any{
			map[string]any{"type": "input_text", "text": c},
		}
	case []any:
		var result []any
		for _, part := range c {
			p, ok := part.(map[string]any)
			if !ok {
				continue
			}
			partType, _ := p["type"].(string)
			switch partType {
			case "text":
				text, _ := p["text"].(string)
				result = append(result, map[string]any{"type": "input_text", "text": text})
			case "image":
				// Convert Claude base64 image to Responses API format
				if source, ok := p["source"].(map[string]any); ok {
					sourceType, _ := source["type"].(string)
					if sourceType == "base64" {
						mediaType, _ := source["media_type"].(string)
						data, _ := source["data"].(string)
						if mediaType != "" && data != "" {
							dataURL := "data:" + mediaType + ";base64," + data
							result = append(result, map[string]any{
								"type":      "input_image",
								"image_url": dataURL,
							})
						}
					} else if sourceType == "url" {
						url, _ := source["url"].(string)
						result = append(result, map[string]any{
							"type":      "input_image",
							"image_url": url,
						})
					}
				}
			case "tool_result":
				// tool_result blocks are handled separately in the caller
			case "tool_use":
				// tool_use blocks are handled separately in the caller
			}
		}
		if len(result) == 0 {
			return []any{map[string]any{"type": "input_text", "text": ""}}
		}
		return result
	default:
		return []any{}
	}
}
func extractTextContent(msg map[string]any) string {
	switch c := msg["content"].(type) {
	case string:
		return c
	case []any:
		var texts []string
		for _, part := range c {
			p, ok := part.(map[string]any)
			if !ok {
				continue
			}
			if t, _ := p["type"].(string); t == "text" {
				if text, ok := p["text"].(string); ok {
					texts = append(texts, text)
				}
			}
		}
		if len(texts) > 0 {
			return strings.Join(texts, "\n")
		}
	}
	return ""
}
