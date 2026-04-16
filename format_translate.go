package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
)

// RequestFormat represents the API format of a request.
type RequestFormat int

const (
	FormatUnknown RequestFormat = iota
	FormatOpenAI                // OpenAI Chat Completions API
	FormatClaude                // Anthropic Messages API
)

func (f RequestFormat) String() string {
	switch f {
	case FormatOpenAI:
		return "openai"
	case FormatClaude:
		return "claude"
	default:
		return "unknown"
	}
}

// TranslateDirection indicates which way we're translating.
type TranslateDirection int

const (
	TranslateNone              TranslateDirection = iota
	TranslateClaudeToOAI                          // Client sent Claude format, upstream expects OpenAI Chat Completions
	TranslateOAIToClaude                          // Client sent OpenAI format, upstream expects Claude
	TranslateChatToResponses                      // Client sent Chat Completions, upstream expects Responses API
	TranslateResponsesToClaude                    // Client sent Responses API, upstream expects Claude Messages
	TranslateClaudeToResponses                    // Client sent Claude format, upstream expects Responses API
)

// detectRequestFormat determines the API format from the request path.
func detectRequestFormat(path string) RequestFormat {
	switch {
	case path == "/v1/messages" || strings.HasPrefix(path, "/v1/messages?"):
		return FormatClaude
	case strings.HasPrefix(path, "/v1/chat/completions"):
		return FormatOpenAI
	default:
		return FormatUnknown
	}
}

// providerTargetFormat returns the format the provider expects.
func providerTargetFormat(accountType AccountType) RequestFormat {
	switch accountType {
	case AccountTypeClaude:
		return FormatClaude
	case AccountTypeZAI:
		return FormatClaude
	case AccountTypeCodex:
		return FormatOpenAI
	default:
		return FormatUnknown
	}
}

// translateRequestBody translates a request body between formats.
func translateRequestBody(body []byte, src, dst RequestFormat) ([]byte, error) {
	if src == dst || src == FormatUnknown || dst == FormatUnknown {
		return body, nil
	}
	switch {
	case src == FormatClaude && dst == FormatOpenAI:
		return translateClaudeReqToOpenAI(body)
	case src == FormatOpenAI && dst == FormatClaude:
		return translateOpenAIReqToClaude(body)
	}
	return body, nil
}

// translateResponseBody translates a response body between formats.
// For error responses (status >= 400), use translateErrorBody instead.
func translateResponseBody(body []byte, src, dst RequestFormat, requestModel string) ([]byte, error) {
	if src == dst || src == FormatUnknown || dst == FormatUnknown {
		return body, nil
	}
	switch {
	case src == FormatOpenAI && dst == FormatClaude:
		return translateOpenAIRespToClaude(body, requestModel)
	case src == FormatClaude && dst == FormatOpenAI:
		return translateClaudeRespToOpenAI(body)
	}
	return body, nil
}

// translateErrorBody translates an error response body between formats so
// the client gets errors in its expected format.
func translateErrorBody(body []byte, src, dst RequestFormat) []byte {
	if src == dst || src == FormatUnknown || dst == FormatUnknown {
		return body
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body // not JSON, return as-is
	}

	switch {
	case src == FormatOpenAI && dst == FormatClaude:
		return translateOpenAIErrorToClaude(parsed, body)
	case src == FormatClaude && dst == FormatOpenAI:
		return translateClaudeErrorToOpenAI(parsed, body)
	}
	return body
}

// translateOpenAIErrorToClaude converts an OpenAI error response to Claude format.
// OpenAI: {"error":{"message":"...","type":"...","code":"..."}}
// Claude: {"type":"error","error":{"type":"...","message":"..."}}
func translateOpenAIErrorToClaude(parsed map[string]any, original []byte) []byte {
	errObj, ok := parsed["error"].(map[string]any)
	if !ok {
		return original
	}
	message, _ := errObj["message"].(string)
	errType, _ := errObj["type"].(string)
	if errType == "" {
		errType = "api_error"
	}
	// Map OpenAI error types to Claude error types
	claudeType := mapOAIErrorTypeToClaude(errType)
	out, err := json.Marshal(map[string]any{
		"type": "error",
		"error": map[string]any{
			"type":    claudeType,
			"message": message,
		},
	})
	if err != nil {
		return original
	}
	return out
}

// translateErrorToClaudeFormat converts a Codex/OpenAI error response to Claude
// Messages API error format. Handles both OpenAI-style errors
// ({"error":{"message":"..."}}) and Codex-style errors ({"detail":"..."}).
func translateErrorToClaudeFormat(body []byte, statusCode int) []byte {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		// Not JSON - wrap the raw text as a Claude error
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = fmt.Sprintf("upstream error: HTTP %d", statusCode)
		}
		out, _ := json.Marshal(map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "api_error",
				"message": msg,
			},
		})
		return out
	}

	// Try OpenAI error format: {"error":{"message":"...","type":"..."}}
	if _, ok := parsed["error"].(map[string]any); ok {
		return translateOpenAIErrorToClaude(parsed, body)
	}

	// Try Codex detail format: {"detail":"..."}
	if detail, ok := parsed["detail"].(string); ok && detail != "" {
		errType := "api_error"
		if statusCode == 400 {
			errType = "invalid_request_error"
		} else if statusCode == 429 {
			errType = "rate_limit_error"
		}
		out, _ := json.Marshal(map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    errType,
				"message": detail,
			},
		})
		return out
	}

	// Unknown format, return as-is
	return body
}

// translateClaudeErrorToOpenAI converts a Claude error response to OpenAI format.
// Claude: {"type":"error","error":{"type":"...","message":"..."}}
// OpenAI: {"error":{"message":"...","type":"...","code":null}}
func translateClaudeErrorToOpenAI(parsed map[string]any, original []byte) []byte {
	if t, _ := parsed["type"].(string); t != "error" {
		return original
	}
	errObj, ok := parsed["error"].(map[string]any)
	if !ok {
		return original
	}
	message, _ := errObj["message"].(string)
	errType, _ := errObj["type"].(string)
	if errType == "" {
		errType = "api_error"
	}
	oaiType := mapClaudeErrorTypeToOAI(errType)
	out, err := json.Marshal(map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    oaiType,
			"code":    nil,
		},
	})
	if err != nil {
		return original
	}
	return out
}

func mapOAIErrorTypeToClaude(oaiType string) string {
	switch oaiType {
	case "invalid_request_error":
		return "invalid_request_error"
	case "authentication_error":
		return "authentication_error"
	case "insufficient_quota", "billing_hard_limit_reached":
		return "overloaded_error"
	case "rate_limit_error":
		return "rate_limit_error"
	case "server_error", "service_unavailable_error":
		return "api_error"
	default:
		return "api_error"
	}
}

func mapClaudeErrorTypeToOAI(claudeType string) string {
	switch claudeType {
	case "invalid_request_error":
		return "invalid_request_error"
	case "authentication_error":
		return "authentication_error"
	case "rate_limit_error":
		return "rate_limit_error"
	case "overloaded_error":
		return "server_error"
	case "not_found_error":
		return "invalid_request_error"
	default:
		return "server_error"
	}
}

// --- Claude -> OpenAI request translation ---

func translateClaudeReqToOpenAI(body []byte) ([]byte, error) {
	var claude map[string]any
	if err := json.Unmarshal(body, &claude); err != nil {
		return nil, fmt.Errorf("parse claude request: %w", err)
	}

	oai := map[string]any{}

	// model
	if m, ok := claude["model"].(string); ok {
		oai["model"] = m
	}

	// Build messages
	var msgs []map[string]any

	// System message from top-level "system" field
	if sys := extractClaudeSystem(claude["system"]); sys != "" {
		msgs = append(msgs, map[string]any{"role": "system", "content": sys})
	}

	// Convert messages
	if rawMsgs, ok := claude["messages"].([]any); ok {
		for _, rm := range rawMsgs {
			m, ok := rm.(map[string]any)
			if !ok {
				continue
			}
			converted := convertClaudeMsgToOpenAI(m)
			msgs = append(msgs, converted...)
		}
	}

	oai["messages"] = msgs

	// Direct copy fields
	for _, key := range []string{"model", "temperature", "top_p", "max_tokens"} {
		if v, ok := claude[key]; ok {
			oai[key] = v
		}
	}

	// stop_sequences -> stop
	if ss, ok := claude["stop_sequences"]; ok {
		oai["stop"] = ss
	}

	// stream
	if s, ok := claude["stream"].(bool); ok {
		oai["stream"] = s
		if s {
			oai["stream_options"] = map[string]any{"include_usage": true}
		}
	}

	// tools
	if tools, ok := claude["tools"].([]any); ok && len(tools) > 0 {
		oai["tools"] = convertClaudeToolsToOpenAI(tools)
	}

	// tool_choice
	if tc, ok := claude["tool_choice"]; ok {
		oai["tool_choice"] = convertClaudeToolChoiceToOpenAI(tc)
	}

	return json.Marshal(oai)
}

func extractClaudeSystem(sys any) string {
	if sys == nil {
		return ""
	}
	// String
	if s, ok := sys.(string); ok {
		return s
	}
	// Array of content blocks
	if blocks, ok := sys.([]any); ok {
		var parts []string
		for _, b := range blocks {
			if block, ok := b.(map[string]any); ok {
				if t, ok := block["text"].(string); ok {
					parts = append(parts, t)
				}
			}
		}
		if len(parts) > 0 {
			result := parts[0]
			for i := 1; i < len(parts); i++ {
				result += "\n\n" + parts[i]
			}
			return result
		}
	}
	return ""
}

func convertClaudeMsgToOpenAI(m map[string]any) []map[string]any {
	role, _ := m["role"].(string)
	content := m["content"]

	// String content - simple case
	if s, ok := content.(string); ok {
		return []map[string]any{{"role": role, "content": s}}
	}

	// Array of content blocks
	blocks, ok := content.([]any)
	if !ok || len(blocks) == 0 {
		return []map[string]any{{"role": role, "content": ""}}
	}

	// Check for tool_result blocks (these become separate tool messages)
	var textParts []string
	var toolCalls []map[string]any
	var toolResults []map[string]any
	var contentParts []map[string]any // multimodal content parts for OpenAI
	hasImages := false

	for _, b := range blocks {
		block, ok := b.(map[string]any)
		if !ok {
			continue
		}
		blockType, _ := block["type"].(string)
		switch blockType {
		case "text":
			if t, ok := block["text"].(string); ok {
				textParts = append(textParts, t)
				contentParts = append(contentParts, map[string]any{
					"type": "text",
					"text": t,
				})
			}
		case "image":
			// Convert Claude image block to OpenAI image_url
			if source, ok := block["source"].(map[string]any); ok {
				mediaType, _ := source["media_type"].(string)
				data, _ := source["data"].(string)
				if mediaType != "" && data != "" {
					dataURL := "data:" + mediaType + ";base64," + data
					contentParts = append(contentParts, map[string]any{
						"type": "image_url",
						"image_url": map[string]any{
							"url": dataURL,
						},
					})
					hasImages = true
				}
			}
		case "tool_use":
			tc := map[string]any{
				"id":   block["id"],
				"type": "function",
				"function": map[string]any{
					"name":      block["name"],
					"arguments": marshalToolInput(block["input"]),
				},
			}
			toolCalls = append(toolCalls, tc)
		case "tool_result":
			toolResults = append(toolResults, block)
		case "thinking", "redacted_thinking":
			// Skip thinking blocks - OpenAI doesn't support them in messages
		}
	}

	var msgs []map[string]any

	// If this is an assistant message with tool calls
	if role == "assistant" && len(toolCalls) > 0 {
		msg := map[string]any{"role": "assistant"}
		if len(textParts) > 0 {
			msg["content"] = joinStrings(textParts)
		} else {
			msg["content"] = nil
		}
		msg["tool_calls"] = toolCalls
		msgs = append(msgs, msg)
		return msgs
	}

	// If there are tool results, they become separate tool messages
	if len(toolResults) > 0 {
		for _, tr := range toolResults {
			toolMsg := map[string]any{
				"role":         "tool",
				"tool_call_id": tr["tool_use_id"],
				"content":      extractToolResultContent(tr["content"]),
			}
			msgs = append(msgs, toolMsg)
		}
		return msgs
	}

	// Plain text or multimodal message
	msg := map[string]any{"role": role}
	if hasImages {
		// Use multimodal content array when images are present
		msg["content"] = contentParts
	} else if len(textParts) > 0 {
		msg["content"] = joinStrings(textParts)
	} else {
		msg["content"] = ""
	}
	msgs = append(msgs, msg)
	return msgs
}

func marshalToolInput(input any) string {
	if input == nil {
		return "{}"
	}
	if s, ok := input.(string); ok {
		return s
	}
	b, err := json.Marshal(input)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func extractToolResultContent(content any) string {
	if content == nil {
		return ""
	}
	if s, ok := content.(string); ok {
		return s
	}
	// Array of content blocks
	if blocks, ok := content.([]any); ok {
		var parts []string
		for _, b := range blocks {
			if block, ok := b.(map[string]any); ok {
				if t, ok := block["text"].(string); ok {
					parts = append(parts, t)
				}
			}
		}
		return joinStrings(parts)
	}
	return ""
}

func convertClaudeToolsToOpenAI(tools []any) []map[string]any {
	var out []map[string]any
	for _, t := range tools {
		tool, ok := t.(map[string]any)
		if !ok {
			continue
		}
		// Sanitize input_schema: strip fields that OpenAI rejects
		params := tool["input_schema"]
		if schema, ok := params.(map[string]any); ok {
			params = sanitizeToolSchema(schema)
		}
		oaiTool := map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":       tool["name"],
				"parameters": params,
			},
		}
		if desc, ok := tool["description"].(string); ok {
			oaiTool["function"].(map[string]any)["description"] = desc
		}
		out = append(out, oaiTool)
	}
	return out
}

// sanitizeToolSchema recursively strips JSON Schema fields that OpenAI rejects.
// Currently strips: "format":"uri" (and other format values that cause issues).
func sanitizeToolSchema(schema map[string]any) map[string]any {
	// Strip problematic format values
	if f, ok := schema["format"].(string); ok {
		switch f {
		case "uri", "uri-reference", "iri", "iri-reference",
			"uri-template", "json-pointer", "relative-json-pointer",
			"regex", "idn-email", "idn-hostname":
			delete(schema, "format")
		}
	}

	// Recurse into properties
	if props, ok := schema["properties"].(map[string]any); ok {
		for key, val := range props {
			if propSchema, ok := val.(map[string]any); ok {
				props[key] = sanitizeToolSchema(propSchema)
			}
		}
	}

	// Recurse into items (array schemas)
	if items, ok := schema["items"].(map[string]any); ok {
		schema["items"] = sanitizeToolSchema(items)
	}

	// Recurse into additionalProperties
	if ap, ok := schema["additionalProperties"].(map[string]any); ok {
		schema["additionalProperties"] = sanitizeToolSchema(ap)
	}

	// Recurse into allOf/anyOf/oneOf
	for _, key := range []string{"allOf", "anyOf", "oneOf"} {
		if arr, ok := schema[key].([]any); ok {
			for i, item := range arr {
				if itemSchema, ok := item.(map[string]any); ok {
					arr[i] = sanitizeToolSchema(itemSchema)
				}
			}
		}
	}

	return schema
}

func convertClaudeToolChoiceToOpenAI(tc any) any {
	if tc == nil {
		return nil
	}
	// String values
	if s, ok := tc.(string); ok {
		switch s {
		case "auto":
			return "auto"
		case "any":
			return "required"
		case "none":
			return "none"
		}
	}
	// Object form: {"type": "auto"}, {"type": "any"}, {"type": "tool", "name": "..."}
	if obj, ok := tc.(map[string]any); ok {
		tcType, _ := obj["type"].(string)
		switch tcType {
		case "auto":
			return "auto"
		case "any":
			return "required"
		case "tool":
			return map[string]any{
				"type": "function",
				"function": map[string]any{
					"name": obj["name"],
				},
			}
		}
	}
	return "auto"
}

// --- OpenAI -> Claude request translation ---

func translateOpenAIReqToClaude(body []byte) ([]byte, error) {
	var oai map[string]any
	if err := json.Unmarshal(body, &oai); err != nil {
		return nil, fmt.Errorf("parse openai request: %w", err)
	}

	claude := map[string]any{}

	// model
	if m, ok := oai["model"].(string); ok {
		claude["model"] = m
	}

	// Build messages, extracting system messages
	var systemParts []string
	var claudeMsgs []map[string]any

	if rawMsgs, ok := oai["messages"].([]any); ok {
		// First pass: collect system messages and group tool results
		for _, rm := range rawMsgs {
			m, ok := rm.(map[string]any)
			if !ok {
				continue
			}
			role, _ := m["role"].(string)

			switch role {
			case "system":
				if c, ok := m["content"].(string); ok {
					systemParts = append(systemParts, c)
				}
			case "tool":
				// Tool results in Claude go as user messages with tool_result content blocks
				block := map[string]any{
					"type":        "tool_result",
					"tool_use_id": m["tool_call_id"],
					"content":     m["content"],
				}
				// Try to merge into previous user message if it has tool_result blocks
				if len(claudeMsgs) > 0 {
					last := claudeMsgs[len(claudeMsgs)-1]
					if lastRole, _ := last["role"].(string); lastRole == "user" {
						if lastContent, ok := last["content"].([]any); ok {
							last["content"] = append(lastContent, block)
							continue
						}
					}
				}
				claudeMsgs = append(claudeMsgs, map[string]any{
					"role":    "user",
					"content": []any{block},
				})
			case "assistant":
				claudeMsgs = append(claudeMsgs, convertOpenAIMsgToClaude(m))
			case "user":
				claudeMsgs = append(claudeMsgs, convertOpenAIUserMsgToClaude(m))
			}
		}
	}

	if len(systemParts) > 0 {
		claude["system"] = joinStrings(systemParts)
	}
	claude["messages"] = claudeMsgs

	// max_tokens - Claude requires this field
	if mt, ok := oai["max_tokens"]; ok {
		claude["max_tokens"] = mt
	} else if mt, ok := oai["max_completion_tokens"]; ok {
		claude["max_tokens"] = mt
	} else {
		claude["max_tokens"] = 8192
	}

	// Direct copy
	for _, key := range []string{"temperature", "top_p"} {
		if v, ok := oai[key]; ok {
			claude[key] = v
		}
	}

	// stop -> stop_sequences
	if stop, ok := oai["stop"]; ok {
		switch v := stop.(type) {
		case string:
			claude["stop_sequences"] = []string{v}
		default:
			claude["stop_sequences"] = v
		}
	}

	// stream
	if s, ok := oai["stream"].(bool); ok {
		claude["stream"] = s
	}

	// tools
	if tools, ok := oai["tools"].([]any); ok && len(tools) > 0 {
		claude["tools"] = convertOpenAIToolsToClaude(tools)
	}

	// tool_choice
	if tc, ok := oai["tool_choice"]; ok {
		claude["tool_choice"] = convertOpenAIToolChoiceToClaude(tc)
	}

	return json.Marshal(claude)
}

func convertOpenAIMsgToClaude(m map[string]any) map[string]any {
	msg := map[string]any{"role": "assistant"}

	// Check for tool_calls
	toolCalls, hasTC := m["tool_calls"].([]any)

	content := m["content"]
	var blocks []any

	// Add text content if present (string form)
	if s, ok := content.(string); ok && s != "" {
		blocks = append(blocks, map[string]any{"type": "text", "text": s})
	}

	// Handle multimodal content array (e.g., from OpenAI responses with images)
	if parts, ok := content.([]any); ok {
		for _, p := range parts {
			part, ok := p.(map[string]any)
			if !ok {
				continue
			}
			partType, _ := part["type"].(string)
			switch partType {
			case "text":
				if t, ok := part["text"].(string); ok && t != "" {
					blocks = append(blocks, map[string]any{"type": "text", "text": t})
				}
			case "image_url":
				// Convert OpenAI image_url to Claude image block
				if imgURL, ok := part["image_url"].(map[string]any); ok {
					if block := convertImageURLToClaude(imgURL); block != nil {
						blocks = append(blocks, block)
					}
				}
			}
		}
	}

	// Add reasoning_content as thinking block if present
	if rc, ok := m["reasoning_content"].(string); ok && rc != "" {
		// Prepend thinking block before other content
		thinkBlock := map[string]any{"type": "thinking", "thinking": rc}
		blocks = append([]any{thinkBlock}, blocks...)
	}

	// Add tool_use blocks from tool_calls
	if hasTC {
		for _, tc := range toolCalls {
			call, ok := tc.(map[string]any)
			if !ok {
				continue
			}
			fn, _ := call["function"].(map[string]any)
			if fn == nil {
				continue
			}
			block := map[string]any{
				"type": "tool_use",
				"id":   call["id"],
				"name": fn["name"],
			}
			// Parse arguments string to object
			if argsStr, ok := fn["arguments"].(string); ok {
				var args any
				if err := json.Unmarshal([]byte(argsStr), &args); err == nil {
					block["input"] = args
				} else {
					block["input"] = map[string]any{}
				}
			} else if args, ok := fn["arguments"].(map[string]any); ok {
				block["input"] = args
			} else {
				block["input"] = map[string]any{}
			}
			blocks = append(blocks, block)
		}
	}

	if len(blocks) > 0 {
		msg["content"] = blocks
	} else {
		// Preserve original content (string or null)
		msg["content"] = content
	}

	return msg
}

// convertOpenAIUserMsgToClaude converts an OpenAI user message to Claude format,
// handling both string and multimodal content arrays.
func convertOpenAIUserMsgToClaude(m map[string]any) map[string]any {
	content := m["content"]
	// String content: pass through
	if _, ok := content.(string); ok {
		return map[string]any{"role": "user", "content": content}
	}
	// Multimodal content array
	if parts, ok := content.([]any); ok {
		var blocks []any
		for _, p := range parts {
			part, ok := p.(map[string]any)
			if !ok {
				continue
			}
			partType, _ := part["type"].(string)
			switch partType {
			case "text":
				if t, ok := part["text"].(string); ok && t != "" {
					blocks = append(blocks, map[string]any{"type": "text", "text": t})
				}
			case "image_url":
				if imgURL, ok := part["image_url"].(map[string]any); ok {
					if block := convertImageURLToClaude(imgURL); block != nil {
						blocks = append(blocks, block)
					}
				}
			}
		}
		if len(blocks) > 0 {
			return map[string]any{"role": "user", "content": blocks}
		}
	}
	return map[string]any{"role": "user", "content": content}
}

// convertImageURLToClaude converts an OpenAI image_url object to a Claude image block.
// Handles data URIs (data:image/png;base64,...) by extracting media_type and data.
func convertImageURLToClaude(imgURL map[string]any) map[string]any {
	urlStr, _ := imgURL["url"].(string)
	if urlStr == "" {
		return nil
	}
	// Handle data URIs: data:image/png;base64,iVBOR...
	if strings.HasPrefix(urlStr, "data:") {
		// Parse: data:<media_type>;base64,<data>
		rest := urlStr[5:] // strip "data:"
		semiIdx := strings.Index(rest, ";")
		if semiIdx < 0 {
			return nil
		}
		mediaType := rest[:semiIdx]
		after := rest[semiIdx+1:]
		if !strings.HasPrefix(after, "base64,") {
			return nil
		}
		data := after[7:] // strip "base64,"
		return map[string]any{
			"type": "image",
			"source": map[string]any{
				"type":       "base64",
				"media_type": mediaType,
				"data":       data,
			},
		}
	}
	// For regular URLs, use Claude's URL source type
	return map[string]any{
		"type": "image",
		"source": map[string]any{
			"type": "url",
			"url":  urlStr,
		},
	}
}

func convertOpenAIToolsToClaude(tools []any) []map[string]any {
	var out []map[string]any
	for _, t := range tools {
		tool, ok := t.(map[string]any)
		if !ok {
			continue
		}
		fn, _ := tool["function"].(map[string]any)
		if fn == nil {
			continue
		}
		ct := map[string]any{
			"name":         fn["name"],
			"input_schema": fn["parameters"],
		}
		if desc, ok := fn["description"].(string); ok {
			ct["description"] = desc
		}
		out = append(out, ct)
	}
	return out
}

func convertOpenAIToolChoiceToClaude(tc any) any {
	if tc == nil {
		return nil
	}
	if s, ok := tc.(string); ok {
		switch s {
		case "auto":
			return map[string]any{"type": "auto"}
		case "required":
			return map[string]any{"type": "any"}
		case "none":
			return map[string]any{"type": "auto", "disable_parallel_tool_use": true}
		}
	}
	if obj, ok := tc.(map[string]any); ok {
		if fn, ok := obj["function"].(map[string]any); ok {
			return map[string]any{
				"type": "tool",
				"name": fn["name"],
			}
		}
	}
	return map[string]any{"type": "auto"}
}

// --- OpenAI -> Claude response translation ---

func translateOpenAIRespToClaude(body []byte, requestModel string) ([]byte, error) {
	var oai map[string]any
	if err := json.Unmarshal(body, &oai); err != nil {
		return nil, fmt.Errorf("parse openai response: %w", err)
	}

	id, _ := oai["id"].(string)
	model, _ := oai["model"].(string)
	if model == "" {
		model = requestModel
	}

	claude := map[string]any{
		"id":    id,
		"type":  "message",
		"role":  "assistant",
		"model": model,
	}

	// Convert choices to content blocks
	var content []map[string]any
	stopReason := "end_turn"

	if choices, ok := oai["choices"].([]any); ok && len(choices) > 0 {
		choice, _ := choices[0].(map[string]any)
		if choice != nil {
			if fr, ok := choice["finish_reason"].(string); ok {
				stopReason = oaiFinishReasonToClaude(fr)
			}
			if msg, ok := choice["message"].(map[string]any); ok {
				// Reasoning/thinking content (o1/o3 models)
				// Check reasoning_content (standard OpenAI field)
				if rc, ok := msg["reasoning_content"].(string); ok && rc != "" {
					content = append(content, map[string]any{
						"type":     "thinking",
						"thinking": rc,
					})
				}
				// Check reasoning_details (OpenRouter format)
				if rds, ok := msg["reasoning_details"].([]any); ok {
					for _, rd := range rds {
						if detail, ok := rd.(map[string]any); ok {
							if text := extractReasoningText(detail); text != "" {
								content = append(content, map[string]any{
									"type":     "thinking",
									"thinking": text,
								})
							}
						}
					}
				}

				// Text content
				if c, ok := msg["content"].(string); ok && c != "" {
					content = append(content, map[string]any{"type": "text", "text": c})
				}
				// Tool calls
				if tcs, ok := msg["tool_calls"].([]any); ok {
					for _, tc := range tcs {
						call, ok := tc.(map[string]any)
						if !ok {
							continue
						}
						fn, _ := call["function"].(map[string]any)
						if fn == nil {
							continue
						}
						block := map[string]any{
							"type": "tool_use",
							"id":   call["id"],
							"name": fn["name"],
						}
						if argsStr, ok := fn["arguments"].(string); ok {
							var args any
							if err := json.Unmarshal([]byte(argsStr), &args); err == nil {
								block["input"] = args
							} else {
								block["input"] = map[string]any{}
							}
						} else {
							block["input"] = fn["arguments"]
						}
						content = append(content, block)
					}
					if stopReason == "end_turn" {
						stopReason = "tool_use"
					}
				}
			}
		}
	}

	if len(content) == 0 {
		content = []map[string]any{{"type": "text", "text": ""}}
	}
	claude["content"] = content
	claude["stop_reason"] = stopReason

	// Usage
	if usage, ok := oai["usage"].(map[string]any); ok {
		claudeUsage := map[string]any{
			"input_tokens":  toInt64(usage["prompt_tokens"]),
			"output_tokens": toInt64(usage["completion_tokens"]),
		}
		if ct, ok := usage["prompt_tokens_details"].(map[string]any); ok {
			if cached, ok := ct["cached_tokens"]; ok {
				claudeUsage["cache_read_input_tokens"] = toInt64(cached)
			}
		}
		claude["usage"] = claudeUsage
	}

	return json.Marshal(claude)
}

// --- Claude -> OpenAI response translation ---

func translateClaudeRespToOpenAI(body []byte) ([]byte, error) {
	var claude map[string]any
	if err := json.Unmarshal(body, &claude); err != nil {
		return nil, fmt.Errorf("parse claude response: %w", err)
	}

	id, _ := claude["id"].(string)
	model, _ := claude["model"].(string)

	oai := map[string]any{
		"id":      id,
		"object":  "chat.completion",
		"model":   model,
		"choices": []any{},
	}

	// Convert content blocks to message
	msg := map[string]any{"role": "assistant"}
	var textParts []string
	var thinkingParts []string
	var toolCalls []map[string]any

	if blocks, ok := claude["content"].([]any); ok {
		for _, b := range blocks {
			block, ok := b.(map[string]any)
			if !ok {
				continue
			}
			blockType, _ := block["type"].(string)
			switch blockType {
			case "text":
				if t, ok := block["text"].(string); ok {
					textParts = append(textParts, t)
				}
			case "thinking":
				if t, ok := block["thinking"].(string); ok && t != "" {
					thinkingParts = append(thinkingParts, t)
				}
			case "tool_use":
				tc := map[string]any{
					"id":   block["id"],
					"type": "function",
					"function": map[string]any{
						"name":      block["name"],
						"arguments": marshalToolInput(block["input"]),
					},
				}
				toolCalls = append(toolCalls, tc)
			}
		}
	}

	if len(textParts) > 0 {
		msg["content"] = joinStrings(textParts)
	} else {
		msg["content"] = nil
	}
	if len(thinkingParts) > 0 {
		msg["reasoning_content"] = joinStrings(thinkingParts)
	}
	if len(toolCalls) > 0 {
		msg["tool_calls"] = toolCalls
	}

	finishReason := "stop"
	if sr, ok := claude["stop_reason"].(string); ok {
		finishReason = claudeStopReasonToOAI(sr)
	}

	choice := map[string]any{
		"index":         0,
		"message":       msg,
		"finish_reason": finishReason,
	}
	oai["choices"] = []any{choice}

	// Usage
	if usage, ok := claude["usage"].(map[string]any); ok {
		oai["usage"] = map[string]any{
			"prompt_tokens":     toInt64(usage["input_tokens"]),
			"completion_tokens": toInt64(usage["output_tokens"]),
			"total_tokens":      toInt64(usage["input_tokens"]) + toInt64(usage["output_tokens"]),
		}
	}

	return json.Marshal(oai)
}

// --- Finish reason mapping ---

func oaiFinishReasonToClaude(fr string) string {
	switch fr {
	case "stop":
		return "end_turn"
	case "length":
		return "max_tokens"
	case "tool_calls":
		return "tool_use"
	case "content_filter":
		return "end_turn"
	default:
		return "end_turn"
	}
}

func claudeStopReasonToOAI(sr string) string {
	switch sr {
	case "end_turn":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	case "stop_sequence":
		return "stop"
	default:
		return "stop"
	}
}

// extractReasoningText pulls text from an OpenAI/OpenRouter reasoning detail object.
// Supports three formats: {type:"reasoning.text", text:"..."}, {type:"reasoning.summary", summary:"..."},
// and {type:"reasoning.encrypted", ...} which is skipped.
func extractReasoningText(detail map[string]any) string {
	detailType, _ := detail["type"].(string)
	switch detailType {
	case "reasoning.text", "text":
		if t, ok := detail["text"].(string); ok {
			return t
		}
	case "reasoning.summary", "summary":
		if s, ok := detail["summary"].(string); ok {
			return s
		}
	case "reasoning.encrypted":
		return "" // Skip encrypted reasoning
	default:
		// Try text field as fallback
		if t, ok := detail["text"].(string); ok {
			return t
		}
	}
	return ""
}

// --- Cross-format model detection ---

// isOpenAIModel returns true if the model name looks like an OpenAI model.
func isOpenAIModel(model string) bool {
	m := strings.ToLower(model)
	// Strip thinking suffix e.g. "gpt-4o(16384)"
	if idx := strings.LastIndex(m, "("); idx > 0 {
		m = m[:idx]
	}
	prefixes := []string{
		"gpt-", "o1", "o3", "o4", "chatgpt-",
		"text-davinci", "text-embedding", "dall-e",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(m, p) {
			return true
		}
	}
	// Codex CLI models
	if strings.Contains(m, "codex") {
		return true
	}
	return false
}

// isClaudeModel returns true if the model name looks like an Anthropic Claude model.
// claudeCanonicalModel maps short Claude model names to their full API model IDs.
func claudeCanonicalModel(model string) string {
	raw := strings.TrimSpace(model)
	if raw == "" {
		return model
	}
	lower := strings.ToLower(raw)
	if idx := strings.LastIndex(lower, "("); idx > 0 {
		raw = strings.TrimSpace(raw[:idx])
		lower = strings.TrimSpace(lower[:idx])
	}

	has1M := strings.Contains(lower, "[1m]")
	baseRaw := strings.TrimSpace(strings.ReplaceAll(raw, "[1m]", ""))
	baseLower := strings.TrimSpace(strings.ReplaceAll(lower, "[1m]", ""))

	var canonical string
	if strings.HasPrefix(baseLower, "claude") {
		canonical = baseRaw
	} else {
		switch baseLower {
		case "opus":
			canonical = "claude-opus-4-7"
		case "sonnet":
			canonical = "claude-sonnet-4-6"
		case "haiku":
			canonical = "claude-haiku-4-5-20251001"
		default:
			return model
		}
	}

	if has1M {
		return canonical + " [1m]"
	}
	return canonical
}

func isClaudeModel(model string) bool {
	m := strings.ToLower(model)
	if idx := strings.LastIndex(m, "("); idx > 0 {
		m = m[:idx]
	}
	if strings.HasPrefix(m, "claude") {
		return true
	}
	// Match tier keywords (sonnet, opus, haiku) that are Claude-specific
	for _, kw := range []string{"sonnet", "opus", "haiku"} {
		if strings.Contains(m, kw) {
			return true
		}
	}
	return false
}

// --- Helpers ---

func joinStrings(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += "\n\n" + parts[i]
	}
	return result
}

func toInt64(v any) int64 {
	if v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	}
	return 0
}

// generateToolCallID produces a simple unique-ish ID for tool calls
// when translating from Claude to OpenAI format.
var translateCallCounter int64

func generateToolCallID() string {
	translateCallCounter++
	return fmt.Sprintf("call_%d", translateCallCounter)
}

// logTranslation logs format translation at debug level.
func logTranslation(reqID string, direction TranslateDirection, debug bool) {
	if !debug {
		return
	}
	switch direction {
	case TranslateClaudeToOAI:
		log.Printf("[%s] format translation: claude -> openai", reqID)
	case TranslateOAIToClaude:
		log.Printf("[%s] format translation: openai -> claude", reqID)
	case TranslateChatToResponses:
		log.Printf("[%s] format translation: chat completions -> responses api", reqID)
	case TranslateResponsesToClaude:
		log.Printf("[%s] format translation: responses api -> claude", reqID)
	case TranslateClaudeToResponses:
		log.Printf("[%s] format translation: claude -> responses api", reqID)
	}
}

func claudeModelEntry(slug, displayName string, contextWindow int) map[string]any {
	return map[string]any{
		"slug":                           slug,
		"display_name":                   displayName,
		"description":                    displayName + " via Codex Pool",
		"prefer_websockets":              false,
		"support_verbosity":              false,
		"default_verbosity":              nil,
		"default_reasoning_level":        "high",
		"default_reasoning_summary":      "none",
		"apply_patch_tool_type":          "freeform",
		"web_search_tool_type":           "text",
		"shell_type":                     "shell_command",
		"input_modalities":               []string{"text", "image"},
		"supports_image_detail_original": false,
		"supports_parallel_tool_calls":   true,
		"supports_reasoning_summaries":   false,
		"supports_search_tool":           false,
		"supported_in_api":               true,
		"supported_reasoning_levels":     []any{},
		"experimental_supported_tools":   []any{},
		"truncation_policy":              map[string]any{"mode": "tokens", "limit": 10000},
		"context_window":                 contextWindow,
		"priority":                       100,
		"visibility":                     "list",
		"availability_nux":               nil,
		"available_in_plans":             []string{"plus", "pro", "team", "enterprise", "business"},
		"minimal_client_version":         "0.1.0",
		"reasoning_summary_format":       "none",
		"model_messages":                 nil,
		"base_instructions":              "",
		"upgrade":                        nil,
	}
}

// injectClaudeModels adds Claude model entries to the Codex model catalog response
// so that `codex -m opus` (and sonnet/haiku) don't produce "Model metadata not found" warnings.
func injectClaudeModels(body []byte) []byte {
	// Decompress gzip if needed (upstream may return compressed data when
	// client's Accept-Encoding header is forwarded)
	actualBody := body
	if len(body) > 2 && body[0] == 0x1f && body[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err == nil {
			decompressed, err := io.ReadAll(gr)
			gr.Close()
			if err == nil {
				actualBody = decompressed
			}
		}
	}

	var catalog map[string]any
	if err := json.Unmarshal(actualBody, &catalog); err != nil {
		return body
	}
	models, ok := catalog["models"].([]any)
	if !ok {
		return body
	}

	claudeModels := []map[string]any{
		claudeModelEntry("opus", "Claude Opus 4.7", 200000),
		claudeModelEntry("opus[1m]", "Claude Opus 4.7 [1m]", 1000000),
		claudeModelEntry("sonnet", "Claude Sonnet 4.6", 200000),
		claudeModelEntry("sonnet[1m]", "Claude Sonnet 4.6 [1m]", 1000000),
		claudeModelEntry("haiku", "Claude Haiku 4.5", 200000),
	}

	for _, cm := range claudeModels {
		models = append(models, cm)
	}
	catalog["models"] = models

	out, err := json.Marshal(catalog)
	if err != nil {
		return body
	}
	return out
}
