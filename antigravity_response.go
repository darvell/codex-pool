package main

// Response conversion is derived in part from CLIProxyAPI's Antigravity
// translators, distributed under the MIT License.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

func unwrapAntigravityResponse(body []byte) ([]byte, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	if response := envelope["response"]; len(response) > 0 && !bytes.Equal(response, []byte("null")) {
		return response, nil
	}
	return body, nil
}

func translateAntigravityResponse(body []byte, format antigravityClientFormat, requestModel string) ([]byte, error) {
	return translateAntigravityResponseWithRequest(body, format, requestModel, nil, nil)
}

func translateAntigravityResponseWithRequest(body []byte, format antigravityClientFormat, requestModel string, responsesRequest map[string]any, responsesFunctionNames map[string]string) ([]byte, error) {
	gemini, err := unwrapAntigravityResponse(body)
	if err != nil {
		return nil, fmt.Errorf("unwrap antigravity response: %w", err)
	}
	if format == antigravityFormatGemini {
		return gemini, nil
	}
	var response map[string]any
	if err := json.Unmarshal(gemini, &response); err != nil {
		return nil, err
	}
	switch format {
	case antigravityFormatChat:
		return json.Marshal(antigravityGeminiToOpenAI(response, requestModel))
	case antigravityFormatResponses:
		return json.Marshal(antigravityGeminiToResponsesWithRequest(response, requestModel, responsesRequest, responsesFunctionNames))
	case antigravityFormatAnthropic:
		return json.Marshal(antigravityGeminiToClaude(response, requestModel))
	default:
		return nil, fmt.Errorf("unsupported antigravity client format %q", format)
	}
}

type antigravityResult struct {
	Text               string
	Reasoning          string
	ReasoningSignature string
	Tools              []map[string]any
	Images             []map[string]any
	FinishReason       string
	PromptTokens       int64
	OutputTokens       int64
	ReasoningTokens    int64
	CachedTokens       int64
	TotalTokens        int64
	ResponseID         string
	CreateTime         time.Time
	Parts              []antigravityResponsePart
}

type antigravityResponsePart struct {
	Kind      string
	Text      string
	Signature string
	Tool      map[string]any
	Image     map[string]any
}

func parseAntigravityGeminiResponse(response map[string]any) antigravityResult {
	var result antigravityResult
	result.ResponseID = stringValue(response["responseId"])
	if raw := stringValue(response["createTime"]); raw != "" {
		result.CreateTime, _ = time.Parse(time.RFC3339Nano, raw)
	}
	candidates := anySlice(response["candidates"])
	if len(candidates) > 0 {
		candidate, _ := candidates[0].(map[string]any)
		result.FinishReason = stringValue(candidate["finishReason"])
		content, _ := candidate["content"].(map[string]any)
		for _, raw := range anySlice(content["parts"]) {
			part, _ := raw.(map[string]any)
			text, _ := part["text"].(string)
			if thought, _ := part["thought"].(bool); thought {
				sig := stringValue(part["thoughtSignature"])
				if sig == "" {
					sig = stringValue(part["thought_signature"])
				}
				if text != "" || sig != "" {
					result.Parts = append(result.Parts, antigravityResponsePart{Kind: "reasoning", Text: text, Signature: sig})
				}
				if text != "" {
					result.Reasoning += text
				}
				if sig != "" {
					result.ReasoningSignature = sig
				}
			} else if text != "" {
				result.Text += text
				result.Parts = append(result.Parts, antigravityResponsePart{Kind: "text", Text: text})
			}
			if call, _ := part["functionCall"].(map[string]any); call != nil {
				result.Tools = append(result.Tools, call)
				result.Parts = append(result.Parts, antigravityResponsePart{Kind: "tool", Tool: call})
			}
			if image, _ := part["inlineData"].(map[string]any); image != nil {
				result.Images = append(result.Images, image)
				result.Parts = append(result.Parts, antigravityResponsePart{Kind: "image", Image: image})
			}
		}
	}
	usage, _ := response["usageMetadata"].(map[string]any)
	result.PromptTokens = toInt64(usage["promptTokenCount"])
	result.OutputTokens = toInt64(usage["candidatesTokenCount"])
	result.ReasoningTokens = toInt64(usage["thoughtsTokenCount"])
	result.CachedTokens = toInt64(usage["cachedContentTokenCount"])
	result.TotalTokens = toInt64(usage["totalTokenCount"])
	if result.TotalTokens == 0 {
		result.TotalTokens = result.PromptTokens + result.OutputTokens
	}
	return result
}

func antigravityGeminiToOpenAI(response map[string]any, model string) map[string]any {
	r := parseAntigravityGeminiResponse(response)
	message := map[string]any{"role": "assistant", "content": r.Text}
	if r.Reasoning != "" {
		message["reasoning_content"] = r.Reasoning
		message["reasoning"] = r.Reasoning
	}
	if r.ReasoningSignature != "" {
		message["reasoning_signature"] = r.ReasoningSignature
	}
	if len(r.Tools) > 0 {
		calls := make([]any, 0, len(r.Tools))
		for i, call := range r.Tools {
			id := stringValue(call["id"])
			if id == "" {
				id = fmt.Sprintf("call_%d_%s", i, uuid.NewString())
			}
			args, _ := json.Marshal(call["args"])
			calls = append(calls, map[string]any{"id": id, "type": "function", "function": map[string]any{"name": call["name"], "arguments": string(args)}})
		}
		message["tool_calls"] = calls
	}
	if len(r.Images) > 0 {
		images := make([]any, 0, len(r.Images))
		for _, image := range r.Images {
			images = append(images, map[string]any{"type": "image_url", "image_url": map[string]any{"url": antigravityImageDataURL(image)}})
		}
		message["images"] = images
	}
	return map[string]any{"id": "chatcmpl-" + uuid.NewString(), "object": "chat.completion", "created": time.Now().Unix(), "model": model, "choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": antigravityOpenAIFinishReason(r.FinishReason, len(r.Tools) > 0)}}, "usage": antigravityOpenAIUsage(r)}
}

func antigravityGeminiToResponses(response map[string]any, model string) map[string]any {
	return antigravityGeminiToResponsesWithRequest(response, model, nil, nil)
}

func antigravityGeminiToResponsesWithRequest(response map[string]any, model string, request map[string]any, functionNames map[string]string) map[string]any {
	r := parseAntigravityGeminiResponse(response)
	id := r.ResponseID
	if id == "" {
		id = uuid.NewString()
	}
	if !strings.HasPrefix(id, "resp_") {
		id = "resp_" + id
	}
	createdAt := time.Now().Unix()
	if !r.CreateTime.IsZero() {
		createdAt = r.CreateTime.Unix()
	}
	output := antigravityResponsesOutput(r, functionNames)
	result := map[string]any{"id": id, "object": "response", "created_at": createdAt, "status": "completed", "background": false, "error": nil, "incomplete_details": nil, "model": model, "output": output, "usage": map[string]any{"input_tokens": r.PromptTokens, "output_tokens": r.OutputTokens, "total_tokens": r.TotalTokens, "input_tokens_details": map[string]any{"cached_tokens": r.CachedTokens}, "output_tokens_details": map[string]any{"reasoning_tokens": r.ReasoningTokens}}}
	for _, field := range []string{"instructions", "max_output_tokens", "max_tool_calls", "parallel_tool_calls", "previous_response_id", "prompt_cache_key", "reasoning", "safety_identifier", "service_tier", "store", "temperature", "text", "tool_choice", "tools", "top_logprobs", "top_p", "truncation", "user", "metadata"} {
		if value, exists := request[field]; exists {
			result[field] = value
		}
	}
	return result
}

func antigravityResponsesOutput(r antigravityResult, functionNames map[string]string) []any {
	parts := r.Parts
	if len(parts) == 0 {
		if r.Reasoning != "" || r.ReasoningSignature != "" {
			parts = append(parts, antigravityResponsePart{Kind: "reasoning", Text: r.Reasoning, Signature: r.ReasoningSignature})
		}
		if r.Text != "" {
			parts = append(parts, antigravityResponsePart{Kind: "text", Text: r.Text})
		}
		for _, image := range r.Images {
			parts = append(parts, antigravityResponsePart{Kind: "image", Image: image})
		}
		for _, call := range r.Tools {
			parts = append(parts, antigravityResponsePart{Kind: "tool", Tool: call})
		}
	}
	output := make([]any, 0, len(parts))
	var reasoning strings.Builder
	var reasoningSignature string
	var messageContent []any
	flushReasoning := func() {
		if reasoning.Len() == 0 && reasoningSignature == "" {
			return
		}
		item := map[string]any{"id": "rs_" + uuid.NewString(), "type": "reasoning", "summary": []any{map[string]any{"type": "summary_text", "text": reasoning.String()}}}
		if reasoningSignature != "" {
			item["encrypted_content"] = reasoningSignature
		}
		output = append(output, item)
		reasoning.Reset()
		reasoningSignature = ""
	}
	flushMessage := func() {
		if len(messageContent) == 0 {
			return
		}
		output = append(output, map[string]any{"id": "msg_" + uuid.NewString(), "type": "message", "status": "completed", "role": "assistant", "content": messageContent})
		messageContent = nil
	}
	toolIndex := 0
	for _, part := range parts {
		switch part.Kind {
		case "reasoning":
			flushMessage()
			reasoning.WriteString(part.Text)
			if part.Signature != "" && part.Signature != "skip_thought_signature_validator" {
				reasoningSignature = part.Signature
			}
		case "text":
			flushReasoning()
			messageContent = append(messageContent, map[string]any{"type": "output_text", "text": part.Text, "annotations": []any{}, "logprobs": []any{}})
		case "image":
			flushReasoning()
			messageContent = append(messageContent, map[string]any{"type": "output_image", "image_url": antigravityImageDataURL(part.Image)})
		case "tool":
			flushReasoning()
			flushMessage()
			callID := stringValue(part.Tool["id"])
			if callID == "" {
				callID = fmt.Sprintf("call_%d_%s", toolIndex, uuid.NewString())
			}
			args := []byte("{}")
			if part.Tool["args"] != nil {
				args, _ = json.Marshal(part.Tool["args"])
			}
			name := stringValue(part.Tool["name"])
			if original := functionNames[name]; original != "" {
				name = original
			}
			output = append(output, map[string]any{"id": "fc_" + uuid.NewString(), "type": "function_call", "status": "completed", "call_id": callID, "name": name, "arguments": string(args)})
			toolIndex++
		}
	}
	flushReasoning()
	flushMessage()
	return output
}

func antigravityGeminiToClaude(response map[string]any, model string) map[string]any {
	r := parseAntigravityGeminiResponse(response)
	var content []any
	if r.Reasoning != "" {
		block := map[string]any{"type": "thinking", "thinking": r.Reasoning}
		if r.ReasoningSignature != "" {
			block["signature"] = r.ReasoningSignature
		}
		content = append(content, block)
	}
	if r.Text != "" {
		content = append(content, map[string]any{"type": "text", "text": r.Text})
	}
	for i, call := range r.Tools {
		id := stringValue(call["id"])
		if id == "" {
			id = fmt.Sprintf("toolu_%d_%s", i, uuid.NewString())
		}
		content = append(content, map[string]any{"type": "tool_use", "id": id, "name": call["name"], "input": call["args"]})
	}
	for _, image := range r.Images {
		content = append(content, map[string]any{"type": "image", "source": map[string]any{"type": "base64", "media_type": image["mimeType"], "data": image["data"]}})
	}
	return map[string]any{"id": "msg_" + uuid.NewString(), "type": "message", "role": "assistant", "model": model, "content": content, "stop_reason": antigravityClaudeFinishReason(r.FinishReason, len(r.Tools) > 0), "stop_sequence": nil, "usage": map[string]any{"input_tokens": r.PromptTokens, "output_tokens": r.OutputTokens, "cache_read_input_tokens": r.CachedTokens}}
}

func antigravityOpenAIUsage(r antigravityResult) map[string]any {
	return map[string]any{"prompt_tokens": r.PromptTokens, "completion_tokens": r.OutputTokens, "total_tokens": r.TotalTokens, "prompt_tokens_details": map[string]any{"cached_tokens": r.CachedTokens}, "completion_tokens_details": map[string]any{"reasoning_tokens": r.ReasoningTokens}}
}
func antigravityOpenAIFinishReason(reason string, hasTools bool) string {
	if hasTools {
		return "tool_calls"
	}
	switch strings.ToUpper(reason) {
	case "MAX_TOKENS":
		return "length"
	case "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT":
		return "content_filter"
	default:
		return "stop"
	}
}
func antigravityClaudeFinishReason(reason string, hasTools bool) string {
	if hasTools {
		return "tool_use"
	}
	if strings.EqualFold(reason, "MAX_TOKENS") {
		return "max_tokens"
	}
	return "end_turn"
}
func antigravityImageDataURL(image map[string]any) string {
	return "data:" + stringValue(image["mimeType"]) + ";base64," + stringValue(image["data"])
}

func anySlice(value any) []any {
	items, _ := value.([]any)
	return items
}

func translateAntigravityError(body []byte, format antigravityClientFormat, status int) []byte {
	message := strings.TrimSpace(string(body))
	code := "api_error"
	var obj map[string]any
	if json.Unmarshal(body, &obj) == nil {
		errObj, _ := obj["error"].(map[string]any)
		if errObj != nil {
			if m := stringValue(errObj["message"]); m != "" {
				message = m
			}
			if c := stringValue(errObj["status"]); c != "" {
				code = strings.ToLower(c)
			}
		}
	}
	if message == "" {
		message = fmt.Sprintf("Antigravity upstream returned HTTP %d", status)
	}
	switch format {
	case antigravityFormatAnthropic:
		out, _ := json.Marshal(map[string]any{"type": "error", "error": map[string]any{"type": antigravityClaudeErrorType(status), "message": message}})
		return out
	case antigravityFormatGemini:
		return body
	default:
		out, _ := json.Marshal(map[string]any{"error": map[string]any{"message": message, "type": antigravityOpenAIErrorType(status), "code": code}})
		return out
	}
}
func antigravityOpenAIErrorType(status int) string {
	switch status {
	case 400, 404:
		return "invalid_request_error"
	case 401:
		return "authentication_error"
	case 403:
		return "permission_error"
	case 429:
		return "rate_limit_error"
	default:
		return "server_error"
	}
}
func antigravityClaudeErrorType(status int) string {
	switch status {
	case 400:
		return "invalid_request_error"
	case 401:
		return "authentication_error"
	case 403:
		return "permission_error"
	case 404:
		return "not_found_error"
	case 429:
		return "rate_limit_error"
	case 529:
		return "overloaded_error"
	default:
		return "api_error"
	}
}
