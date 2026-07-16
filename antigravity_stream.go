package main

// Streaming conversion is derived in part from CLIProxyAPI's Antigravity
// translators, distributed under the MIT License.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
)

type antigravityStreamWriter struct {
	w                       io.Writer
	format                  antigravityClientFormat
	model                   string
	buf                     []byte
	started                 bool
	finished                bool
	contentIndex            int
	responseID              string
	messageID               string
	sequence                int
	usage                   antigravityResult
	responsesMessageStarted bool
	responsesMessageIndex   int
	responsesText           strings.Builder
	responsesOutput         map[int]any
	responsesCreatedAt      int64
	responsesReasoningOpen  bool
	responsesReasoningDone  bool
	responsesReasoningID    string
	responsesReasoningIndex int
	responsesReasoningText  strings.Builder
	responsesReasoningSig   string
	responsesMessageCount   int
	responsesRequest        map[string]any
	responsesFunctionNames  map[string]string
}

func newAntigravityStreamWriter(w io.Writer, format antigravityClientFormat, model string) *antigravityStreamWriter {
	return &antigravityStreamWriter{w: w, format: format, model: model, responseID: "resp_" + uuid.NewString(), messageID: "msg_" + uuid.NewString(), responsesOutput: make(map[int]any)}
}

// setResponsesRequest supplies the original Responses request fields that the
// completed event echoes. It is intentionally optional for non-Responses users.
func (sw *antigravityStreamWriter) setResponsesRequest(request map[string]any) {
	sw.responsesRequest = request
}

func (sw *antigravityStreamWriter) setResponsesFunctionNames(functionNames map[string]string) {
	sw.responsesFunctionNames = functionNames
}

func (sw *antigravityStreamWriter) Write(p []byte) (int, error) {
	n := len(p)
	sw.buf = append(sw.buf, p...)
	for {
		idx, advance := bytes.Index(sw.buf, []byte("\n\n")), 2
		if idx < 0 {
			idx = bytes.Index(sw.buf, []byte("\r\n\r\n"))
			advance = 4
		}
		if idx < 0 {
			break
		}
		event := sw.buf[:idx]
		sw.buf = sw.buf[idx+advance:]
		_, data := parseSSEEvent(event)
		if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
			continue
		}
		if err := sw.translate(data); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (sw *antigravityStreamWriter) translate(data []byte) error {
	gemini, err := unwrapAntigravityResponse(data)
	if err != nil {
		return err
	}
	if sw.format == antigravityFormatGemini {
		return sw.emitData(gemini)
	}
	var obj map[string]any
	if err := json.Unmarshal(gemini, &obj); err != nil {
		return err
	}
	r := parseAntigravityGeminiResponse(obj)
	sw.usage = r
	switch sw.format {
	case antigravityFormatChat:
		return sw.emitOpenAI(r)
	case antigravityFormatResponses:
		return sw.emitResponses(r)
	case antigravityFormatAnthropic:
		return sw.emitClaude(r)
	default:
		return fmt.Errorf("unsupported antigravity stream format %q", sw.format)
	}
}

func (sw *antigravityStreamWriter) emitOpenAI(r antigravityResult) error {
	delta := map[string]any{}
	if !sw.started {
		delta["role"] = "assistant"
		sw.started = true
	}
	if r.Text != "" {
		delta["content"] = r.Text
	}
	if r.Reasoning != "" {
		delta["reasoning_content"] = r.Reasoning
		if r.ReasoningSignature != "" {
			delta["reasoning_signature"] = r.ReasoningSignature
		}
	}
	if len(r.Tools) > 0 {
		var calls []any
		for i, call := range r.Tools {
			args, _ := json.Marshal(call["args"])
			id := stringValue(call["id"])
			if id == "" {
				id = fmt.Sprintf("call_%d_%s", i, uuid.NewString())
			}
			calls = append(calls, map[string]any{"index": i, "id": id, "type": "function", "function": map[string]any{"name": call["name"], "arguments": string(args)}})
		}
		delta["tool_calls"] = calls
	}
	if len(r.Images) > 0 {
		var images []any
		for _, image := range r.Images {
			images = append(images, map[string]any{"type": "image_url", "image_url": map[string]any{"url": antigravityImageDataURL(image)}})
		}
		delta["images"] = images
	}
	finish := any(nil)
	if r.FinishReason != "" {
		finish = antigravityOpenAIFinishReason(r.FinishReason, len(r.Tools) > 0)
		sw.finished = true
	}
	chunk := map[string]any{"id": "chatcmpl-" + sw.responseID, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": sw.model, "choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}}}
	if r.PromptTokens+r.OutputTokens > 0 {
		chunk["usage"] = antigravityOpenAIUsage(r)
	}
	if err := sw.emitJSON(chunk); err != nil {
		return err
	}
	if sw.finished {
		return sw.emitRaw("data: [DONE]\n\n")
	}
	return nil
}

func (sw *antigravityStreamWriter) emitResponses(r antigravityResult) error {
	if !sw.started {
		if r.ResponseID != "" {
			sw.responseID = r.ResponseID
			if !strings.HasPrefix(sw.responseID, "resp_") {
				sw.responseID = "resp_" + sw.responseID
			}
		}
		sw.responsesCreatedAt = time.Now().Unix()
		if !r.CreateTime.IsZero() {
			sw.responsesCreatedAt = r.CreateTime.Unix()
		}
		sw.started = true
		base := map[string]any{"id": sw.responseID, "object": "response", "created_at": sw.responsesCreatedAt, "status": "in_progress", "background": false, "error": nil, "model": sw.model, "output": []any{}}
		if err := sw.emitResponsesEvent("response.created", map[string]any{"type": "response.created", "sequence_number": sw.nextSequence(), "response": base}); err != nil {
			return err
		}
		if err := sw.emitResponsesEvent("response.in_progress", map[string]any{"type": "response.in_progress", "sequence_number": sw.nextSequence(), "response": map[string]any{"id": sw.responseID, "object": "response", "created_at": sw.responsesCreatedAt, "status": "in_progress"}}); err != nil {
			return err
		}
	}
	parts := r.Parts
	if len(parts) == 0 {
		if r.Reasoning != "" || r.ReasoningSignature != "" {
			parts = append(parts, antigravityResponsePart{Kind: "reasoning", Text: r.Reasoning, Signature: r.ReasoningSignature})
		}
		if r.Text != "" {
			parts = append(parts, antigravityResponsePart{Kind: "text", Text: r.Text})
		}
		for _, call := range r.Tools {
			parts = append(parts, antigravityResponsePart{Kind: "tool", Tool: call})
		}
		for _, image := range r.Images {
			parts = append(parts, antigravityResponsePart{Kind: "image", Image: image})
		}
	}
	for _, part := range parts {
		switch part.Kind {
		case "reasoning":
			if sw.responsesReasoningDone {
				continue
			}
			if part.Signature != "" && part.Signature != "skip_thought_signature_validator" {
				sw.responsesReasoningSig = part.Signature
			}
			if err := sw.ensureResponsesReasoning(); err != nil {
				return err
			}
			if part.Text != "" {
				sw.responsesReasoningText.WriteString(part.Text)
				if err := sw.emitResponsesEvent("response.reasoning_summary_text.delta", map[string]any{"type": "response.reasoning_summary_text.delta", "sequence_number": sw.nextSequence(), "item_id": sw.responsesReasoningID, "output_index": sw.responsesReasoningIndex, "summary_index": 0, "delta": part.Text}); err != nil {
					return err
				}
			}
		case "text":
			if err := sw.finalizeResponsesReasoning(); err != nil {
				return err
			}
			if err := sw.ensureResponsesMessage(); err != nil {
				return err
			}
			if err := sw.emitResponsesEvent("response.output_text.delta", map[string]any{"type": "response.output_text.delta", "sequence_number": sw.nextSequence(), "item_id": sw.messageID, "output_index": sw.responsesMessageIndex, "content_index": 0, "delta": part.Text, "logprobs": []any{}}); err != nil {
				return err
			}
			sw.responsesText.WriteString(part.Text)
		case "tool":
			if err := sw.finalizeResponsesReasoning(); err != nil {
				return err
			}
			if err := sw.finalizeResponsesMessage(); err != nil {
				return err
			}
			if err := sw.emitResponsesTool(part.Tool); err != nil {
				return err
			}
		case "image":
			if err := sw.finalizeResponsesReasoning(); err != nil {
				return err
			}
			if err := sw.finalizeResponsesMessage(); err != nil {
				return err
			}
			if err := sw.emitResponsesImage(part.Image); err != nil {
				return err
			}
		}
	}
	if r.FinishReason != "" && !sw.finished {
		sw.finished = true
		if err := sw.finalizeResponsesReasoning(); err != nil {
			return err
		}
		if err := sw.finalizeResponsesMessage(); err != nil {
			return err
		}
		output := make([]any, 0, len(sw.responsesOutput))
		for index := 0; index < sw.contentIndex; index++ {
			if item, exists := sw.responsesOutput[index]; exists {
				output = append(output, item)
			}
		}
		response := map[string]any{"id": sw.responseID, "object": "response", "created_at": sw.responsesCreatedAt, "status": "completed", "background": false, "error": nil, "incomplete_details": nil, "model": sw.model, "output": output, "usage": map[string]any{"input_tokens": r.PromptTokens, "output_tokens": r.OutputTokens, "total_tokens": r.TotalTokens, "input_tokens_details": map[string]any{"cached_tokens": r.CachedTokens}, "output_tokens_details": map[string]any{"reasoning_tokens": r.ReasoningTokens}}}
		for _, field := range []string{"instructions", "max_output_tokens", "max_tool_calls", "parallel_tool_calls", "previous_response_id", "prompt_cache_key", "reasoning", "safety_identifier", "service_tier", "store", "temperature", "text", "tool_choice", "tools", "top_logprobs", "top_p", "truncation", "user", "metadata"} {
			if value, exists := sw.responsesRequest[field]; exists {
				response[field] = value
			}
		}
		return sw.emitResponsesEvent("response.completed", map[string]any{"type": "response.completed", "sequence_number": sw.nextSequence(), "response": response})
	}
	return nil
}

func (sw *antigravityStreamWriter) emitResponsesTool(call map[string]any) error {
	callID := stringValue(call["id"])
	if callID == "" {
		callID = "call_" + uuid.NewString()
	}
	itemID := "fc_" + uuid.NewString()
	args := []byte("{}")
	if call["args"] != nil {
		args, _ = json.Marshal(call["args"])
	}
	name := stringValue(call["name"])
	if original := sw.responsesFunctionNames[name]; original != "" {
		name = original
	}
	item := map[string]any{"id": itemID, "type": "function_call", "status": "in_progress", "call_id": callID, "name": name, "arguments": ""}
	if err := sw.emitResponsesEvent("response.output_item.added", map[string]any{"type": "response.output_item.added", "sequence_number": sw.nextSequence(), "output_index": sw.contentIndex, "item": item}); err != nil {
		return err
	}
	if err := sw.emitResponsesEvent("response.function_call_arguments.delta", map[string]any{"type": "response.function_call_arguments.delta", "sequence_number": sw.nextSequence(), "item_id": itemID, "output_index": sw.contentIndex, "delta": string(args)}); err != nil {
		return err
	}
	if err := sw.emitResponsesEvent("response.function_call_arguments.done", map[string]any{"type": "response.function_call_arguments.done", "sequence_number": sw.nextSequence(), "item_id": itemID, "output_index": sw.contentIndex, "arguments": string(args)}); err != nil {
		return err
	}
	item["status"] = "completed"
	item["arguments"] = string(args)
	if err := sw.emitResponsesEvent("response.output_item.done", map[string]any{"type": "response.output_item.done", "sequence_number": sw.nextSequence(), "output_index": sw.contentIndex, "item": item}); err != nil {
		return err
	}
	sw.responsesOutput[sw.contentIndex] = item
	sw.contentIndex++
	return nil
}

func (sw *antigravityStreamWriter) emitResponsesImage(image map[string]any) error {
	item := map[string]any{"id": "img_" + uuid.NewString(), "type": "output_image", "status": "completed", "image_url": antigravityImageDataURL(image)}
	if err := sw.emitResponsesEvent("response.output_item.added", map[string]any{"type": "response.output_item.added", "sequence_number": sw.nextSequence(), "output_index": sw.contentIndex, "item": item}); err != nil {
		return err
	}
	if err := sw.emitResponsesEvent("response.output_item.done", map[string]any{"type": "response.output_item.done", "sequence_number": sw.nextSequence(), "output_index": sw.contentIndex, "item": item}); err != nil {
		return err
	}
	sw.responsesOutput[sw.contentIndex] = item
	sw.contentIndex++
	return nil
}

func (sw *antigravityStreamWriter) ensureResponsesMessage() error {
	if sw.responsesMessageStarted {
		return nil
	}
	sw.responsesMessageStarted = true
	sw.messageID = fmt.Sprintf("msg_%s_%d", sw.responseID, sw.responsesMessageCount)
	sw.responsesMessageCount++
	sw.responsesText.Reset()
	sw.responsesMessageIndex = sw.contentIndex
	sw.contentIndex++
	item := map[string]any{"id": sw.messageID, "type": "message", "status": "in_progress", "role": "assistant", "content": []any{}}
	if err := sw.emitResponsesEvent("response.output_item.added", map[string]any{"type": "response.output_item.added", "sequence_number": sw.nextSequence(), "output_index": sw.responsesMessageIndex, "item": item}); err != nil {
		return err
	}
	part := map[string]any{"type": "output_text", "text": "", "annotations": []any{}, "logprobs": []any{}}
	return sw.emitResponsesEvent("response.content_part.added", map[string]any{"type": "response.content_part.added", "sequence_number": sw.nextSequence(), "item_id": sw.messageID, "output_index": sw.responsesMessageIndex, "content_index": 0, "part": part})
}

func (sw *antigravityStreamWriter) ensureResponsesReasoning() error {
	if sw.responsesReasoningOpen {
		return nil
	}
	sw.responsesReasoningOpen = true
	sw.responsesReasoningIndex = sw.contentIndex
	sw.contentIndex++
	sw.responsesReasoningID = fmt.Sprintf("rs_%s_%d", sw.responseID, sw.responsesReasoningIndex)
	item := map[string]any{"id": sw.responsesReasoningID, "type": "reasoning", "status": "in_progress", "encrypted_content": sw.responsesReasoningSig, "summary": []any{}}
	if err := sw.emitResponsesEvent("response.output_item.added", map[string]any{"type": "response.output_item.added", "sequence_number": sw.nextSequence(), "output_index": sw.responsesReasoningIndex, "item": item}); err != nil {
		return err
	}
	part := map[string]any{"type": "summary_text", "text": ""}
	return sw.emitResponsesEvent("response.reasoning_summary_part.added", map[string]any{"type": "response.reasoning_summary_part.added", "sequence_number": sw.nextSequence(), "item_id": sw.responsesReasoningID, "output_index": sw.responsesReasoningIndex, "summary_index": 0, "part": part})
}

func (sw *antigravityStreamWriter) finalizeResponsesReasoning() error {
	if !sw.responsesReasoningOpen || sw.responsesReasoningDone {
		return nil
	}
	text := sw.responsesReasoningText.String()
	if err := sw.emitResponsesEvent("response.reasoning_summary_text.done", map[string]any{"type": "response.reasoning_summary_text.done", "sequence_number": sw.nextSequence(), "item_id": sw.responsesReasoningID, "output_index": sw.responsesReasoningIndex, "summary_index": 0, "text": text}); err != nil {
		return err
	}
	part := map[string]any{"type": "summary_text", "text": text}
	if err := sw.emitResponsesEvent("response.reasoning_summary_part.done", map[string]any{"type": "response.reasoning_summary_part.done", "sequence_number": sw.nextSequence(), "item_id": sw.responsesReasoningID, "output_index": sw.responsesReasoningIndex, "summary_index": 0, "part": part}); err != nil {
		return err
	}
	item := map[string]any{"id": sw.responsesReasoningID, "type": "reasoning", "encrypted_content": sw.responsesReasoningSig, "summary": []any{part}}
	if err := sw.emitResponsesEvent("response.output_item.done", map[string]any{"type": "response.output_item.done", "sequence_number": sw.nextSequence(), "output_index": sw.responsesReasoningIndex, "item": item}); err != nil {
		return err
	}
	sw.responsesOutput[sw.responsesReasoningIndex] = item
	sw.responsesReasoningDone = true
	return nil
}

func (sw *antigravityStreamWriter) finalizeResponsesMessage() error {
	if !sw.responsesMessageStarted {
		return nil
	}
	text := sw.responsesText.String()
	if err := sw.emitResponsesEvent("response.output_text.done", map[string]any{"type": "response.output_text.done", "sequence_number": sw.nextSequence(), "item_id": sw.messageID, "output_index": sw.responsesMessageIndex, "content_index": 0, "text": text, "logprobs": []any{}}); err != nil {
		return err
	}
	part := map[string]any{"type": "output_text", "text": text, "annotations": []any{}, "logprobs": []any{}}
	if err := sw.emitResponsesEvent("response.content_part.done", map[string]any{"type": "response.content_part.done", "sequence_number": sw.nextSequence(), "item_id": sw.messageID, "output_index": sw.responsesMessageIndex, "content_index": 0, "part": part}); err != nil {
		return err
	}
	item := map[string]any{"id": sw.messageID, "type": "message", "status": "completed", "role": "assistant", "content": []any{part}}
	if err := sw.emitResponsesEvent("response.output_item.done", map[string]any{"type": "response.output_item.done", "sequence_number": sw.nextSequence(), "output_index": sw.responsesMessageIndex, "item": item}); err != nil {
		return err
	}
	sw.responsesOutput[sw.responsesMessageIndex] = item
	sw.responsesMessageStarted = false
	return nil
}

func (sw *antigravityStreamWriter) emitClaude(r antigravityResult) error {
	if !sw.started {
		sw.started = true
		start := map[string]any{"type": "message_start", "message": map[string]any{"id": sw.messageID, "type": "message", "role": "assistant", "model": sw.model, "content": []any{}, "stop_reason": nil, "stop_sequence": nil, "usage": map[string]any{"input_tokens": r.PromptTokens, "output_tokens": 0}}}
		if err := sw.emitClaudeEvent("message_start", start); err != nil {
			return err
		}
	}
	if r.Reasoning != "" {
		idx := sw.contentIndex
		block := map[string]any{"type": "thinking", "thinking": ""}
		if r.ReasoningSignature != "" {
			block["signature"] = r.ReasoningSignature
		}
		if err := sw.emitClaudeEvent("content_block_start", map[string]any{"type": "content_block_start", "index": idx, "content_block": block}); err != nil {
			return err
		}
		if err := sw.emitClaudeEvent("content_block_delta", map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": "thinking_delta", "thinking": r.Reasoning}}); err != nil {
			return err
		}
		if r.ReasoningSignature != "" {
			if err := sw.emitClaudeEvent("content_block_delta", map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": "signature_delta", "signature": r.ReasoningSignature}}); err != nil {
				return err
			}
		}
		if err := sw.emitClaudeEvent("content_block_stop", map[string]any{"type": "content_block_stop", "index": idx}); err != nil {
			return err
		}
		sw.contentIndex++
	}
	if r.Text != "" {
		idx := sw.contentIndex
		if err := sw.emitClaudeEvent("content_block_start", map[string]any{"type": "content_block_start", "index": idx, "content_block": map[string]any{"type": "text", "text": ""}}); err != nil {
			return err
		}
		if err := sw.emitClaudeEvent("content_block_delta", map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": "text_delta", "text": r.Text}}); err != nil {
			return err
		}
		if err := sw.emitClaudeEvent("content_block_stop", map[string]any{"type": "content_block_stop", "index": idx}); err != nil {
			return err
		}
		sw.contentIndex++
	}
	for _, call := range r.Tools {
		idx := sw.contentIndex
		id := stringValue(call["id"])
		if id == "" {
			id = "toolu_" + uuid.NewString()
		}
		args, _ := json.Marshal(call["args"])
		if err := sw.emitClaudeEvent("content_block_start", map[string]any{"type": "content_block_start", "index": idx, "content_block": map[string]any{"type": "tool_use", "id": id, "name": call["name"], "input": map[string]any{}}}); err != nil {
			return err
		}
		if err := sw.emitClaudeEvent("content_block_delta", map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": "input_json_delta", "partial_json": string(args)}}); err != nil {
			return err
		}
		if err := sw.emitClaudeEvent("content_block_stop", map[string]any{"type": "content_block_stop", "index": idx}); err != nil {
			return err
		}
		sw.contentIndex++
	}
	for _, image := range r.Images {
		idx := sw.contentIndex
		block := map[string]any{"type": "image", "source": map[string]any{"type": "base64", "media_type": image["mimeType"], "data": image["data"]}}
		if err := sw.emitClaudeEvent("content_block_start", map[string]any{"type": "content_block_start", "index": idx, "content_block": block}); err != nil {
			return err
		}
		if err := sw.emitClaudeEvent("content_block_stop", map[string]any{"type": "content_block_stop", "index": idx}); err != nil {
			return err
		}
		sw.contentIndex++
	}
	if r.FinishReason != "" && !sw.finished {
		sw.finished = true
		if err := sw.emitClaudeEvent("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": antigravityClaudeFinishReason(r.FinishReason, len(r.Tools) > 0), "stop_sequence": nil}, "usage": map[string]any{"output_tokens": r.OutputTokens}}); err != nil {
			return err
		}
		return sw.emitClaudeEvent("message_stop", map[string]any{"type": "message_stop"})
	}
	return nil
}

func (sw *antigravityStreamWriter) nextSequence() int { sw.sequence++; return sw.sequence }
func (sw *antigravityStreamWriter) emitResponsesEvent(event string, obj map[string]any) error {
	raw, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return sw.emitRaw("event: " + event + "\ndata: " + string(raw) + "\n\n")
}
func (sw *antigravityStreamWriter) emitClaudeEvent(event string, obj map[string]any) error {
	raw, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return sw.emitRaw("event: " + event + "\ndata: " + string(raw) + "\n\n")
}
func (sw *antigravityStreamWriter) emitJSON(obj map[string]any) error {
	raw, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return sw.emitData(raw)
}
func (sw *antigravityStreamWriter) emitData(data []byte) error {
	return sw.emitRaw("data: " + string(data) + "\n\n")
}
func (sw *antigravityStreamWriter) emitRaw(s string) error {
	_, err := io.WriteString(sw.w, s)
	return err
}

func antigravityStreamContentType(format antigravityClientFormat) string {
	if format == antigravityFormatGemini || format == antigravityFormatChat {
		return "text/event-stream"
	}
	return "text/event-stream; charset=utf-8"
}
func isAntigravitySSEContentType(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/event-stream")
}
