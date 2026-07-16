package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
)

// sseTranslateWriter intercepts upstream SSE events, translates them to the
// target format, and writes the translated events to the client. It also
// forwards original event data to a usage callback for usage tracking.
type sseTranslateWriter struct {
	w         io.Writer          // underlying writer (flushWriter)
	direction TranslateDirection // which way to translate
	state     streamTranslationState
	buf       []byte
	callback  func([]byte) // called with original event data for usage parsing
	debug     bool
	reqID     string
}

type streamTranslationState struct {
	messageStarted    bool
	contentBlockIndex int
	toolCallIndex     int
	currentToolID     string
	currentToolName   string
	sentRole          bool
	sentThinking      bool // whether we've emitted a thinking content_block_start
	sentText          bool // whether we've emitted a text content_block_start
	finishReason      string
	model             string
	id                string
	inputTokens       int64
	outputTokens      int64
	cachedInputTokens int64
}

func (sw *sseTranslateWriter) Write(p []byte) (int, error) {
	origLen := len(p)
	sw.buf = append(sw.buf, p...)
	sw.scanAndTranslate()
	return origLen, nil
}

func (sw *sseTranslateWriter) scanAndTranslate() {
	for {
		// Find end of SSE event
		idx := bytes.Index(sw.buf, []byte("\n\n"))
		advance := 2
		if idx < 0 {
			idx = bytes.Index(sw.buf, []byte("\r\n\r\n"))
			advance = 4
			if idx < 0 {
				if len(sw.buf) > 1024*1024 {
					sw.buf = sw.buf[len(sw.buf)-512*1024:]
				}
				return
			}
		}

		event := sw.buf[:idx]
		sw.buf = sw.buf[idx+advance:]
		sw.processEvent(event)
	}
}

func (sw *sseTranslateWriter) processEvent(event []byte) {
	eventType, data := parseSSEEvent(event)

	// Forward original data to usage callback
	if len(data) > 0 && sw.callback != nil && !bytes.Equal(data, []byte("[DONE]")) {
		sw.callback(data)
	}

	switch sw.direction {
	case TranslateOAIToClaude:
		sw.translateOAIEventToClaude(eventType, data)
	case TranslateClaudeToOAI:
		sw.translateClaudeEventToOAI(eventType, data)
	}
}

// --- OpenAI Stream -> Claude Stream ---

func (sw *sseTranslateWriter) translateOAIEventToClaude(eventType string, data []byte) {
	if len(data) == 0 {
		return
	}
	if bytes.Equal(data, []byte("[DONE]")) {
		// Emit final events if not already done
		if sw.state.messageStarted {
			sw.emitClaudeContentBlockStop()
			sw.emitClaudeMessageDelta()
			sw.emitClaudeEvent("message_stop", `{"type":"message_stop"}`)
		}
		return
	}

	var chunk map[string]any
	if err := json.Unmarshal(data, &chunk); err != nil {
		return
	}

	// Extract ID and model
	if id, ok := chunk["id"].(string); ok && id != "" {
		sw.state.id = id
	}
	if model, ok := chunk["model"].(string); ok && model != "" {
		sw.state.model = model
	}

	// Handle usage in final chunk
	if usage, ok := chunk["usage"].(map[string]any); ok {
		sw.state.inputTokens = toInt64(usage["prompt_tokens"])
		sw.state.outputTokens = toInt64(usage["completion_tokens"])
		if details, ok := usage["prompt_tokens_details"].(map[string]any); ok {
			sw.state.cachedInputTokens = toInt64(details["cached_tokens"])
		}
	}

	choices, ok := chunk["choices"].([]any)
	if !ok || len(choices) == 0 {
		return
	}
	choice, _ := choices[0].(map[string]any)
	if choice == nil {
		return
	}

	// Check finish reason
	if fr, ok := choice["finish_reason"].(string); ok && fr != "" {
		sw.state.finishReason = oaiFinishReasonToClaude(fr)
	}

	delta, _ := choice["delta"].(map[string]any)
	if delta == nil {
		return
	}

	// First chunk with role - emit message_start
	if role, ok := delta["role"].(string); ok && role != "" && !sw.state.messageStarted {
		sw.state.messageStarted = true
		sw.emitClaudeMessageStart()
	}

	// Reasoning/thinking content (o1/o3 models, OpenRouter)
	reasoningText := ""
	if rc, ok := delta["reasoning_content"].(string); ok && rc != "" {
		reasoningText = rc
	} else if rc, ok := delta["reasoning"].(string); ok && rc != "" {
		reasoningText = rc
	}
	if reasoningText != "" {
		if !sw.state.sentThinking {
			sw.state.sentThinking = true
			sw.state.sentRole = true
			sw.emitClaudeEvent("content_block_start", fmt.Sprintf(
				`{"type":"content_block_start","index":%d,"content_block":{"type":"thinking","thinking":""}}`,
				sw.state.contentBlockIndex))
		}
		sw.emitClaudeEvent("content_block_delta", fmt.Sprintf(
			`{"type":"content_block_delta","index":%d,"delta":{"type":"thinking_delta","thinking":%s}}`,
			sw.state.contentBlockIndex, mustMarshalString(reasoningText)))
	}

	// Text content
	if content, ok := delta["content"].(string); ok && content != "" {
		if !sw.state.sentText {
			// Close thinking block if it was open, then start text block
			if sw.state.sentThinking {
				sw.emitClaudeContentBlockStop()
				sw.state.contentBlockIndex++
			}
			sw.state.sentText = true
			sw.state.sentRole = true
			sw.emitClaudeEvent("content_block_start", fmt.Sprintf(
				`{"type":"content_block_start","index":%d,"content_block":{"type":"text","text":""}}`,
				sw.state.contentBlockIndex))
		}
		sw.emitClaudeEvent("content_block_delta", fmt.Sprintf(
			`{"type":"content_block_delta","index":%d,"delta":{"type":"text_delta","text":%s}}`,
			sw.state.contentBlockIndex, mustMarshalString(content)))
	}

	// Tool calls
	if tcs, ok := delta["tool_calls"].([]any); ok {
		for _, tc := range tcs {
			call, ok := tc.(map[string]any)
			if !ok {
				continue
			}
			fn, _ := call["function"].(map[string]any)

			// New tool call (has name)
			if fn != nil {
				if name, ok := fn["name"].(string); ok && name != "" {
					// Close previous content block if any
					if sw.state.sentRole {
						sw.emitClaudeContentBlockStop()
						sw.state.contentBlockIndex++
					}
					sw.state.sentRole = true

					toolID := ""
					if id, ok := call["id"].(string); ok {
						toolID = id
					}
					sw.state.currentToolID = toolID
					sw.state.currentToolName = name
					sw.state.toolCallIndex++

					sw.emitClaudeEvent("content_block_start", fmt.Sprintf(
						`{"type":"content_block_start","index":%d,"content_block":{"type":"tool_use","id":%s,"name":%s,"input":{}}}`,
						sw.state.contentBlockIndex, mustMarshalString(toolID), mustMarshalString(name)))
				}
			}

			// Tool call arguments delta
			if fn != nil {
				if args, ok := fn["arguments"].(string); ok && args != "" {
					sw.emitClaudeEvent("content_block_delta", fmt.Sprintf(
						`{"type":"content_block_delta","index":%d,"delta":{"type":"input_json_delta","partial_json":%s}}`,
						sw.state.contentBlockIndex, mustMarshalString(args)))
				}
			}
		}
	}
}

func (sw *sseTranslateWriter) emitClaudeMessageStart() {
	model := sw.state.model
	if model == "" {
		model = "unknown"
	}
	id := sw.state.id
	if id == "" {
		id = "msg_translated"
	}
	msg := fmt.Sprintf(`{"type":"message_start","message":{"id":%s,"type":"message","role":"assistant","model":%s,"content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":0,"output_tokens":0}}}`,
		mustMarshalString(id), mustMarshalString(model))
	sw.emitClaudeEvent("message_start", msg)
}

func (sw *sseTranslateWriter) emitClaudeContentBlockStop() {
	sw.emitClaudeEvent("content_block_stop", fmt.Sprintf(
		`{"type":"content_block_stop","index":%d}`, sw.state.contentBlockIndex))
}

func (sw *sseTranslateWriter) emitClaudeMessageDelta() {
	stopReason := sw.state.finishReason
	if stopReason == "" {
		stopReason = "end_turn"
	}
	msg := fmt.Sprintf(`{"type":"message_delta","delta":{"stop_reason":%s,"stop_sequence":null},"usage":{"output_tokens":%d}}`,
		mustMarshalString(stopReason), sw.state.outputTokens)
	sw.emitClaudeEvent("message_delta", msg)
}

func (sw *sseTranslateWriter) emitClaudeEvent(eventType, data string) {
	out := fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, data)
	if _, err := sw.w.Write([]byte(out)); err != nil {
		if sw.debug {
			log.Printf("[%s] translate write error: %v", sw.reqID, err)
		}
	}
}

// --- Claude Stream -> OpenAI Stream ---

func (sw *sseTranslateWriter) translateClaudeEventToOAI(eventType string, data []byte) {
	if len(data) == 0 {
		return
	}

	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return
	}

	evType, _ := obj["type"].(string)
	if eventType == "" {
		eventType = evType
	}

	switch eventType {
	case "message_start":
		msg, _ := obj["message"].(map[string]any)
		if msg != nil {
			if id, ok := msg["id"].(string); ok {
				sw.state.id = id
			}
			if model, ok := msg["model"].(string); ok {
				sw.state.model = model
			}
			if usage, ok := msg["usage"].(map[string]any); ok {
				sw.state.inputTokens = toInt64(usage["input_tokens"])
			}
		}
		sw.state.messageStarted = true
		// Emit initial role chunk
		sw.emitOAIChunk(map[string]any{"role": "assistant", "content": ""}, nil)

	case "content_block_start":
		block, _ := obj["content_block"].(map[string]any)
		if block == nil {
			return
		}
		blockType, _ := block["type"].(string)
		if blockType == "thinking" {
			// Track that we're in a thinking block (reasoning content goes in delta)
			sw.state.sentThinking = true
			return
		}
		if blockType == "tool_use" {
			id, _ := block["id"].(string)
			name, _ := block["name"].(string)
			sw.state.currentToolID = id
			sw.state.currentToolName = name
			sw.state.toolCallIndex++
			idx := sw.state.toolCallIndex - 1
			sw.emitOAIChunk(map[string]any{
				"tool_calls": []any{
					map[string]any{
						"index": idx,
						"id":    id,
						"type":  "function",
						"function": map[string]any{
							"name":      name,
							"arguments": "",
						},
					},
				},
			}, nil)
		}

	case "content_block_delta":
		delta, _ := obj["delta"].(map[string]any)
		if delta == nil {
			return
		}
		deltaType, _ := delta["type"].(string)
		switch deltaType {
		case "thinking_delta":
			thinking, _ := delta["thinking"].(string)
			if thinking != "" {
				sw.emitOAIChunk(map[string]any{"reasoning_content": thinking}, nil)
			}
			return
		case "text_delta":
			text, _ := delta["text"].(string)
			if text != "" {
				sw.emitOAIChunk(map[string]any{"content": text}, nil)
			}
		case "input_json_delta":
			partial, _ := delta["partial_json"].(string)
			if partial != "" {
				idx := sw.state.toolCallIndex - 1
				if idx < 0 {
					idx = 0
				}
				sw.emitOAIChunk(map[string]any{
					"tool_calls": []any{
						map[string]any{
							"index": idx,
							"function": map[string]any{
								"arguments": partial,
							},
						},
					},
				}, nil)
			}
		}

	case "content_block_stop":
		// If this is a thinking block stop, just clear the flag
		if sw.state.sentThinking {
			sw.state.sentThinking = false
			return
		}
		// No other action needed for OpenAI format

	case "message_delta":
		delta, _ := obj["delta"].(map[string]any)
		if delta == nil {
			return
		}
		stopReason := ""
		if sr, ok := delta["stop_reason"].(string); ok {
			stopReason = claudeStopReasonToOAI(sr)
		}
		// Get output usage
		if usage, ok := obj["usage"].(map[string]any); ok {
			sw.state.outputTokens = toInt64(usage["output_tokens"])
		}
		// Emit final chunk with finish_reason and usage
		usage := map[string]any{
			"prompt_tokens":     sw.state.inputTokens,
			"completion_tokens": sw.state.outputTokens,
			"total_tokens":      sw.state.inputTokens + sw.state.outputTokens,
		}
		sw.emitOAIChunkWithFinish(map[string]any{}, stopReason, usage)

	case "message_stop":
		sw.writeOAI("data: [DONE]\n\n")

	case "ping":
		// Ignore pings
	}
}

func (sw *sseTranslateWriter) emitOAIChunk(delta map[string]any, usage map[string]any) {
	sw.emitOAIChunkWithFinish(delta, "", usage)
}

func (sw *sseTranslateWriter) emitOAIChunkWithFinish(delta map[string]any, finishReason string, usage map[string]any) {
	id := sw.state.id
	if id == "" {
		id = "chatcmpl-translated"
	}
	model := sw.state.model
	if model == "" {
		model = "unknown"
	}

	chunk := map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"model":   model,
		"choices": []any{},
	}

	choiceObj := map[string]any{
		"index": 0,
		"delta": delta,
	}
	if finishReason != "" {
		choiceObj["finish_reason"] = finishReason
	} else {
		choiceObj["finish_reason"] = nil
	}
	chunk["choices"] = []any{choiceObj}

	if usage != nil {
		chunk["usage"] = usage
	}

	b, err := json.Marshal(chunk)
	if err != nil {
		return
	}
	sw.writeOAI(fmt.Sprintf("data: %s\n\n", string(b)))
}

func (sw *sseTranslateWriter) writeOAI(s string) {
	if _, err := sw.w.Write([]byte(s)); err != nil {
		if sw.debug {
			log.Printf("[%s] translate write error: %v", sw.reqID, err)
		}
	}
}

func mustMarshalString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
