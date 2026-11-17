package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
)

type sseTranslateWriter struct {
	sseEventBuffer
	err            error
	w              io.Writer
	direction      TranslateDirection
	finishOnReason bool // Mistral may omit the [DONE] sentinel
	openAI         openAIStreamState
	claude         claudeStreamState
	blocks         claudeBlockState
	callback       func([]byte)
	debug          bool
	reqID          string
}

type openAIStreamState struct {
	finishReason string
	model        string
	id           string
	outputTokens int64
}

type claudeStreamState struct {
	model         string
	id            string
	inputTokens   int64
	outputTokens  int64
	toolCallIndex int
}

type claudeBlockState struct {
	messageStarted    bool
	messageFinished   bool
	contentBlockIndex int
	toolBlocks        map[int]int
	toolBlockOrder    []int
	sentRole          bool
	sentThinking      bool
	sentText          bool
}

func (sw *sseTranslateWriter) Write(p []byte) (int, error) {
	return sw.sseEventBuffer.writeEvents(p, sw.processEvent, &sw.err)
}

func (sw *sseTranslateWriter) processEvent(event []byte) {
	eventType, data := parseSSEEvent(event)

	if len(data) > 0 && sw.callback != nil && !bytes.Equal(data, []byte("[DONE]")) {
		sw.callback(data)
	}

	switch sw.direction {
	case TranslateOAIToClaude:
		sw.translateOAIEventToClaude(data)
	case TranslateClaudeToOAI:
		sw.translateClaudeEventToOAI(eventType, data)
	}
}

func (sw *sseTranslateWriter) translateOAIEventToClaude(data []byte) {
	emitter := claudeBlockEmitter{emit: sw.emitClaudeEvent}
	if len(data) == 0 {
		return
	}
	if bytes.Equal(data, []byte("[DONE]")) {
		if sw.blocks.messageStarted && !sw.blocks.messageFinished {
			sw.stopClaudeBlocks()
			sw.emitClaudeMessageDelta()
			sw.emitClaudeEvent("message_stop", `{"type":"message_stop"}`)
			sw.blocks.messageFinished = true
		}
		return
	}

	var chunk map[string]any
	if err := json.Unmarshal(data, &chunk); err != nil {
		return
	}

	if id, ok := chunk["id"].(string); ok && id != "" {
		sw.openAI.id = id
	}
	if model, ok := chunk["model"].(string); ok && model != "" {
		sw.openAI.model = model
	}

	if usage, ok := chunk["usage"].(map[string]any); ok {
		sw.openAI.outputTokens = toInt64(usage["completion_tokens"])
	}

	choices, ok := chunk["choices"].([]any)
	if !ok || len(choices) == 0 {
		return
	}
	choice, _ := choices[0].(map[string]any)
	if choice == nil {
		return
	}

	if fr, ok := choice["finish_reason"].(string); ok && fr != "" {
		sw.openAI.finishReason = oaiFinishReasonToClaude(fr)
		// Mistral's last chunk carries both finish_reason and usage. Close the
		// Messages stream here; some upstream relays omit the optional [DONE].
		defer func() {
			if !sw.finishOnReason || !sw.blocks.messageStarted || sw.blocks.messageFinished {
				return
			}
			sw.stopClaudeBlocks()
			sw.emitClaudeMessageDelta()
			sw.emitClaudeEvent("message_stop", `{"type":"message_stop"}`)
			sw.blocks.messageFinished = true
		}()
	}

	delta, _ := choice["delta"].(map[string]any)
	if delta == nil {
		return
	}

	if role, ok := delta["role"].(string); ok && role != "" && !sw.blocks.messageStarted {
		sw.blocks.messageStarted = true
		sw.emitClaudeMessageStart()
	}

	// Reasoning/thinking content (o1/o3 models and typed Mistral chunks).
	reasoningText := ""
	if rc, ok := delta["reasoning_content"].(string); ok && rc != "" {
		reasoningText = rc
	} else if rc, ok := delta["reasoning"].(string); ok && rc != "" {
		reasoningText = rc
	}
	typedText, typedThinking := openAITypedDeltaContent(delta["content"])
	if reasoningText == "" {
		reasoningText = typedThinking
	}
	if reasoningText != "" {
		if !sw.blocks.messageStarted {
			sw.blocks.messageStarted = true
			sw.emitClaudeMessageStart()
		}
		if !sw.blocks.sentThinking {
			sw.blocks.sentThinking = true
			sw.blocks.sentRole = true
			emitter.thinkingStart(sw.blocks.contentBlockIndex)
		}
		emitter.thinking(sw.blocks.contentBlockIndex, reasoningText)
	}

	textContent, _ := delta["content"].(string)
	if textContent == "" {
		textContent = typedText
	}
	if textContent != "" {
		if !sw.blocks.messageStarted {
			sw.blocks.messageStarted = true
			sw.emitClaudeMessageStart()
		}
		if !sw.blocks.sentText {
			if sw.blocks.sentThinking {
				sw.emitClaudeContentBlockStop()
				sw.blocks.contentBlockIndex++
			}
			sw.blocks.sentText = true
			sw.blocks.sentRole = true
			emitter.textStart(sw.blocks.contentBlockIndex)
		}
		emitter.text(sw.blocks.contentBlockIndex, textContent)
	}

	if tcs, ok := delta["tool_calls"].([]any); ok {
		for _, tc := range tcs {
			call, ok := tc.(map[string]any)
			if !ok {
				continue
			}
			fn, _ := call["function"].(map[string]any)
			if fn == nil {
				continue
			}
			upstreamIndex := int(toInt64(call["index"]))
			blockIndex, started := sw.blocks.toolBlocks[upstreamIndex]
			name, _ := fn["name"].(string)
			if !started && name != "" {
				if !sw.blocks.messageStarted {
					sw.blocks.messageStarted = true
					sw.emitClaudeMessageStart()
				}
				if sw.blocks.sentRole {
					// Parallel tools remain open: later deltas can target any index.
					if len(sw.blocks.toolBlocks) == 0 {
						sw.emitClaudeContentBlockStop()
					}
					sw.blocks.contentBlockIndex++
				}
				sw.blocks.sentRole = true
				blockIndex = sw.blocks.contentBlockIndex
				if sw.blocks.toolBlocks == nil {
					sw.blocks.toolBlocks = make(map[int]int)
				}
				sw.blocks.toolBlocks[upstreamIndex] = blockIndex
				sw.blocks.toolBlockOrder = append(sw.blocks.toolBlockOrder, blockIndex)
				started = true
				toolID, _ := call["id"].(string)
				emitter.toolStart(blockIndex, toolID, name)
			}
			if args, _ := fn["arguments"].(string); started && args != "" {
				emitter.arguments(blockIndex, args)
			}
		}
	}
}

func openAITypedDeltaContent(value any) (text, thinking string) {
	parts, ok := value.([]any)
	if !ok {
		return "", ""
	}
	for _, raw := range parts {
		part, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		switch partType, _ := part["type"].(string); partType {
		case "text":
			if value, _ := part["text"].(string); value != "" {
				text += value
			}
		case "thinking", "reasoning":
			thinking += mistralThinkingText(part["thinking"])
		}
	}
	return text, thinking
}

func (sw *sseTranslateWriter) emitClaudeMessageStart() {
	emitter := claudeBlockEmitter{emit: sw.emitClaudeEvent}
	emitter.messageStart(sw.openAI.id, sw.openAI.model, 0)
}

func (sw *sseTranslateWriter) stopClaudeBlocks() {
	emitter := claudeBlockEmitter{emit: sw.emitClaudeEvent}
	if len(sw.blocks.toolBlockOrder) > 0 {
		for _, index := range sw.blocks.toolBlockOrder {
			emitter.stop(index)
		}
		return
	}
	if sw.blocks.sentRole {
		sw.emitClaudeContentBlockStop()
	}
}

func (sw *sseTranslateWriter) emitClaudeContentBlockStop() {
	emitter := claudeBlockEmitter{emit: sw.emitClaudeEvent}
	emitter.stop(sw.blocks.contentBlockIndex)
}

func (sw *sseTranslateWriter) emitClaudeMessageDelta() {
	stopReason := sw.openAI.finishReason
	if stopReason == "" {
		stopReason = "end_turn"
	}
	msg := fmt.Sprintf(`{"type":"message_delta","delta":{"stop_reason":%s,"stop_sequence":null},"usage":{"output_tokens":%d}}`,
		mustMarshalString(stopReason), sw.openAI.outputTokens)
	sw.emitClaudeEvent("message_delta", msg)
}

func (sw *sseTranslateWriter) emitClaudeEvent(eventType, data string) {
	out := fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, data)
	sw.writeOAI(out)
}

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
				sw.claude.id = id
			}
			if model, ok := msg["model"].(string); ok {
				sw.claude.model = model
			}
			if usage, ok := msg["usage"].(map[string]any); ok {
				sw.claude.inputTokens = toInt64(usage["input_tokens"])
			}
		}
		sw.emitOAIChunk(map[string]any{"role": "assistant", "content": ""}, nil)

	case "content_block_start":
		block, _ := obj["content_block"].(map[string]any)
		if block == nil {
			return
		}
		blockType, _ := block["type"].(string)
		if blockType == "tool_use" {
			id, _ := block["id"].(string)
			name, _ := block["name"].(string)
			sw.claude.toolCallIndex++
			idx := sw.claude.toolCallIndex - 1
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
				idx := sw.claude.toolCallIndex - 1
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

	case "message_delta":
		delta, _ := obj["delta"].(map[string]any)
		if delta == nil {
			return
		}
		stopReason := ""
		if sr, ok := delta["stop_reason"].(string); ok {
			stopReason = claudeStopReasonToOAI(sr)
		}
		if usage, ok := obj["usage"].(map[string]any); ok {
			sw.claude.outputTokens = toInt64(usage["output_tokens"])
		}
		usage := map[string]any{
			"prompt_tokens":     sw.claude.inputTokens,
			"completion_tokens": sw.claude.outputTokens,
			"total_tokens":      sw.claude.inputTokens + sw.claude.outputTokens,
		}
		sw.emitOAIChunkWithFinish(map[string]any{}, stopReason, usage)

	case "message_stop":
		sw.writeOAI("data: [DONE]\n\n")

	case "ping":
	}
}

func (sw *sseTranslateWriter) emitOAIChunk(delta map[string]any, usage map[string]any) {
	sw.emitOAIChunkWithFinish(delta, "", usage)
}

func (sw *sseTranslateWriter) emitOAIChunkWithFinish(delta map[string]any, finishReason string, usage map[string]any) {
	id := sw.claude.id
	if id == "" {
		id = "chatcmpl-translated"
	}
	model := sw.claude.model
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
	writeSSE(sw.w, []byte(s), &sw.err)
	if sw.err != nil && sw.debug {
		log.Printf("[%s] translate write error: %v", sw.reqID, sw.err)
	}
}

func mustMarshalString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
