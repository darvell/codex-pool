package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
)

type responsesBufferingWriter struct {
	buf          []byte
	id           string
	model        string
	contentText  string
	inputTokens  int64
	outputTokens int64
	status       string
}

func (bw *responsesBufferingWriter) Write(p []byte) (int, error) {
	origLen := len(p)
	bw.buf = append(bw.buf, p...)
	bw.scanEvents()
	return origLen, nil
}

func (bw *responsesBufferingWriter) scanEvents() {
	for {
		idx := bytes.Index(bw.buf, []byte("\n\n"))
		advance := 2
		if idx < 0 {
			idx = bytes.Index(bw.buf, []byte("\r\n\r\n"))
			advance = 4
			if idx < 0 {
				return
			}
		}
		event := bw.buf[:idx]
		bw.buf = bw.buf[idx+advance:]
		bw.processEvent(event)
	}
}

func (bw *responsesBufferingWriter) processEvent(event []byte) {
	var eventType string
	var data []byte
	for _, line := range bytes.Split(event, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if bytes.HasPrefix(line, []byte("event:")) {
			eventType = string(bytes.TrimSpace(line[6:]))
		} else if bytes.HasPrefix(line, []byte("data: ")) {
			data = bytes.TrimSpace(line[6:])
		} else if bytes.HasPrefix(line, []byte("data:")) {
			data = bytes.TrimSpace(line[5:])
		}
	}
	if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
		return
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return
	}
	if eventType == "" {
		eventType, _ = obj["type"].(string)
	}
	switch eventType {
	case "response.created":
		bw.applyResponse(obj)
	case "response.output_text.delta":
		if delta, _ := obj["delta"].(string); delta != "" {
			bw.contentText += delta
		}
	case "response.completed":
		bw.applyResponse(obj)
		if bw.status == "" {
			bw.status = "completed"
		}
	case "response.failed":
		bw.applyResponse(obj)
		bw.status = "failed"
	}
}

func (bw *responsesBufferingWriter) applyResponse(obj map[string]any) {
	resp, _ := obj["response"].(map[string]any)
	if resp == nil {
		return
	}
	if id, _ := resp["id"].(string); id != "" {
		bw.id = id
	}
	if model, _ := resp["model"].(string); model != "" {
		bw.model = model
	}
	if status, _ := resp["status"].(string); status != "" {
		bw.status = status
	}
	if usage, _ := resp["usage"].(map[string]any); usage != nil {
		bw.inputTokens = toInt64(usage["input_tokens"])
		bw.outputTokens = toInt64(usage["output_tokens"])
	}
}

func (bw *responsesBufferingWriter) Result() []byte {
	id := bw.id
	if id == "" {
		id = "resp_translated"
	}
	model := bw.model
	if model == "" {
		model = "unknown"
	}
	status := bw.status
	if status == "" {
		status = "completed"
	}
	out := map[string]any{
		"id":         id,
		"object":     "response",
		"created_at": float64(0),
		"status":     status,
		"model":      model,
		"output": []any{
			map[string]any{
				"id":     "msg_" + id,
				"type":   "message",
				"status": status,
				"role":   "assistant",
				"content": []any{
					map[string]any{"type": "output_text", "text": bw.contentText, "annotations": []any{}},
				},
			},
		},
		"usage": map[string]any{
			"input_tokens":  bw.inputTokens,
			"output_tokens": bw.outputTokens,
			"total_tokens":  bw.inputTokens + bw.outputTokens,
		},
	}
	b, _ := json.Marshal(out)
	return b
}

// responsesToChatCompletionsWriter intercepts upstream Responses API SSE events
// and translates them to OpenAI Chat Completions streaming format.
type responsesToChatCompletionsWriter struct {
	w        io.Writer
	buf      []byte
	callback func([]byte) // called with original event data for usage parsing
	debug    bool
	reqID    string

	// State tracking
	id                  string
	model               string
	started             bool
	toolCallIndex       int
	toolCallIDToIndex   map[string]int
	itemIDToToolCallID  map[string]string
	toolCallHasArgDelta map[string]bool
	inputTokens         int64
	outputTokens        int64
}

func (rw *responsesToChatCompletionsWriter) Write(p []byte) (int, error) {
	origLen := len(p)
	rw.buf = append(rw.buf, p...)
	rw.scanAndTranslate()
	return origLen, nil
}

func (rw *responsesToChatCompletionsWriter) scanAndTranslate() {
	for {
		idx := bytes.Index(rw.buf, []byte("\n\n"))
		advance := 2
		if idx < 0 {
			idx = bytes.Index(rw.buf, []byte("\r\n\r\n"))
			advance = 4
			if idx < 0 {
				if len(rw.buf) > 1024*1024 {
					rw.buf = rw.buf[len(rw.buf)-512*1024:]
				}
				return
			}
		}

		event := rw.buf[:idx]
		rw.buf = rw.buf[idx+advance:]
		rw.processEvent(event)
	}
}

func (rw *responsesToChatCompletionsWriter) processEvent(event []byte) {
	var eventType string
	var data []byte

	for _, line := range bytes.Split(event, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if bytes.HasPrefix(line, []byte("event:")) {
			eventType = string(bytes.TrimSpace(line[6:]))
		} else if bytes.HasPrefix(line, []byte("event: ")) {
			eventType = string(bytes.TrimSpace(line[7:]))
		} else if bytes.HasPrefix(line, []byte("data: ")) {
			data = bytes.TrimSpace(line[6:])
		} else if bytes.HasPrefix(line, []byte("data:")) {
			data = bytes.TrimSpace(line[5:])
		}
	}

	// Forward original data to usage callback
	if len(data) > 0 && rw.callback != nil && !bytes.Equal(data, []byte("[DONE]")) {
		rw.callback(data)
	}

	if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
		return
	}

	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return
	}

	if eventType == "" {
		if t, ok := obj["type"].(string); ok {
			eventType = t
		}
	}

	switch eventType {
	case "response.created":
		resp, _ := obj["response"].(map[string]any)
		if resp != nil {
			if id, ok := resp["id"].(string); ok {
				rw.id = id
			}
			if m, ok := resp["model"].(string); ok {
				rw.model = m
			}
		}
		// Emit initial role chunk
		rw.started = true
		rw.emitChunk(map[string]any{"role": "assistant", "content": ""}, "", nil)

	case "response.output_item.added":
		item, _ := obj["item"].(map[string]any)
		if item == nil {
			return
		}
		itemType, _ := item["type"].(string)
		switch itemType {
		case "function_call":
			callID, _ := item["call_id"].(string)
			itemID, _ := item["id"].(string)
			if callID == "" {
				callID = itemID
			}
			name, _ := item["name"].(string)
			idx := rw.registerToolCall(itemID, callID)
			rw.emitChunk(map[string]any{
				"tool_calls": []any{
					map[string]any{
						"index": idx,
						"id":    callID,
						"type":  "function",
						"function": map[string]any{
							"name":      name,
							"arguments": "",
						},
					},
				},
			}, "", nil)
		}

	case "response.output_text.delta":
		delta, _ := obj["delta"].(string)
		if delta != "" {
			rw.emitChunk(map[string]any{"content": delta}, "", nil)
		}

	case "response.reasoning_text.delta", "response.reasoning_summary_text.delta":
		delta, _ := obj["delta"].(string)
		if delta != "" {
			rw.emitChunk(map[string]any{"reasoning_content": delta}, "", nil)
		}

	case "response.function_call_arguments.delta":
		delta, _ := obj["delta"].(string)
		if delta != "" {
			callID := rw.resolveToolCallID(obj)
			idx := rw.toolCallIndexForID(callID)
			if callID != "" {
				if rw.toolCallHasArgDelta == nil {
					rw.toolCallHasArgDelta = map[string]bool{}
				}
				rw.toolCallHasArgDelta[callID] = true
			}
			rw.emitChunk(map[string]any{
				"tool_calls": []any{
					map[string]any{
						"index": idx,
						"function": map[string]any{
							"arguments": delta,
						},
					},
				},
			}, "", nil)
		}

	case "response.function_call_arguments.done":
		callID := rw.resolveToolCallID(obj)
		args, _ := obj["arguments"].(string)
		if args != "" && callID != "" && !rw.toolCallHasArgDelta[callID] {
			rw.emitChunk(map[string]any{
				"tool_calls": []any{
					map[string]any{
						"index": rw.toolCallIndexForID(callID),
						"function": map[string]any{
							"arguments": args,
						},
					},
				},
			}, "", nil)
		}

	case "response.output_item.done":
		item, _ := obj["item"].(map[string]any)
		callID := rw.resolveToolCallIDFromItem(item)
		args, _ := item["arguments"].(string)
		if args != "" && callID != "" && !rw.toolCallHasArgDelta[callID] {
			rw.emitChunk(map[string]any{
				"tool_calls": []any{
					map[string]any{
						"index": rw.toolCallIndexForID(callID),
						"function": map[string]any{
							"arguments": args,
						},
					},
				},
			}, "", nil)
		}

	case "response.completed":
		resp, _ := obj["response"].(map[string]any)
		if resp != nil {
			if usage, ok := resp["usage"].(map[string]any); ok {
				rw.inputTokens = toInt64(usage["input_tokens"])
				rw.outputTokens = toInt64(usage["output_tokens"])
			}
		}

		// Determine finish reason
		finishReason := "stop"
		if resp != nil {
			if status, ok := resp["status"].(string); ok {
				switch status {
				case "completed":
					finishReason = "stop"
				case "incomplete":
					if reason, ok := resp["incomplete_details"].(map[string]any); ok {
						if r, _ := reason["reason"].(string); r == "max_output_tokens" {
							finishReason = "length"
						}
					}
				}
			}
		}
		if rw.toolCallIndex > 0 {
			finishReason = "tool_calls"
		}

		usage := map[string]any{
			"prompt_tokens":     rw.inputTokens,
			"completion_tokens": rw.outputTokens,
			"total_tokens":      rw.inputTokens + rw.outputTokens,
		}
		rw.emitChunk(map[string]any{}, finishReason, usage)
		rw.writeRaw("data: [DONE]\n\n")

	case "response.failed":
		// Emit error as a final chunk
		resp, _ := obj["response"].(map[string]any)
		errMsg := "response failed"
		if resp != nil {
			if e, ok := resp["error"].(map[string]any); ok {
				if m, ok := e["message"].(string); ok && m != "" {
					errMsg = m
				}
			}
		}
		rw.emitChunk(map[string]any{"content": "[Error: " + errMsg + "]"}, "stop", nil)
		rw.writeRaw("data: [DONE]\n\n")

	case "response.output_text.done", "response.content_part.done",
		"response.content_part.added", "response.reasoning_text.done",
		"response.reasoning_summary_text.done", "response.in_progress":
		// Informational events, no action needed

	default:
		if rw.debug {
			log.Printf("[%s] responses->chat: unhandled event type: %s", rw.reqID, eventType)
		}
	}
}

func (rw *responsesToChatCompletionsWriter) registerToolCall(itemID, callID string) int {
	if rw.toolCallIDToIndex == nil {
		rw.toolCallIDToIndex = map[string]int{}
	}
	if rw.itemIDToToolCallID == nil {
		rw.itemIDToToolCallID = map[string]string{}
	}
	if callID == "" {
		callID = itemID
	}
	if itemID != "" && callID != "" {
		rw.itemIDToToolCallID[itemID] = callID
	}
	if callID != "" {
		if idx, ok := rw.toolCallIDToIndex[callID]; ok {
			return idx
		}
	}
	idx := rw.toolCallIndex
	rw.toolCallIndex++
	if callID != "" {
		rw.toolCallIDToIndex[callID] = idx
	}
	return idx
}

func (rw *responsesToChatCompletionsWriter) resolveToolCallID(obj map[string]any) string {
	callID, _ := obj["call_id"].(string)
	if callID == "" {
		callID, _ = obj["item_id"].(string)
	}
	if callID == "" {
		return ""
	}
	if resolved := rw.itemIDToToolCallID[callID]; resolved != "" {
		return resolved
	}
	return callID
}

func (rw *responsesToChatCompletionsWriter) resolveToolCallIDFromItem(item map[string]any) string {
	if item == nil {
		return ""
	}
	callID, _ := item["call_id"].(string)
	if callID == "" {
		callID, _ = item["id"].(string)
	}
	if resolved := rw.itemIDToToolCallID[callID]; resolved != "" {
		return resolved
	}
	return callID
}

func (rw *responsesToChatCompletionsWriter) toolCallIndexForID(callID string) int {
	if idx, ok := rw.toolCallIDToIndex[callID]; ok {
		return idx
	}
	idx := rw.toolCallIndex - 1
	if idx < 0 {
		return 0
	}
	return idx
}

func (rw *responsesToChatCompletionsWriter) emitChunk(delta map[string]any, finishReason string, usage map[string]any) {
	id := rw.id
	if id == "" {
		id = "chatcmpl-translated"
	}
	model := rw.model
	if model == "" {
		model = "unknown"
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

	chunk := map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"model":   model,
		"choices": []any{choiceObj},
	}

	if usage != nil {
		chunk["usage"] = usage
	}

	b, err := json.Marshal(chunk)
	if err != nil {
		return
	}
	rw.writeRaw(fmt.Sprintf("data: %s\n\n", string(b)))
}

func (rw *responsesToChatCompletionsWriter) writeRaw(s string) {
	if _, err := rw.w.Write([]byte(s)); err != nil {
		if rw.debug {
			log.Printf("[%s] responses->chat write error: %v", rw.reqID, err)
		}
	}
}

// responsesToChatCompletionsBufferingWriter is like responsesToChatCompletionsWriter
// but buffers all SSE events and produces a single non-streaming JSON response.
// Used when the client sends stream:false but Codex backend requires streaming.
type responsesToChatCompletionsBufferingWriter struct {
	buf      []byte
	callback func([]byte) // usage callback
	debug    bool
	reqID    string

	// State accumulated from SSE events
	id                  string
	model               string
	contentText         string
	toolCalls           []any
	toolCallIndex       int
	toolCallIDToIndex   map[string]int
	itemIDToToolCallID  map[string]string
	toolCallHasArgDelta map[string]bool
	inputTokens         int64
	outputTokens        int64
	finishReason        string
	errMsg              string
}

func (bw *responsesToChatCompletionsBufferingWriter) Write(p []byte) (int, error) {
	origLen := len(p)
	bw.buf = append(bw.buf, p...)
	bw.scanEvents()
	return origLen, nil
}

func (bw *responsesToChatCompletionsBufferingWriter) scanEvents() {
	for {
		idx := bytes.Index(bw.buf, []byte("\n\n"))
		advance := 2
		if idx < 0 {
			idx = bytes.Index(bw.buf, []byte("\r\n\r\n"))
			advance = 4
			if idx < 0 {
				return
			}
		}
		event := bw.buf[:idx]
		bw.buf = bw.buf[idx+advance:]
		bw.processEvent(event)
	}
}

func (bw *responsesToChatCompletionsBufferingWriter) processEvent(event []byte) {
	var eventType string
	var data []byte

	for _, line := range bytes.Split(event, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if bytes.HasPrefix(line, []byte("event:")) {
			eventType = string(bytes.TrimSpace(line[6:]))
		} else if bytes.HasPrefix(line, []byte("event: ")) {
			eventType = string(bytes.TrimSpace(line[7:]))
		} else if bytes.HasPrefix(line, []byte("data: ")) {
			data = bytes.TrimSpace(line[6:])
		} else if bytes.HasPrefix(line, []byte("data:")) {
			data = bytes.TrimSpace(line[5:])
		}
	}

	if len(data) > 0 && bw.callback != nil && !bytes.Equal(data, []byte("[DONE]")) {
		bw.callback(data)
	}

	if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
		return
	}

	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return
	}

	if eventType == "" {
		if t, ok := obj["type"].(string); ok {
			eventType = t
		}
	}

	switch eventType {
	case "response.created":
		resp, _ := obj["response"].(map[string]any)
		if resp != nil {
			if id, ok := resp["id"].(string); ok {
				bw.id = id
			}
			if m, ok := resp["model"].(string); ok {
				bw.model = m
			}
		}

	case "response.output_text.delta":
		delta, _ := obj["delta"].(string)
		bw.contentText += delta

	case "response.output_item.added":
		item, _ := obj["item"].(map[string]any)
		if item == nil {
			return
		}
		if itemType, _ := item["type"].(string); itemType == "function_call" {
			callID, _ := item["call_id"].(string)
			itemID, _ := item["id"].(string)
			if callID == "" {
				callID = itemID
			}
			name, _ := item["name"].(string)
			idx := bw.registerToolCall(itemID, callID)
			bw.toolCalls = append(bw.toolCalls, map[string]any{
				"id":    callID,
				"type":  "function",
				"index": idx,
				"function": map[string]any{
					"name":      name,
					"arguments": "",
				},
			})
		}

	case "response.function_call_arguments.delta":
		delta, _ := obj["delta"].(string)
		if delta != "" && len(bw.toolCalls) > 0 {
			callID := bw.resolveToolCallID(obj)
			idx := bw.toolCallIndexForID(callID)
			if callID != "" {
				if bw.toolCallHasArgDelta == nil {
					bw.toolCallHasArgDelta = map[string]bool{}
				}
				bw.toolCallHasArgDelta[callID] = true
			}
			tc := bw.toolCalls[idx].(map[string]any)
			fn := tc["function"].(map[string]any)
			fn["arguments"] = fn["arguments"].(string) + delta
		}

	case "response.function_call_arguments.done":
		callID := bw.resolveToolCallID(obj)
		args, _ := obj["arguments"].(string)
		if args != "" && callID != "" && !bw.toolCallHasArgDelta[callID] && len(bw.toolCalls) > 0 {
			tc := bw.toolCalls[bw.toolCallIndexForID(callID)].(map[string]any)
			fn := tc["function"].(map[string]any)
			fn["arguments"] = args
		}

	case "response.output_item.done":
		item, _ := obj["item"].(map[string]any)
		callID := bw.resolveToolCallIDFromItem(item)
		args, _ := item["arguments"].(string)
		if args != "" && callID != "" && !bw.toolCallHasArgDelta[callID] && len(bw.toolCalls) > 0 {
			tc := bw.toolCalls[bw.toolCallIndexForID(callID)].(map[string]any)
			fn := tc["function"].(map[string]any)
			fn["arguments"] = args
		}

	case "response.completed":
		resp, _ := obj["response"].(map[string]any)
		if resp != nil {
			if usage, ok := resp["usage"].(map[string]any); ok {
				bw.inputTokens = toInt64(usage["input_tokens"])
				bw.outputTokens = toInt64(usage["output_tokens"])
			}
		}
		bw.finishReason = "stop"
		if resp != nil {
			if status, ok := resp["status"].(string); ok {
				switch status {
				case "incomplete":
					if reason, ok := resp["incomplete_details"].(map[string]any); ok {
						if r, _ := reason["reason"].(string); r == "max_output_tokens" {
							bw.finishReason = "length"
						}
					}
				}
			}
		}
		if bw.toolCallIndex > 0 {
			bw.finishReason = "tool_calls"
		}

	case "response.failed":
		resp, _ := obj["response"].(map[string]any)
		bw.errMsg = "response failed"
		if resp != nil {
			if e, ok := resp["error"].(map[string]any); ok {
				if m, ok := e["message"].(string); ok && m != "" {
					bw.errMsg = m
				}
			}
		}
		bw.finishReason = "stop"
	}
}

func (bw *responsesToChatCompletionsBufferingWriter) registerToolCall(itemID, callID string) int {
	if bw.toolCallIDToIndex == nil {
		bw.toolCallIDToIndex = map[string]int{}
	}
	if bw.itemIDToToolCallID == nil {
		bw.itemIDToToolCallID = map[string]string{}
	}
	if callID == "" {
		callID = itemID
	}
	if itemID != "" && callID != "" {
		bw.itemIDToToolCallID[itemID] = callID
	}
	if callID != "" {
		if idx, ok := bw.toolCallIDToIndex[callID]; ok {
			return idx
		}
	}
	idx := bw.toolCallIndex
	bw.toolCallIndex++
	if callID != "" {
		bw.toolCallIDToIndex[callID] = idx
	}
	return idx
}

func (bw *responsesToChatCompletionsBufferingWriter) resolveToolCallID(obj map[string]any) string {
	callID, _ := obj["call_id"].(string)
	if callID == "" {
		callID, _ = obj["item_id"].(string)
	}
	if resolved := bw.itemIDToToolCallID[callID]; resolved != "" {
		return resolved
	}
	return callID
}

func (bw *responsesToChatCompletionsBufferingWriter) resolveToolCallIDFromItem(item map[string]any) string {
	if item == nil {
		return ""
	}
	callID, _ := item["call_id"].(string)
	if callID == "" {
		callID, _ = item["id"].(string)
	}
	if resolved := bw.itemIDToToolCallID[callID]; resolved != "" {
		return resolved
	}
	return callID
}

func (bw *responsesToChatCompletionsBufferingWriter) toolCallIndexForID(callID string) int {
	if idx, ok := bw.toolCallIDToIndex[callID]; ok {
		return idx
	}
	idx := bw.toolCallIndex - 1
	if idx < 0 {
		return 0
	}
	if idx >= len(bw.toolCalls) {
		return len(bw.toolCalls) - 1
	}
	return idx
}

// Result returns the assembled non-streaming Chat Completions JSON response.
func (bw *responsesToChatCompletionsBufferingWriter) Result() []byte {
	id := bw.id
	if id == "" {
		id = "chatcmpl-translated"
	}
	model := bw.model
	if model == "" {
		model = "unknown"
	}

	content := bw.contentText
	if bw.errMsg != "" {
		content = "[Error: " + bw.errMsg + "]"
	}

	message := map[string]any{
		"role":    "assistant",
		"content": content,
	}
	if len(bw.toolCalls) > 0 {
		message["tool_calls"] = bw.toolCalls
	}

	finishReason := bw.finishReason
	if finishReason == "" {
		finishReason = "stop"
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

	if bw.inputTokens > 0 || bw.outputTokens > 0 {
		out["usage"] = map[string]any{
			"prompt_tokens":     bw.inputTokens,
			"completion_tokens": bw.outputTokens,
			"total_tokens":      bw.inputTokens + bw.outputTokens,
		}
	}

	b, _ := json.Marshal(out)
	return b
}

// responsesToClaudeBufferingWriter buffers Responses API SSE events into a
// non-streaming Claude Messages API response.
type responsesToClaudeBufferingWriter struct {
	buf      []byte
	callback func([]byte)
	debug    bool
	reqID    string

	id           string
	model        string
	contentText  string
	toolUses     []map[string]any
	inputTokens  int64
	outputTokens int64
	stopReason   string
	errMsg       string
}

func (bw *responsesToClaudeBufferingWriter) Write(p []byte) (int, error) {
	origLen := len(p)
	bw.buf = append(bw.buf, p...)
	bw.scanEvents()
	return origLen, nil
}

func (bw *responsesToClaudeBufferingWriter) scanEvents() {
	for {
		idx := bytes.Index(bw.buf, []byte("\n\n"))
		advance := 2
		if idx < 0 {
			idx = bytes.Index(bw.buf, []byte("\r\n\r\n"))
			advance = 4
			if idx < 0 {
				return
			}
		}
		event := bw.buf[:idx]
		bw.buf = bw.buf[idx+advance:]
		bw.processEvent(event)
	}
}

func (bw *responsesToClaudeBufferingWriter) processEvent(event []byte) {
	var eventType string
	var data []byte

	for _, line := range bytes.Split(event, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if bytes.HasPrefix(line, []byte("event:")) {
			eventType = string(bytes.TrimSpace(line[6:]))
		} else if bytes.HasPrefix(line, []byte("data: ")) {
			data = bytes.TrimSpace(line[6:])
		} else if bytes.HasPrefix(line, []byte("data:")) {
			data = bytes.TrimSpace(line[5:])
		}
	}

	if len(data) > 0 && bw.callback != nil && !bytes.Equal(data, []byte("[DONE]")) {
		bw.callback(data)
	}
	if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
		return
	}

	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		if bw.debug {
			log.Printf("[%s] responses->claude buffer: JSON parse error for event %q: %v", bw.reqID, eventType, err)
		}
		return
	}
	if eventType == "" {
		if t, ok := obj["type"].(string); ok {
			eventType = t
		}
	}

	switch eventType {
	case "response.created":
		resp, _ := obj["response"].(map[string]any)
		if resp != nil {
			if id, ok := resp["id"].(string); ok {
				bw.id = id
			}
			if model, ok := resp["model"].(string); ok {
				bw.model = model
			}
			if usage, ok := resp["usage"].(map[string]any); ok {
				bw.inputTokens = toInt64(usage["input_tokens"])
			}
		}
	case "response.output_text.delta":
		if delta, _ := obj["delta"].(string); delta != "" {
			bw.contentText += delta
		}
	case "response.output_item.added":
		item, _ := obj["item"].(map[string]any)
		if item == nil {
			return
		}
		if itemType, _ := item["type"].(string); itemType == "function_call" {
			callID, _ := item["call_id"].(string)
			name, _ := item["name"].(string)
			bw.toolUses = append(bw.toolUses, map[string]any{
				"type":  "tool_use",
				"id":    callID,
				"name":  name,
				"input": map[string]any{},
				"_args": "",
			})
		}
	case "response.function_call_arguments.delta":
		if delta, _ := obj["delta"].(string); delta != "" && len(bw.toolUses) > 0 {
			last := bw.toolUses[len(bw.toolUses)-1]
			last["_args"] = last["_args"].(string) + delta
		}
	case "response.output_item.done":
		bw.finishToolUse()
	case "response.completed":
		resp, _ := obj["response"].(map[string]any)
		if resp != nil {
			if id, ok := resp["id"].(string); ok && bw.id == "" {
				bw.id = id
			}
			if model, ok := resp["model"].(string); ok && bw.model == "" {
				bw.model = model
			}
			if usage, ok := resp["usage"].(map[string]any); ok {
				bw.inputTokens = toInt64(usage["input_tokens"])
				bw.outputTokens = toInt64(usage["output_tokens"])
			}
			if status, ok := resp["status"].(string); ok && status == "incomplete" {
				bw.stopReason = "max_tokens"
			}
		}
		if bw.stopReason == "" {
			bw.stopReason = "end_turn"
		}
		if len(bw.toolUses) > 0 {
			bw.stopReason = "tool_use"
		}
	case "response.failed":
		resp, _ := obj["response"].(map[string]any)
		bw.errMsg = "response failed"
		if resp != nil {
			if e, ok := resp["error"].(map[string]any); ok {
				if msg, _ := e["message"].(string); msg != "" {
					bw.errMsg = msg
				}
			}
		}
		bw.stopReason = "end_turn"
	}
}

func (bw *responsesToClaudeBufferingWriter) finishToolUse() {
	if len(bw.toolUses) == 0 {
		return
	}
	last := bw.toolUses[len(bw.toolUses)-1]
	args, _ := last["_args"].(string)
	delete(last, "_args")
	if args == "" {
		return
	}
	var input map[string]any
	if json.Unmarshal([]byte(args), &input) == nil {
		last["input"] = input
	}
}

func (bw *responsesToClaudeBufferingWriter) Result() []byte {
	for i := range bw.toolUses {
		args, _ := bw.toolUses[i]["_args"].(string)
		if args != "" {
			var input map[string]any
			if json.Unmarshal([]byte(args), &input) == nil {
				bw.toolUses[i]["input"] = input
			}
		}
		delete(bw.toolUses[i], "_args")
	}

	content := make([]any, 0, 1+len(bw.toolUses))
	text := bw.contentText
	if bw.errMsg != "" {
		text = "[Error: " + bw.errMsg + "]"
	}
	if text != "" {
		content = append(content, map[string]any{"type": "text", "text": text})
	}
	for _, toolUse := range bw.toolUses {
		content = append(content, toolUse)
	}

	stopReason := bw.stopReason
	if stopReason == "" {
		stopReason = "end_turn"
	}
	id := bw.id
	if id == "" {
		id = "msg_translated"
	}
	model := bw.model
	if model == "" {
		model = "unknown"
	}

	out := map[string]any{
		"id":            id,
		"type":          "message",
		"role":          "assistant",
		"model":         model,
		"content":       content,
		"stop_reason":   stopReason,
		"stop_sequence": nil,
		"usage": map[string]any{
			"input_tokens":  bw.inputTokens,
			"output_tokens": bw.outputTokens,
		},
	}
	b, _ := json.Marshal(out)
	return b
}

// claudeToResponsesWriter translates Claude Messages API SSE events
// to OpenAI Responses API SSE events. Used when Codex CLI sends to /responses
// with a Claude model.
type claudeToResponsesWriter struct {
	w        io.Writer
	buf      []byte
	callback func([]byte)
	debug    bool
	reqID    string

	// State
	id               string
	model            string
	started          bool
	outputIndex      int
	contentIndex     int
	currentBlockType string // "text", "thinking", "tool_use"
	currentToolID    string
	currentToolName  string
	accumulatedText  string
	accumulatedArgs  string
	inputTokens      int64
	outputTokens     int64
	stopReason       string
	sentMessageItem  bool // whether we've emitted the message output_item.added
}

func (cw *claudeToResponsesWriter) Write(p []byte) (int, error) {
	origLen := len(p)
	cw.buf = append(cw.buf, p...)
	cw.scanAndTranslate()
	return origLen, nil
}

func (cw *claudeToResponsesWriter) scanAndTranslate() {
	for {
		idx := bytes.Index(cw.buf, []byte("\n\n"))
		advance := 2
		if idx < 0 {
			idx = bytes.Index(cw.buf, []byte("\r\n\r\n"))
			advance = 4
			if idx < 0 {
				if len(cw.buf) > 1024*1024 {
					cw.buf = cw.buf[len(cw.buf)-512*1024:]
				}
				return
			}
		}
		event := cw.buf[:idx]
		cw.buf = cw.buf[idx+advance:]
		cw.processEvent(event)
	}
}

func (cw *claudeToResponsesWriter) processEvent(event []byte) {
	var eventType string
	var data []byte

	for _, line := range bytes.Split(event, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if bytes.HasPrefix(line, []byte("event:")) {
			eventType = string(bytes.TrimSpace(line[6:]))
		} else if bytes.HasPrefix(line, []byte("event: ")) {
			eventType = string(bytes.TrimSpace(line[7:]))
		} else if bytes.HasPrefix(line, []byte("data: ")) {
			data = bytes.TrimSpace(line[6:])
		} else if bytes.HasPrefix(line, []byte("data:")) {
			data = bytes.TrimSpace(line[5:])
		}
	}

	if len(data) > 0 && cw.callback != nil && !bytes.Equal(data, []byte("[DONE]")) {
		cw.callback(data)
	}

	if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
		return
	}

	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return
	}

	if eventType == "" {
		if t, ok := obj["type"].(string); ok {
			eventType = t
		}
	}

	switch eventType {
	case "message_start":
		msg, _ := obj["message"].(map[string]any)
		if msg != nil {
			if id, ok := msg["id"].(string); ok {
				cw.id = id
			}
			if model, ok := msg["model"].(string); ok {
				cw.model = model
			}
			if usage, ok := msg["usage"].(map[string]any); ok {
				cw.inputTokens = toInt64(usage["input_tokens"])
			}
		}
		cw.started = true
		// Emit response.created
		cw.emitEvent("response.created", map[string]any{
			"type": "response.created",
			"response": map[string]any{
				"id":     cw.id,
				"object": "response",
				"model":  cw.model,
				"status": "in_progress",
				"output": []any{},
				"usage":  map[string]any{"input_tokens": cw.inputTokens, "output_tokens": 0},
			},
		})

	case "content_block_start":
		block, _ := obj["content_block"].(map[string]any)
		if block == nil {
			return
		}
		blockType, _ := block["type"].(string)
		cw.currentBlockType = blockType

		switch blockType {
		case "text":
			cw.accumulatedText = ""
			// Emit output_item.added for the message (only once)
			if !cw.sentMessageItem {
				cw.sentMessageItem = true
				cw.emitEvent("response.output_item.added", map[string]any{
					"type":         "response.output_item.added",
					"output_index": cw.outputIndex,
					"item": map[string]any{
						"type":    "message",
						"role":    "assistant",
						"content": []any{},
						"status":  "in_progress",
					},
				})
			}
			// Emit content_part.added
			cw.emitEvent("response.content_part.added", map[string]any{
				"type":          "response.content_part.added",
				"output_index":  cw.outputIndex,
				"content_index": cw.contentIndex,
				"part":          map[string]any{"type": "output_text", "text": ""},
			})
		case "thinking":
			// Track thinking block, emit reasoning events
		case "tool_use":
			id, _ := block["id"].(string)
			name, _ := block["name"].(string)
			name = strings.TrimPrefix(name, "mcp_")
			cw.currentToolID = id
			cw.currentToolName = name
			cw.accumulatedArgs = ""
			// Close previous message output item if needed
			if cw.sentMessageItem {
				// Emit content_part.done and output_item.done for the message
				cw.emitEvent("response.content_part.done", map[string]any{
					"type":          "response.content_part.done",
					"output_index":  cw.outputIndex,
					"content_index": cw.contentIndex,
					"part":          map[string]any{"type": "output_text", "text": cw.accumulatedText},
				})
				cw.emitEvent("response.output_item.done", map[string]any{
					"type":         "response.output_item.done",
					"output_index": cw.outputIndex,
					"item": map[string]any{
						"type": "message",
						"role": "assistant",
						"content": []any{
							map[string]any{"type": "output_text", "text": cw.accumulatedText},
						},
						"status": "completed",
					},
				})
				cw.outputIndex++
				cw.contentIndex = 0
				cw.sentMessageItem = false
			}
			// Emit output_item.added for the function_call
			cw.emitEvent("response.output_item.added", map[string]any{
				"type":         "response.output_item.added",
				"output_index": cw.outputIndex,
				"item": map[string]any{
					"type":      "function_call",
					"call_id":   id,
					"name":      name,
					"arguments": "",
					"status":    "in_progress",
				},
			})
		}

	case "content_block_delta":
		delta, _ := obj["delta"].(map[string]any)
		if delta == nil {
			return
		}
		deltaType, _ := delta["type"].(string)
		switch deltaType {
		case "text_delta":
			text, _ := delta["text"].(string)
			if text != "" {
				cw.accumulatedText += text
				cw.emitEvent("response.output_text.delta", map[string]any{
					"type":          "response.output_text.delta",
					"output_index":  cw.outputIndex,
					"content_index": cw.contentIndex,
					"delta":         text,
				})
			}
		case "thinking_delta":
			thinking, _ := delta["thinking"].(string)
			if thinking != "" {
				cw.emitEvent("response.reasoning_text.delta", map[string]any{
					"type":          "response.reasoning_text.delta",
					"output_index":  cw.outputIndex,
					"content_index": cw.contentIndex,
					"delta":         thinking,
				})
			}
		case "input_json_delta":
			partial, _ := delta["partial_json"].(string)
			if partial != "" {
				cw.accumulatedArgs += partial
				cw.emitEvent("response.function_call_arguments.delta", map[string]any{
					"type":         "response.function_call_arguments.delta",
					"output_index": cw.outputIndex,
					"delta":        partial,
				})
			}
		}

	case "content_block_stop":
		switch cw.currentBlockType {
		case "text":
			cw.emitEvent("response.output_text.done", map[string]any{
				"type":          "response.output_text.done",
				"output_index":  cw.outputIndex,
				"content_index": cw.contentIndex,
				"text":          cw.accumulatedText,
			})
			cw.contentIndex++
		case "thinking":
			// No specific done event needed
		case "tool_use":
			cw.emitEvent("response.function_call_arguments.done", map[string]any{
				"type":         "response.function_call_arguments.done",
				"output_index": cw.outputIndex,
				"call_id":      cw.currentToolID,
				"name":         cw.currentToolName,
				"arguments":    cw.accumulatedArgs,
			})
			cw.emitEvent("response.output_item.done", map[string]any{
				"type":         "response.output_item.done",
				"output_index": cw.outputIndex,
				"item": map[string]any{
					"type":      "function_call",
					"call_id":   cw.currentToolID,
					"name":      cw.currentToolName,
					"arguments": cw.accumulatedArgs,
					"status":    "completed",
				},
			})
			cw.outputIndex++
			cw.contentIndex = 0
		}
		cw.currentBlockType = ""

	case "message_delta":
		delta, _ := obj["delta"].(map[string]any)
		if delta != nil {
			if sr, ok := delta["stop_reason"].(string); ok {
				cw.stopReason = sr
			}
		}
		if usage, ok := obj["usage"].(map[string]any); ok {
			cw.outputTokens = toInt64(usage["output_tokens"])
		}

	case "message_stop":
		// Close any open message item
		if cw.sentMessageItem {
			cw.emitEvent("response.content_part.done", map[string]any{
				"type":          "response.content_part.done",
				"output_index":  cw.outputIndex,
				"content_index": cw.contentIndex,
				"part":          map[string]any{"type": "output_text", "text": cw.accumulatedText},
			})
			cw.emitEvent("response.output_item.done", map[string]any{
				"type":         "response.output_item.done",
				"output_index": cw.outputIndex,
				"item": map[string]any{
					"type": "message",
					"role": "assistant",
					"content": []any{
						map[string]any{"type": "output_text", "text": cw.accumulatedText},
					},
					"status": "completed",
				},
			})
		}
		// Emit response.completed
		status := "completed"
		if cw.stopReason == "max_tokens" {
			status = "incomplete"
		}
		cw.emitEvent("response.completed", map[string]any{
			"type": "response.completed",
			"response": map[string]any{
				"id":     cw.id,
				"object": "response",
				"model":  cw.model,
				"status": status,
				"usage": map[string]any{
					"input_tokens":  cw.inputTokens,
					"output_tokens": cw.outputTokens,
					"total_tokens":  cw.inputTokens + cw.outputTokens,
				},
			},
		})

	case "ping":
		// Ignore
	}
}

func (cw *claudeToResponsesWriter) emitEvent(eventType string, data map[string]any) {
	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	out := fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, string(b))
	if _, err := cw.w.Write([]byte(out)); err != nil {
		if cw.debug {
			log.Printf("[%s] claude->responses write error: %v", cw.reqID, err)
		}
	}
}

// responsesToClaudeWriter translates Responses API SSE events to Claude Messages
// API SSE events. Used when Claude Code sends /v1/messages with a Codex model,
// so the Responses API SSE from upstream needs to be converted back to Claude SSE.
type responsesToClaudeWriter struct {
	w        io.Writer
	buf      []byte
	callback func([]byte)
	debug    bool
	reqID    string

	// State
	id                string
	model             string
	started           bool
	contentBlockIndex int
	toolCallIndex     int
	sentText          bool // whether we've emitted a text content_block_start
	sentThinking      bool // whether we've emitted a thinking content_block_start
	finishReason      string
	inputTokens       int64
	outputTokens      int64
}

func (rw *responsesToClaudeWriter) Write(p []byte) (int, error) {
	origLen := len(p)
	rw.buf = append(rw.buf, p...)
	rw.scanAndTranslate()
	return origLen, nil
}

func (rw *responsesToClaudeWriter) scanAndTranslate() {
	for {
		idx := bytes.Index(rw.buf, []byte("\n\n"))
		advance := 2
		if idx < 0 {
			idx = bytes.Index(rw.buf, []byte("\r\n\r\n"))
			advance = 4
			if idx < 0 {
				if len(rw.buf) > 1024*1024 {
					rw.buf = rw.buf[len(rw.buf)-512*1024:]
				}
				return
			}
		}
		event := rw.buf[:idx]
		rw.buf = rw.buf[idx+advance:]
		rw.processEvent(event)
	}
}

func (rw *responsesToClaudeWriter) processEvent(event []byte) {
	var eventType string
	var data []byte

	for _, line := range bytes.Split(event, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if bytes.HasPrefix(line, []byte("event:")) {
			eventType = string(bytes.TrimSpace(line[6:]))
		} else if bytes.HasPrefix(line, []byte("event: ")) {
			eventType = string(bytes.TrimSpace(line[7:]))
		} else if bytes.HasPrefix(line, []byte("data: ")) {
			data = bytes.TrimSpace(line[6:])
		} else if bytes.HasPrefix(line, []byte("data:")) {
			data = bytes.TrimSpace(line[5:])
		}
	}

	// Forward original data to usage callback
	if len(data) > 0 && rw.callback != nil && !bytes.Equal(data, []byte("[DONE]")) {
		rw.callback(data)
	}

	if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
		return
	}

	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		if rw.debug {
			log.Printf("[%s] responses->claude: JSON parse error for event %q: %v (data len=%d)", rw.reqID, eventType, err, len(data))
		}
		return
	}

	if eventType == "" {
		if t, ok := obj["type"].(string); ok {
			eventType = t
		}
	}

	if rw.debug {
		log.Printf("[%s] responses->claude: processing event: %s", rw.reqID, eventType)
	}

	switch eventType {
	case "response.created":
		resp, _ := obj["response"].(map[string]any)
		if resp != nil {
			if id, ok := resp["id"].(string); ok {
				rw.id = id
			}
			if m, ok := resp["model"].(string); ok {
				rw.model = m
			}
			if usage, ok := resp["usage"].(map[string]any); ok {
				rw.inputTokens = toInt64(usage["input_tokens"])
			}
		}
		rw.started = true
		// Emit message_start
		rw.emitClaudeMessageStart()

	case "response.output_text.delta":
		delta, _ := obj["delta"].(string)
		if delta != "" {
			// Fallback: if response.created was dropped (e.g. huge event
			// exceeding buffer), emit message_start now.
			if !rw.started {
				rw.started = true
				rw.emitClaudeMessageStart()
			}
			if !rw.sentText {
				rw.sentText = true
				// Close thinking block if it was open
				if rw.sentThinking {
					rw.emitClaudeEvent("content_block_stop", fmt.Sprintf(
						`{"type":"content_block_stop","index":%d}`, rw.contentBlockIndex))
					rw.contentBlockIndex++
				}
				rw.emitClaudeEvent("content_block_start", fmt.Sprintf(
					`{"type":"content_block_start","index":%d,"content_block":{"type":"text","text":""}}`,
					rw.contentBlockIndex))
			}
			rw.emitClaudeEvent("content_block_delta", fmt.Sprintf(
				`{"type":"content_block_delta","index":%d,"delta":{"type":"text_delta","text":%s}}`,
				rw.contentBlockIndex, mustMarshalString(delta)))
		}

	case "response.reasoning_text.delta", "response.reasoning_summary_text.delta":
		delta, _ := obj["delta"].(string)
		if delta != "" {
			if !rw.started {
				rw.started = true
				rw.emitClaudeMessageStart()
			}
			if !rw.sentThinking {
				rw.sentThinking = true
				rw.emitClaudeEvent("content_block_start", fmt.Sprintf(
					`{"type":"content_block_start","index":%d,"content_block":{"type":"thinking","thinking":""}}`,
					rw.contentBlockIndex))
			}
			rw.emitClaudeEvent("content_block_delta", fmt.Sprintf(
				`{"type":"content_block_delta","index":%d,"delta":{"type":"thinking_delta","thinking":%s}}`,
				rw.contentBlockIndex, mustMarshalString(delta)))
		}

	case "response.output_item.added":
		item, _ := obj["item"].(map[string]any)
		if item == nil {
			return
		}
		itemType, _ := item["type"].(string)
		if itemType == "function_call" {
			if !rw.started {
				rw.started = true
				rw.emitClaudeMessageStart()
			}
			// Close previous content block
			if rw.sentText || rw.sentThinking {
				rw.emitClaudeEvent("content_block_stop", fmt.Sprintf(
					`{"type":"content_block_stop","index":%d}`, rw.contentBlockIndex))
				rw.contentBlockIndex++
				rw.sentText = false
				rw.sentThinking = false
			}
			callID, _ := item["call_id"].(string)
			name, _ := item["name"].(string)
			rw.emitClaudeEvent("content_block_start", fmt.Sprintf(
				`{"type":"content_block_start","index":%d,"content_block":{"type":"tool_use","id":%s,"name":%s,"input":{}}}`,
				rw.contentBlockIndex, mustMarshalString(callID), mustMarshalString(name)))
			rw.toolCallIndex++
		}

	case "response.function_call_arguments.delta":
		delta, _ := obj["delta"].(string)
		if delta != "" {
			rw.emitClaudeEvent("content_block_delta", fmt.Sprintf(
				`{"type":"content_block_delta","index":%d,"delta":{"type":"input_json_delta","partial_json":%s}}`,
				rw.contentBlockIndex, mustMarshalString(delta)))
		}

	case "response.output_item.done":
		item, _ := obj["item"].(map[string]any)
		if item != nil {
			if itemType, _ := item["type"].(string); itemType == "function_call" {
				rw.emitClaudeEvent("content_block_stop", fmt.Sprintf(
					`{"type":"content_block_stop","index":%d}`, rw.contentBlockIndex))
				rw.contentBlockIndex++
			}
		}

	case "response.completed":
		resp, _ := obj["response"].(map[string]any)
		if resp != nil {
			if usage, ok := resp["usage"].(map[string]any); ok {
				rw.inputTokens = toInt64(usage["input_tokens"])
				rw.outputTokens = toInt64(usage["output_tokens"])
			}
		}
		// Close any open content block
		if rw.sentText || rw.sentThinking {
			rw.emitClaudeEvent("content_block_stop", fmt.Sprintf(
				`{"type":"content_block_stop","index":%d}`, rw.contentBlockIndex))
		}
		// Determine stop reason
		stopReason := "end_turn"
		if resp != nil {
			if status, ok := resp["status"].(string); ok && status == "incomplete" {
				stopReason = "max_tokens"
			}
		}
		if rw.toolCallIndex > 0 {
			stopReason = "tool_use"
		}
		rw.finishReason = stopReason
		// Emit message_delta and message_stop
		rw.emitClaudeEvent("message_delta", fmt.Sprintf(
			`{"type":"message_delta","delta":{"stop_reason":%s,"stop_sequence":null},"usage":{"output_tokens":%d}}`,
			mustMarshalString(stopReason), rw.outputTokens))
		rw.emitClaudeEvent("message_stop", `{"type":"message_stop"}`)

	case "response.failed":
		resp, _ := obj["response"].(map[string]any)
		errMsg := "response failed"
		if resp != nil {
			if e, ok := resp["error"].(map[string]any); ok {
				if m, ok := e["message"].(string); ok && m != "" {
					errMsg = m
				}
			}
		}
		// Emit error as text content
		if !rw.sentText {
			rw.sentText = true
			rw.emitClaudeEvent("content_block_start", fmt.Sprintf(
				`{"type":"content_block_start","index":%d,"content_block":{"type":"text","text":""}}`,
				rw.contentBlockIndex))
		}
		rw.emitClaudeEvent("content_block_delta", fmt.Sprintf(
			`{"type":"content_block_delta","index":%d,"delta":{"type":"text_delta","text":%s}}`,
			rw.contentBlockIndex, mustMarshalString("[Error: "+errMsg+"]")))
		rw.emitClaudeEvent("content_block_stop", fmt.Sprintf(
			`{"type":"content_block_stop","index":%d}`, rw.contentBlockIndex))
		rw.emitClaudeEvent("message_delta", fmt.Sprintf(
			`{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":0}}`))
		rw.emitClaudeEvent("message_stop", `{"type":"message_stop"}`)

	case "response.output_text.done", "response.content_part.done",
		"response.content_part.added", "response.reasoning_text.done",
		"response.reasoning_summary_text.done", "response.function_call_arguments.done",
		"response.in_progress":
		// Informational events, no action needed

	default:
		if rw.debug {
			log.Printf("[%s] responses->claude: unhandled event type: %s", rw.reqID, eventType)
		}
	}
}

func (rw *responsesToClaudeWriter) emitClaudeMessageStart() {
	model := rw.model
	if model == "" {
		model = "unknown"
	}
	id := rw.id
	if id == "" {
		id = "msg_translated"
	}
	msg := fmt.Sprintf(`{"type":"message_start","message":{"id":%s,"type":"message","role":"assistant","model":%s,"content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":%d,"output_tokens":0}}}`,
		mustMarshalString(id), mustMarshalString(model), rw.inputTokens)
	rw.emitClaudeEvent("message_start", msg)
}

func (rw *responsesToClaudeWriter) emitClaudeEvent(eventType, data string) {
	out := fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, data)
	if rw.debug {
		preview := data
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		log.Printf("[%s] responses->claude EMIT: %s (len=%d) %s", rw.reqID, eventType, len(data), preview)
	}
	if _, err := rw.w.Write([]byte(out)); err != nil {
		if rw.debug {
			log.Printf("[%s] responses->claude write error: %v", rw.reqID, err)
		}
	}
}
