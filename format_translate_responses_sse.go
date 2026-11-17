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
	tools responsesToolCalls
	sseEventBuffer
	id                  string
	model               string
	contentText         []byte
	functionCalls       []any
	imageGenerationCall map[string]any
	inputTokens         int64
	outputTokens        int64
	cachedTokens        int64
	status              string
	createdAt           int64

	// failure is the upstream error object from response.failed or an error
	// event; overloaded marks a capacity shed the caller can retry elsewhere
	// because nothing has been written to the client yet.
	failure    any
	overloaded bool
}

func (bw *responsesBufferingWriter) Write(p []byte) (int, error) {
	return bw.sseEventBuffer.writeEvents(p, bw.processEvent, nil)
}

func (bw *responsesBufferingWriter) processEvent(event []byte) {
	eventType, data := parseSSEEvent(event)
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
			bw.contentText = append(bw.contentText, delta...)
		}
	case "response.output_item.added":
		item, _ := obj["item"].(map[string]any)
		if itemType, _ := item["type"].(string); itemType == "function_call" {
			bw.addFunctionCall(item)
		} else if itemType == "image_generation_call" {
			bw.addImageGenerationCall(item)
		}
	case "response.function_call_arguments.delta":
		if delta, _ := obj["delta"].(string); delta != "" {
			callID := bw.tools.eventID(obj)
			bw.tools.noteDelta(callID)
			bw.appendFunctionCallArguments(callID, delta)
		}
	case "response.function_call_arguments.done":
		callID := bw.tools.eventID(obj)
		args, _ := obj["arguments"].(string)
		if args != "" && callID != "" && !bw.tools.argDeltas[callID] {
			bw.setFunctionCallArguments(callID, args)
		}
	case "response.output_item.done":
		item, _ := obj["item"].(map[string]any)
		if itemType, _ := item["type"].(string); itemType == "image_generation_call" {
			bw.addImageGenerationCall(item)
			break
		}
		callID := bw.tools.itemID(item)
		args, _ := item["arguments"].(string)
		if args != "" && callID != "" && !bw.tools.argDeltas[callID] {
			bw.setFunctionCallArguments(callID, args)
		}
	case "response.image_generation_call.partial_image":
		bw.addImageGenerationResult(obj, "partial_image_b64")
	case "response.image_generation_call.completed":
		bw.addImageGenerationResult(obj, "result")
	case "response.completed", "response.incomplete":
		bw.applyResponse(obj)
		if eventType == "response.incomplete" {
			bw.status = "incomplete"
		} else if bw.status == "" {
			bw.status = "completed"
		}
	case "response.failed":
		bw.applyResponse(obj)
		bw.status = "failed"
		if resp, _ := obj["response"].(map[string]any); resp != nil && resp["error"] != nil {
			bw.failure = resp["error"]
		}
		bw.overloaded = bw.overloaded || isServerOverloadedError(data)
	case "error":
		bw.status = "failed"
		if errObj := obj["error"]; errObj != nil {
			bw.failure = errObj
		} else {
			bw.failure = obj
		}
		bw.overloaded = bw.overloaded || isServerOverloadedError(data)
	}
}

func (bw *responsesBufferingWriter) addImageGenerationResult(event map[string]any, field string) {
	result, _ := event[field].(string)
	if result == "" {
		return
	}
	if bw.imageGenerationCall == nil {
		bw.imageGenerationCall = map[string]any{
			"type": "image_generation_call",
		}
	}
	if itemID, _ := event["item_id"].(string); itemID != "" {
		bw.imageGenerationCall["id"] = itemID
	}
	bw.imageGenerationCall["result"] = result
	bw.imageGenerationCall["status"] = "completed"
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
	if created := toInt64(resp["created_at"]); created > 0 {
		bw.createdAt = created
	}
	if usage, ok := resp["usage"].(map[string]any); ok {
		readResponsesUsage(usage).apply(&bw.inputTokens, &bw.outputTokens, &bw.cachedTokens)
	}
}

func (bw *responsesBufferingWriter) addImageGenerationCall(item map[string]any) {
	if item == nil {
		return
	}
	copy := make(map[string]any, len(item)+1)
	for k, v := range item {
		copy[k] = v
	}
	if _, ok := copy["status"]; !ok {
		copy["status"] = "completed"
	}
	bw.imageGenerationCall = copy
}

func (bw *responsesBufferingWriter) addFunctionCall(item map[string]any) {
	if item == nil {
		return
	}
	callID, _ := item["call_id"].(string)
	itemID, _ := item["id"].(string)
	if callID == "" {
		callID = itemID
	}
	name, _ := item["name"].(string)
	idx := bw.tools.register(itemID, callID)
	for len(bw.functionCalls) <= idx {
		bw.functionCalls = append(bw.functionCalls, nil)
	}
	bw.functionCalls[idx] = map[string]any{
		"type":      "function_call",
		"id":        itemID,
		"call_id":   callID,
		"name":      name,
		"arguments": "",
		"status":    "completed",
	}
}

func (bw *responsesBufferingWriter) functionCallIndexForID(callID string) int {
	if idx, ok := bw.tools.indices[callID]; ok {
		return idx
	}
	idx := bw.tools.next - 1
	if idx < 0 {
		return 0
	}
	if idx >= len(bw.functionCalls) {
		return len(bw.functionCalls) - 1
	}
	return idx
}

func (bw *responsesBufferingWriter) appendFunctionCallArguments(callID, delta string) {
	if len(bw.functionCalls) == 0 {
		return
	}
	idx := bw.functionCallIndexForID(callID)
	call, _ := bw.functionCalls[idx].(map[string]any)
	if call == nil {
		return
	}
	args, _ := call["arguments"].(string)
	call["arguments"] = args + delta
}

func (bw *responsesBufferingWriter) setFunctionCallArguments(callID, args string) {
	if len(bw.functionCalls) == 0 {
		return
	}
	idx := bw.functionCallIndexForID(callID)
	call, _ := bw.functionCalls[idx].(map[string]any)
	if call != nil {
		call["arguments"] = args
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
	if bw.imageGenerationCall != nil {
		if result, _ := bw.imageGenerationCall["result"].(string); result != "" {
			status = "completed"
			bw.imageGenerationCall["status"] = "completed"
		}
	}
	output := []any{}
	if len(bw.contentText) != 0 || len(bw.functionCalls) == 0 {
		output = append(output, map[string]any{
			"id":     "msg_" + id,
			"type":   "message",
			"status": status,
			"role":   "assistant",
			"content": []any{
				map[string]any{"type": "output_text", "text": string(bw.contentText), "annotations": []any{}},
			},
		})
	}
	for _, call := range bw.functionCalls {
		if call != nil {
			output = append(output, call)
		}
	}
	if bw.imageGenerationCall != nil {
		output = append(output, bw.imageGenerationCall)
	}
	out := map[string]any{
		"id":         id,
		"object":     "response",
		"created_at": bw.createdAt,
		"status":     status,
		"model":      model,
		"output":     output,
		"usage": map[string]any{
			"input_tokens":  bw.inputTokens,
			"output_tokens": bw.outputTokens,
			"total_tokens":  bw.inputTokens + bw.outputTokens,
		},
	}
	if bw.cachedTokens > 0 {
		out["usage"].(map[string]any)["input_tokens_details"] = map[string]any{"cached_tokens": bw.cachedTokens}
	}
	if status == "failed" && bw.failure != nil {
		out["error"] = bw.failure
	}
	b, _ := json.Marshal(out)
	return b
}

type responsesToCompletionsWriter struct {
	sseEventBuffer
	err       error
	terminal  bool
	w         io.Writer
	callback  func([]byte)
	debug     bool
	reqID     string
	id        string
	model     string
	createdAt int64
}

func (rw *responsesToCompletionsWriter) Write(p []byte) (int, error) {
	return rw.sseEventBuffer.writeEvents(p, rw.processEvent, &rw.err)
}

func (rw *responsesToCompletionsWriter) processEvent(event []byte) {
	if rw.terminal {
		return
	}
	eventType, data := parseSSEEvent(event)
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
		eventType, _ = obj["type"].(string)
	}
	switch eventType {
	case "response.created":
		if resp, _ := obj["response"].(map[string]any); resp != nil {
			if id, _ := resp["id"].(string); id != "" {
				rw.id = id
			}
			if model, _ := resp["model"].(string); model != "" {
				rw.model = model
			}
			if created := toInt64(resp["created_at"]); created > 0 {
				rw.createdAt = created
			}
		}
	case "response.output_text.delta":
		if delta, _ := obj["delta"].(string); delta != "" {
			rw.emitChunk(delta, "", nil)
		}
	case "response.completed", "response.incomplete":
		rw.terminal = true
		resp, _ := obj["response"].(map[string]any)
		usage := completionsUsageFromResponses(resp)
		finishReason := responseFinishReason(resp)
		rw.emitChunk("", finishReason, usage)
		rw.writeRaw("data: [DONE]\n\n")
	case "response.failed":
		rw.terminal = true
		rw.emitChunk("[Error: response failed]", "stop", nil)
		rw.writeRaw("data: [DONE]\n\n")
	}
}

func (rw *responsesToCompletionsWriter) emitChunk(text, finishReason string, usage map[string]any) {
	id := rw.id
	if id == "" {
		id = "cmpl-translated"
	}
	model := rw.model
	if model == "" {
		model = "unknown"
	}
	choice := map[string]any{"text": text, "index": 0, "logprobs": nil}
	if finishReason != "" {
		choice["finish_reason"] = finishReason
	} else {
		choice["finish_reason"] = nil
	}
	chunk := map[string]any{"id": id, "object": "text_completion.chunk", "created": rw.createdAt, "model": model, "choices": []any{choice}}
	if usage != nil {
		chunk["usage"] = usage
	}
	b, err := json.Marshal(chunk)
	if err != nil {
		return
	}
	rw.writeRaw(fmt.Sprintf("data: %s\n\n", string(b)))
}

func (rw *responsesToCompletionsWriter) writeRaw(s string) {
	writeSSE(rw.w, []byte(s), &rw.err)
	if rw.err != nil && rw.debug {
		log.Printf("[%s] responses->completions write error: %v", rw.reqID, rw.err)
	}
}

type responsesToCompletionsBufferingWriter struct {
	sseEventBuffer
	callback     func([]byte)
	debug        bool
	reqID        string
	id           string
	model        string
	contentText  []byte
	inputTokens  int64
	outputTokens int64
	cachedTokens int64
	createdAt    int64
	finishReason string
	errMsg       string
}

func (bw *responsesToCompletionsBufferingWriter) Write(p []byte) (int, error) {
	return bw.sseEventBuffer.writeEvents(p, bw.processEvent, nil)
}

func (bw *responsesToCompletionsBufferingWriter) processEvent(event []byte) {
	eventType, data := parseSSEEvent(event)
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
		eventType, _ = obj["type"].(string)
	}
	switch eventType {
	case "response.created":
		if resp, _ := obj["response"].(map[string]any); resp != nil {
			if id, _ := resp["id"].(string); id != "" {
				bw.id = id
			}
			if model, _ := resp["model"].(string); model != "" {
				bw.model = model
			}
			if created := toInt64(resp["created_at"]); created > 0 {
				bw.createdAt = created
			}
		}
	case "response.output_text.delta":
		if delta, _ := obj["delta"].(string); delta != "" {
			bw.contentText = append(bw.contentText, delta...)
		}
	case "response.completed", "response.incomplete":
		if resp, _ := obj["response"].(map[string]any); resp != nil {
			if created := toInt64(resp["created_at"]); created > 0 {
				bw.createdAt = created
			}
			if usage, ok := resp["usage"].(map[string]any); ok {
				readResponsesUsage(usage).apply(&bw.inputTokens, &bw.outputTokens, &bw.cachedTokens)
			}
			bw.finishReason = responseFinishReason(resp)
		}
		if bw.finishReason == "" {
			bw.finishReason = "stop"
		}
	case "response.failed":
		bw.errMsg = "response failed"
		if resp, _ := obj["response"].(map[string]any); resp != nil {
			if e, _ := resp["error"].(map[string]any); e != nil {
				if msg, _ := e["message"].(string); msg != "" {
					bw.errMsg = msg
				}
			}
		}
		bw.finishReason = "stop"
	}
}

func (bw *responsesToCompletionsBufferingWriter) Result() []byte {
	id := bw.id
	if id == "" {
		id = "cmpl-translated"
	}
	model := bw.model
	if model == "" {
		model = "unknown"
	}
	text := string(bw.contentText)
	if bw.errMsg != "" {
		text = "[Error: " + bw.errMsg + "]"
	}
	finishReason := bw.finishReason
	if finishReason == "" {
		finishReason = "stop"
	}
	out := map[string]any{
		"id":      id,
		"object":  "text_completion",
		"created": bw.createdAt,
		"model":   model,
		"choices": []any{
			map[string]any{"text": text, "index": 0, "logprobs": nil, "finish_reason": finishReason},
		},
	}
	if bw.inputTokens > 0 || bw.outputTokens > 0 {
		usage := map[string]any{
			"prompt_tokens":     bw.inputTokens,
			"completion_tokens": bw.outputTokens,
			"total_tokens":      bw.inputTokens + bw.outputTokens,
		}
		if bw.cachedTokens > 0 {
			usage["prompt_tokens_details"] = map[string]any{"cached_tokens": bw.cachedTokens}
		}
		out["usage"] = usage
	}
	b, _ := json.Marshal(out)
	return b
}

type responsesToChatCompletionsWriter struct {
	tools responsesToolCalls
	sseEventBuffer
	err      error
	terminal bool
	w        io.Writer
	callback func([]byte)
	debug    bool
	reqID    string

	id           string
	model        string
	inputTokens  int64
	outputTokens int64
	cachedTokens int64
	createdAt    int64
}

func (rw *responsesToChatCompletionsWriter) Write(p []byte) (int, error) {
	return rw.sseEventBuffer.writeEvents(p, rw.processEvent, &rw.err)
}

func (rw *responsesToChatCompletionsWriter) processEvent(event []byte) {
	if rw.terminal {
		return
	}
	eventType, data := parseSSEEvent(event)

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
			if created := toInt64(resp["created_at"]); created > 0 {
				rw.createdAt = created
			}
		}
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
			idx := rw.tools.register(itemID, callID)
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
			callID := rw.tools.eventID(obj)
			idx := rw.toolCallIndexForID(callID)
			rw.tools.noteDelta(callID)
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
		callID := rw.tools.eventID(obj)
		args, _ := obj["arguments"].(string)
		if args != "" && callID != "" && !rw.tools.argDeltas[callID] {
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
		callID := rw.tools.itemID(item)
		args, _ := item["arguments"].(string)
		if args != "" && callID != "" && !rw.tools.argDeltas[callID] {
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

	case "response.completed", "response.incomplete":
		resp, _ := obj["response"].(map[string]any)
		if resp != nil {
			if created := toInt64(resp["created_at"]); created > 0 {
				rw.createdAt = created
			}
			if usage, ok := resp["usage"].(map[string]any); ok {
				readResponsesUsage(usage).apply(&rw.inputTokens, &rw.outputTokens, &rw.cachedTokens)
			}
		}

		rw.terminal = true
		finishReason := responseFinishReason(resp)
		if rw.tools.next > 0 && finishReason == "stop" {
			finishReason = "tool_calls"
		}

		usage := map[string]any{
			"prompt_tokens":     rw.inputTokens,
			"completion_tokens": rw.outputTokens,
			"total_tokens":      rw.inputTokens + rw.outputTokens,
		}
		if rw.cachedTokens > 0 {
			usage["prompt_tokens_details"] = map[string]any{"cached_tokens": rw.cachedTokens}
		}
		rw.emitChunk(map[string]any{}, finishReason, usage)
		rw.writeRaw("data: [DONE]\n\n")

	case "response.failed":
		rw.terminal = true
		resp, _ := obj["response"].(map[string]any)
		errMsg := responseErrorMessage(resp)
		rw.emitChunk(map[string]any{"content": "[Error: " + errMsg + "]"}, "stop", nil)
		rw.writeRaw("data: [DONE]\n\n")

	case "response.output_text.done", "response.content_part.done",
		"response.content_part.added", "response.reasoning_text.done",
		"response.reasoning_summary_text.done", "response.in_progress":

	default:
		if rw.debug {
			log.Printf("[%s] responses->chat: unhandled event type: %s", rw.reqID, eventType)
		}
	}
}

func (rw *responsesToChatCompletionsWriter) toolCallIndexForID(callID string) int {
	if idx, ok := rw.tools.indices[callID]; ok {
		return idx
	}
	idx := rw.tools.next - 1
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
		"created": rw.createdAt,
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
	writeSSE(rw.w, []byte(s), &rw.err)
	if rw.err != nil && rw.debug {
		log.Printf("[%s] responses->chat write error: %v", rw.reqID, rw.err)
	}
}

// The Codex backend requires SSE even when a Chat client requests stream:false.
type responsesToChatCompletionsBufferingWriter struct {
	tools responsesToolCalls
	sseEventBuffer
	callback func([]byte)
	debug    bool
	reqID    string

	id           string
	model        string
	contentText  []byte
	toolCalls    []any
	inputTokens  int64
	outputTokens int64
	finishReason string
	errMsg       string
}

func (bw *responsesToChatCompletionsBufferingWriter) Write(p []byte) (int, error) {
	return bw.sseEventBuffer.writeEvents(p, bw.processEvent, nil)
}

func (bw *responsesToChatCompletionsBufferingWriter) processEvent(event []byte) {
	eventType, data := parseSSEEvent(event)

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
		bw.contentText = append(bw.contentText, delta...)

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
			idx := bw.tools.register(itemID, callID)
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
			callID := bw.tools.eventID(obj)
			idx := bw.toolCallIndexForID(callID)
			bw.tools.noteDelta(callID)
			tc := bw.toolCalls[idx].(map[string]any)
			fn := tc["function"].(map[string]any)
			fn["arguments"] = fn["arguments"].(string) + delta
		}

	case "response.function_call_arguments.done":
		callID := bw.tools.eventID(obj)
		args, _ := obj["arguments"].(string)
		if args != "" && callID != "" && !bw.tools.argDeltas[callID] && len(bw.toolCalls) > 0 {
			tc := bw.toolCalls[bw.toolCallIndexForID(callID)].(map[string]any)
			fn := tc["function"].(map[string]any)
			fn["arguments"] = args
		}

	case "response.output_item.done":
		item, _ := obj["item"].(map[string]any)
		callID := bw.tools.itemID(item)
		args, _ := item["arguments"].(string)
		if args != "" && callID != "" && !bw.tools.argDeltas[callID] && len(bw.toolCalls) > 0 {
			tc := bw.toolCalls[bw.toolCallIndexForID(callID)].(map[string]any)
			fn := tc["function"].(map[string]any)
			fn["arguments"] = args
		}

	case "response.completed", "response.incomplete":
		resp, _ := obj["response"].(map[string]any)
		if resp != nil {
			if usage, ok := resp["usage"].(map[string]any); ok {
				readResponsesUsage(usage).apply(&bw.inputTokens, &bw.outputTokens, nil)
			}
		}
		bw.finishReason = responseFinishReason(resp)
		if bw.tools.next > 0 && bw.finishReason == "stop" {
			bw.finishReason = "tool_calls"
		}

	case "response.failed":
		resp, _ := obj["response"].(map[string]any)
		bw.errMsg = responseErrorMessage(resp)
		bw.finishReason = "stop"
	}
}

func (bw *responsesToChatCompletionsBufferingWriter) toolCallIndexForID(callID string) int {
	if idx, ok := bw.tools.indices[callID]; ok {
		return idx
	}
	idx := bw.tools.next - 1
	if idx < 0 {
		return 0
	}
	if idx >= len(bw.toolCalls) {
		return len(bw.toolCalls) - 1
	}
	return idx
}

func (bw *responsesToChatCompletionsBufferingWriter) Result() []byte {
	id := bw.id
	if id == "" {
		id = "chatcmpl-translated"
	}
	model := bw.model
	if model == "" {
		model = "unknown"
	}

	content := string(bw.contentText)
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

type responsesToClaudeBufferingWriter struct {
	sseEventBuffer
	callback func([]byte)
	debug    bool
	reqID    string

	id           string
	model        string
	contentText  []byte
	toolUses     []map[string]any
	toolIndex    map[string]int
	itemToCallID map[string]string
	inputTokens  int64
	outputTokens int64
	stopReason   string
	errMsg       string
}

func (bw *responsesToClaudeBufferingWriter) Write(p []byte) (int, error) {
	return bw.sseEventBuffer.writeEvents(p, bw.processEvent, nil)
}

func (bw *responsesToClaudeBufferingWriter) processEvent(event []byte) {
	eventType, data := parseSSEEvent(event)

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
				readResponsesUsage(usage).apply(&bw.inputTokens, nil, nil)
			}
		}
	case "response.output_text.delta":
		if delta, _ := obj["delta"].(string); delta != "" {
			bw.contentText = append(bw.contentText, delta...)
		}
	case "response.output_item.added":
		item, _ := obj["item"].(map[string]any)
		if item == nil {
			return
		}
		if itemType, _ := item["type"].(string); itemType == "function_call" {
			callID, _ := item["call_id"].(string)
			itemID, _ := item["id"].(string)
			name, _ := item["name"].(string)
			bw.toolUses = append(bw.toolUses, map[string]any{
				"type":  "tool_use",
				"id":    callID,
				"name":  name,
				"input": map[string]any{},
				"_args": "",
			})
			if bw.toolIndex == nil {
				bw.toolIndex = make(map[string]int)
				bw.itemToCallID = make(map[string]string)
			}
			bw.toolIndex[callID] = len(bw.toolUses) - 1
			if itemID != "" {
				bw.itemToCallID[itemID] = callID
			}
		}
	case "response.function_call_arguments.delta":
		if delta, _ := obj["delta"].(string); delta != "" {
			if index, ok := bw.toolUseIndexForEvent(obj); ok {
				tool := bw.toolUses[index]
				tool["_args"] = tool["_args"].(string) + delta
			}
		}
	case "response.output_item.done":
		if index, ok := bw.toolUseIndexForEvent(obj); ok {
			bw.finishToolUse(index)
		}
	case "response.completed", "response.incomplete":
		resp, _ := obj["response"].(map[string]any)
		if resp != nil {
			if id, ok := resp["id"].(string); ok && bw.id == "" {
				bw.id = id
			}
			if model, ok := resp["model"].(string); ok && bw.model == "" {
				bw.model = model
			}
			if usage, ok := resp["usage"].(map[string]any); ok {
				readResponsesUsage(usage).apply(&bw.inputTokens, &bw.outputTokens, nil)
			}
		}
		bw.stopReason = oaiFinishReasonToClaude(responseFinishReason(resp))
		if len(bw.toolUses) > 0 && responseFinishReason(resp) == "stop" {
			bw.stopReason = "tool_use"
		}
	case "response.failed":
		resp, _ := obj["response"].(map[string]any)
		bw.errMsg = responseErrorMessage(resp)
		bw.stopReason = "end_turn"
	}
}

func (bw *responsesToClaudeBufferingWriter) toolUseIndexForEvent(obj map[string]any) (int, bool) {
	callID, _ := obj["call_id"].(string)
	if callID == "" {
		itemID, _ := obj["item_id"].(string)
		callID = bw.itemToCallID[itemID]
	}
	if callID == "" {
		if item, _ := obj["item"].(map[string]any); item != nil {
			callID, _ = item["call_id"].(string)
			if callID == "" {
				itemID, _ := item["id"].(string)
				callID = bw.itemToCallID[itemID]
			}
		}
	}
	index, ok := bw.toolIndex[callID]
	return index, ok
}

func (bw *responsesToClaudeBufferingWriter) finishToolUse(index int) {
	if index < 0 || index >= len(bw.toolUses) {
		return
	}
	tool := bw.toolUses[index]
	args, _ := tool["_args"].(string)
	delete(tool, "_args")
	if args == "" {
		return
	}
	var input map[string]any
	if json.Unmarshal([]byte(args), &input) == nil {
		tool["input"] = input
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
	text := string(bw.contentText)
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

type claudeToResponsesWriter struct {
	sseEventBuffer
	err      error
	w        io.Writer
	callback func([]byte)
	debug    bool
	reqID    string

	id               string
	model            string
	outputIndex      int
	contentIndex     int
	currentBlockType string
	currentToolID    string
	currentToolName  string
	accumulatedText  string
	accumulatedArgs  string
	inputTokens      int64
	outputTokens     int64
	stopReason       string
	sentMessageItem  bool
}

func (cw *claudeToResponsesWriter) Write(p []byte) (int, error) {
	return cw.sseEventBuffer.writeEvents(p, cw.processEvent, &cw.err)
}

func (cw *claudeToResponsesWriter) processEvent(event []byte) {
	eventType, data := parseSSEEvent(event)

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
			cw.emitEvent("response.content_part.added", map[string]any{
				"type":          "response.content_part.added",
				"output_index":  cw.outputIndex,
				"content_index": cw.contentIndex,
				"part":          map[string]any{"type": "output_text", "text": ""},
			})
		case "thinking":
		case "tool_use":
			id, _ := block["id"].(string)
			name, _ := block["name"].(string)
			name = strings.TrimPrefix(name, "mcp_")
			cw.currentToolID = id
			cw.currentToolName = name
			cw.accumulatedArgs = ""
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
				cw.outputIndex++
				cw.contentIndex = 0
				cw.sentMessageItem = false
			}
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
	}
}

func (cw *claudeToResponsesWriter) emitEvent(eventType string, data map[string]any) {
	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	out := fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, string(b))
	writeSSE(cw.w, []byte(out), &cw.err)
	if cw.err != nil && cw.debug {
		log.Printf("[%s] claude->responses write error: %v", cw.reqID, cw.err)
	}
}

type responsesToClaudeWriter struct {
	sseEventBuffer
	err      error
	terminal bool
	w        io.Writer
	callback func([]byte)
	debug    bool
	reqID    string

	id                string
	model             string
	started           bool
	contentBlockIndex int
	toolCallIndex     int
	sentText          bool
	sentThinking      bool
	inputTokens       int64
	outputTokens      int64
}

func (rw *responsesToClaudeWriter) Write(p []byte) (int, error) {
	return rw.sseEventBuffer.writeEvents(p, rw.processEvent, &rw.err)
}

func (rw *responsesToClaudeWriter) processEvent(event []byte) {
	emitter := claudeBlockEmitter{emit: rw.emitClaudeEvent}
	if rw.terminal {
		return
	}
	eventType, data := parseSSEEvent(event)

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
				readResponsesUsage(usage).apply(&rw.inputTokens, nil, nil)
			}
		}
		rw.started = true
		rw.emitClaudeMessageStart()

	case "response.output_text.delta":
		delta, _ := obj["delta"].(string)
		if delta != "" {
			// Some upstreams begin with a delta rather than response.created.
			if !rw.started {
				rw.started = true
				rw.emitClaudeMessageStart()
			}
			if !rw.sentText {
				rw.sentText = true
				if rw.sentThinking {
					emitter.stop(rw.contentBlockIndex)
					rw.contentBlockIndex++
				}
				emitter.textStart(rw.contentBlockIndex)
			}
			emitter.text(rw.contentBlockIndex, delta)
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
				emitter.thinkingStart(rw.contentBlockIndex)
			}
			emitter.thinking(rw.contentBlockIndex, delta)
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
			if rw.sentText || rw.sentThinking {
				emitter.stop(rw.contentBlockIndex)
				rw.contentBlockIndex++
				rw.sentText = false
				rw.sentThinking = false
			}
			callID, _ := item["call_id"].(string)
			name, _ := item["name"].(string)
			emitter.toolStart(rw.contentBlockIndex, callID, name)
			rw.toolCallIndex++
		}

	case "response.function_call_arguments.delta":
		delta, _ := obj["delta"].(string)
		if delta != "" {
			emitter.arguments(rw.contentBlockIndex, delta)
		}

	case "response.output_item.done":
		item, _ := obj["item"].(map[string]any)
		if item != nil {
			if itemType, _ := item["type"].(string); itemType == "function_call" {
				emitter.stop(rw.contentBlockIndex)
				rw.contentBlockIndex++
			}
		}

	case "response.completed", "response.incomplete":
		resp, _ := obj["response"].(map[string]any)
		if resp != nil {
			if usage, ok := resp["usage"].(map[string]any); ok {
				readResponsesUsage(usage).apply(&rw.inputTokens, &rw.outputTokens, nil)
			}
		}
		if rw.sentText || rw.sentThinking {
			emitter.stop(rw.contentBlockIndex)
		}
		rw.terminal = true
		stopReason := oaiFinishReasonToClaude(responseFinishReason(resp))
		if rw.toolCallIndex > 0 && responseFinishReason(resp) == "stop" {
			stopReason = "tool_use"
		}
		if !rw.started {
			rw.started = true
			rw.emitClaudeMessageStart()
		}
		rw.emitClaudeEvent("message_delta", fmt.Sprintf(
			`{"type":"message_delta","delta":{"stop_reason":%s,"stop_sequence":null},"usage":{"input_tokens":%d,"output_tokens":%d}}`,
			mustMarshalString(stopReason), rw.inputTokens, rw.outputTokens))
		rw.emitClaudeEvent("message_stop", `{"type":"message_stop"}`)

	case "response.failed":
		rw.terminal = true
		resp, _ := obj["response"].(map[string]any)
		errMsg := responseErrorMessage(resp)
		if !rw.sentText {
			rw.sentText = true
			emitter.textStart(rw.contentBlockIndex)
		}
		emitter.text(rw.contentBlockIndex, "[Error: "+errMsg+"]")
		emitter.stop(rw.contentBlockIndex)
		rw.emitClaudeEvent("message_delta", fmt.Sprintf(
			`{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":0}}`))
		rw.emitClaudeEvent("message_stop", `{"type":"message_stop"}`)

	case "response.output_text.done", "response.content_part.done",
		"response.content_part.added", "response.reasoning_text.done",
		"response.reasoning_summary_text.done", "response.function_call_arguments.done",
		"response.in_progress":

	default:
		if rw.debug {
			log.Printf("[%s] responses->claude: unhandled event type: %s", rw.reqID, eventType)
		}
	}
}

func (rw *responsesToClaudeWriter) emitClaudeMessageStart() {
	emitter := claudeBlockEmitter{emit: rw.emitClaudeEvent}
	emitter.messageStart(rw.id, rw.model, rw.inputTokens)
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
	writeSSE(rw.w, []byte(out), &rw.err)
	if rw.err != nil && rw.debug {
		log.Printf("[%s] responses->claude write error: %v", rw.reqID, rw.err)
	}
}
