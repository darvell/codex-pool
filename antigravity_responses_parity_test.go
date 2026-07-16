package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

type responsesParityEvent struct {
	Name string
	Data map[string]any
}

func writeAntigravityResponsesChunks(t *testing.T, chunks ...string) []responsesParityEvent {
	t.Helper()
	var out bytes.Buffer
	writer := newAntigravityStreamWriter(&out, antigravityFormatResponses, "gemini-3.5-flash")
	for _, chunk := range chunks {
		if _, err := writer.Write([]byte("data: " + chunk + "\n\n")); err != nil {
			t.Fatal(err)
		}
	}
	blocks := strings.Split(strings.TrimSpace(out.String()), "\n\n")
	events := make([]responsesParityEvent, 0, len(blocks))
	for _, block := range blocks {
		lines := strings.Split(block, "\n")
		if len(lines) != 2 {
			t.Fatalf("malformed SSE block %q", block)
		}
		var data map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[1], "data: ")), &data); err != nil {
			t.Fatal(err)
		}
		events = append(events, responsesParityEvent{Name: strings.TrimPrefix(lines[0], "event: "), Data: data})
	}
	return events
}

func TestAntigravityResponsesStreamAggregatesReasoningAndUsesProviderMetadata(t *testing.T) {
	events := writeAntigravityResponsesChunks(t,
		`{"response":{"responseId":"upstream-123","createTime":"2026-07-14T12:34:56.789Z","candidates":[{"content":{"parts":[{"thought":true,"thoughtSignature":"native-signature","text":""}]}}]}}`,
		`{"response":{"responseId":"upstream-123","candidates":[{"content":{"parts":[{"thought":true,"text":"think "}]}}]}}`,
		`{"response":{"responseId":"upstream-123","candidates":[{"content":{"parts":[{"thought":true,"text":"again"}]}}]}}`,
		`{"response":{"responseId":"upstream-123","candidates":[{"content":{"parts":[{"text":"answer"}]},"finishReason":"STOP"}]}}`,
	)

	wantNames := []string{
		"response.created", "response.in_progress", "response.output_item.added",
		"response.reasoning_summary_part.added", "response.reasoning_summary_text.delta",
		"response.reasoning_summary_text.delta", "response.reasoning_summary_text.done",
		"response.reasoning_summary_part.done", "response.output_item.done",
		"response.output_item.added", "response.content_part.added", "response.output_text.delta",
		"response.output_text.done", "response.content_part.done", "response.output_item.done", "response.completed",
	}
	if len(events) != len(wantNames) {
		t.Fatalf("event count = %d, want %d: %#v", len(events), len(wantNames), events)
	}
	for i, want := range wantNames {
		if events[i].Name != want {
			t.Fatalf("event %d = %q, want %q", i, events[i].Name, want)
		}
		if got := int(events[i].Data["sequence_number"].(float64)); got != i+1 {
			t.Fatalf("event %d sequence = %d, want %d", i, got, i+1)
		}
	}
	created := events[0].Data["response"].(map[string]any)
	if created["id"] != "resp_upstream-123" || int64(created["created_at"].(float64)) != 1784032496 {
		t.Fatalf("provider metadata lost: %#v", created)
	}
	reasoningDone := events[8].Data["item"].(map[string]any)
	if reasoningDone["encrypted_content"] != "native-signature" || reasoningDone["summary"].([]any)[0].(map[string]any)["text"] != "think again" {
		t.Fatalf("reasoning was not aggregated: %#v", reasoningDone)
	}
}

func TestAntigravityResponsesStreamClosesItemsBeforeStartingTheNext(t *testing.T) {
	events := writeAntigravityResponsesChunks(t,
		`{"response":{"responseId":"ordered","candidates":[{"content":{"parts":[{"text":"before"},{"functionCall":{"name":"Read"}},{"text":"after"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":4,"candidatesTokenCount":3,"totalTokenCount":7}}}`,
	)

	var messageDone, functionAdded, functionDone, secondMessageAdded int
	messageDone, functionAdded, functionDone, secondMessageAdded = -1, -1, -1, -1
	for i, event := range events {
		switch event.Name {
		case "response.output_text.delta", "response.output_text.done":
			if _, ok := event.Data["logprobs"]; !ok {
				t.Fatalf("%s omitted logprobs: %#v", event.Name, event.Data)
			}
		case "response.output_item.done":
			item := event.Data["item"].(map[string]any)
			if item["type"] == "message" && event.Data["output_index"].(float64) == 0 {
				messageDone = i
			}
			if item["type"] == "function_call" {
				functionDone = i
				if item["arguments"] != "{}" {
					t.Fatalf("parameterless function arguments = %#v, want {}", item["arguments"])
				}
			}
		case "response.output_item.added":
			item := event.Data["item"].(map[string]any)
			if item["type"] == "function_call" {
				functionAdded = i
			}
			if item["type"] == "message" && event.Data["output_index"].(float64) == 2 {
				secondMessageAdded = i
			}
		case "response.completed":
			response := event.Data["response"].(map[string]any)
			output := response["output"].([]any)
			if len(output) != 3 || output[0].(map[string]any)["type"] != "message" || output[1].(map[string]any)["type"] != "function_call" || output[2].(map[string]any)["type"] != "message" {
				t.Fatalf("completed output order is wrong: %#v", output)
			}
			if output[0].(map[string]any)["content"].([]any)[0].(map[string]any)["text"] != "before" || output[2].(map[string]any)["content"].([]any)[0].(map[string]any)["text"] != "after" {
				t.Fatalf("message segments were merged: %#v", output)
			}
		}
	}
	if !(messageDone >= 0 && messageDone < functionAdded && functionAdded < functionDone && functionDone < secondMessageAdded) {
		t.Fatalf("items overlapped: messageDone=%d functionAdded=%d functionDone=%d secondMessageAdded=%d", messageDone, functionAdded, functionDone, secondMessageAdded)
	}
}

func TestAntigravityResponsesNonStreamUsesProviderMetadataAndScaffold(t *testing.T) {
	response := map[string]any{
		"responseId": "native-id",
		"createTime": "2026-07-14T12:34:56.789Z",
		"candidates": []any{map[string]any{
			"content":      map[string]any{"parts": []any{map[string]any{"text": "ok"}}},
			"finishReason": "STOP",
		}},
	}
	got := antigravityGeminiToResponses(response, "gemini-3.5-flash")
	if got["id"] != "resp_native-id" || int64(got["created_at"].(int64)) != 1784032496 {
		t.Fatalf("provider metadata lost: %#v", got)
	}
	if got["background"] != false || got["error"] != nil || got["incomplete_details"] != nil {
		t.Fatalf("response scaffold is incomplete: %#v", got)
	}
	part := got["output"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)
	if _, ok := part["logprobs"]; !ok {
		t.Fatalf("output_text omitted logprobs: %#v", part)
	}
}

func TestAntigravityResponsesStreamEchoesRequestFieldsInCompletedResponse(t *testing.T) {
	var out bytes.Buffer
	writer := newAntigravityStreamWriter(&out, antigravityFormatResponses, "gemini-3.5-flash")
	writer.setResponsesRequest(map[string]any{
		"instructions":        "be exact",
		"parallel_tool_calls": false,
		"metadata":            map[string]any{"trace": "abc"},
	})
	if _, err := writer.Write([]byte("data: " + `{"response":{"candidates":[{"content":{"parts":[{"text":"ok"}]},"finishReason":"STOP"}]}}` + "\n\n")); err != nil {
		t.Fatal(err)
	}
	var completed map[string]any
	for _, block := range strings.Split(strings.TrimSpace(out.String()), "\n\n") {
		lines := strings.Split(block, "\n")
		if strings.TrimPrefix(lines[0], "event: ") != "response.completed" {
			continue
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[1], "data: ")), &completed); err != nil {
			t.Fatal(err)
		}
	}
	response := completed["response"].(map[string]any)
	if response["instructions"] != "be exact" || response["parallel_tool_calls"] != false || response["metadata"].(map[string]any)["trace"] != "abc" {
		t.Fatalf("request fields were not echoed: %#v", response)
	}
}

func TestAntigravityResponsesRestoresMappedFunctionNames(t *testing.T) {
	response := map[string]any{
		"candidates": []any{map[string]any{
			"content": map[string]any{"parts": []any{
				map[string]any{"functionCall": map[string]any{
					"name": "default_api_Read_123456789abc", "id": "call-1", "args": map[string]any{},
				}},
			}},
			"finishReason": "STOP",
		}},
	}
	reverseNames := map[string]string{"default_api_Read_123456789abc": "default_api:Read/with a very long original name"}
	got := antigravityGeminiToResponsesWithRequest(response, "gemini-3.5-flash", nil, reverseNames)
	call := got["output"].([]any)[0].(map[string]any)
	if call["name"] != "default_api:Read/with a very long original name" {
		t.Fatalf("function name = %#v", call["name"])
	}

	var out bytes.Buffer
	writer := newAntigravityStreamWriter(&out, antigravityFormatResponses, "gemini-3.5-flash")
	writer.setResponsesFunctionNames(reverseNames)
	chunk, err := json.Marshal(map[string]any{"response": response})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("data: " + string(chunk) + "\n\n")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"name":"default_api:Read/with a very long original name"`) {
		t.Fatalf("stream did not restore function name: %s", out.String())
	}
}

func TestAntigravityResponsesNonStreamPreservesPartOrder(t *testing.T) {
	response := map[string]any{
		"candidates": []any{map[string]any{
			"content": map[string]any{"parts": []any{
				map[string]any{"text": "before"},
				map[string]any{"functionCall": map[string]any{"name": "Read", "id": "call-1"}},
				map[string]any{"text": "after"},
			}},
			"finishReason": "STOP",
		}},
	}
	got := antigravityGeminiToResponses(response, "gemini-3.5-flash")
	output := got["output"].([]any)
	if len(output) != 3 || output[0].(map[string]any)["type"] != "message" || output[1].(map[string]any)["type"] != "function_call" || output[2].(map[string]any)["type"] != "message" {
		t.Fatalf("output order = %#v", output)
	}
	if output[0].(map[string]any)["content"].([]any)[0].(map[string]any)["text"] != "before" || output[2].(map[string]any)["content"].([]any)[0].(map[string]any)["text"] != "after" {
		t.Fatalf("text segments were merged: %#v", output)
	}
}
