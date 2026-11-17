package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseSSEEventJoinsMultilineData(t *testing.T) {
	eventType, data := parseSSEEvent([]byte("event: example\r\ndata: first\r\ndata: second\r\n"))
	if eventType != "example" {
		t.Fatalf("event type = %q", eventType)
	}
	if string(data) != "first\nsecond" {
		t.Fatalf("data = %q", data)
	}
}

func TestResponsesToClaudeBufferingWriterTracksInterleavedToolCalls(t *testing.T) {
	writer := &responsesToClaudeBufferingWriter{}
	events := [][]byte{
		[]byte(`event: response.output_item.added
data: {"type":"response.output_item.added","item":{"id":"item-a","type":"function_call","call_id":"call-a","name":"first"}}`),
		[]byte(`event: response.output_item.added
data: {"type":"response.output_item.added","item":{"id":"item-b","type":"function_call","call_id":"call-b","name":"second"}}`),
		[]byte(`event: response.function_call_arguments.delta
data: {"type":"response.function_call_arguments.delta","item_id":"item-a","delta":"{\"value\":"}`),
		[]byte(`event: response.function_call_arguments.delta
data: {"type":"response.function_call_arguments.delta","call_id":"call-b","delta":"{\"value\":2}"}`),
		[]byte(`event: response.function_call_arguments.delta
data: {"type":"response.function_call_arguments.delta","call_id":"call-a","delta":"1}"}`),
	}
	for _, event := range events {
		if _, err := writer.Write(append(event, '\n', '\n')); err != nil {
			t.Fatal(err)
		}
	}

	var result map[string]any
	if err := json.Unmarshal(writer.Result(), &result); err != nil {
		t.Fatal(err)
	}
	want := []any{
		map[string]any{"type": "tool_use", "id": "call-a", "name": "first", "input": map[string]any{"value": float64(1)}},
		map[string]any{"type": "tool_use", "id": "call-b", "name": "second", "input": map[string]any{"value": float64(2)}},
	}
	if !reflect.DeepEqual(result["content"], want) {
		t.Fatalf("interleaved tools = %#v, want %#v", result["content"], want)
	}
}
