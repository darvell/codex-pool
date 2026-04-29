package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTranslateChatCompletionsToResponsesHandlesLegacyFunctionsAndHostedSearch(t *testing.T) {
	body := []byte(`{
		"model":"gpt-5.5",
		"messages":[
			{"role":"system","content":[{"type":"text","text":"one"},{"type":"text","text":"two"}]},
			{"role":"user","content":[{"type":"text","text":"look"},{"type":"image_url","image_url":"data:image/png;base64,abc"}]},
			{"role":"assistant","function_call":{"name":"lookup","arguments":"{\"q\":\"x\"}"}},
			{"role":"function","name":"lookup","content":"found"}
		],
		"functions":[{"name":"lookup","parameters":{"type":"object"}}],
		"tools":[{"type":"web_search_preview","search_context_size":"low"}],
		"tool_choice":{"type":"function","function":{"name":"lookup"}}
	}`)

	out, err := translateChatCompletionsToResponses(body)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, out)
	}
	if got["instructions"] != "one\ntwo" {
		t.Fatalf("instructions = %#v", got["instructions"])
	}
	input := got["input"].([]any)
	user := input[0].(map[string]any)
	content := user["content"].([]any)
	if content[1].(map[string]any)["image_url"] != "data:image/png;base64,abc" {
		t.Fatalf("image content not preserved: %#v", content)
	}
	fnCall := input[1].(map[string]any)
	if fnCall["type"] != "function_call" || fnCall["call_id"] != "fc_lookup" {
		t.Fatalf("legacy function_call not converted: %#v", fnCall)
	}
	fnOut := input[2].(map[string]any)
	if fnOut["type"] != "function_call_output" || fnOut["call_id"] != "fc_lookup" {
		t.Fatalf("legacy function result not converted: %#v", fnOut)
	}
	tools := got["tools"].([]any)
	if tools[0].(map[string]any)["type"] != "web_search" {
		t.Fatalf("hosted search not normalized: %#v", tools[0])
	}
	params := tools[1].(map[string]any)["parameters"].(map[string]any)
	if _, ok := params["properties"]; !ok {
		t.Fatalf("object schema missing properties: %#v", params)
	}
	choice := got["tool_choice"].(map[string]any)
	if choice["type"] != "function" || choice["name"] != "lookup" {
		t.Fatalf("tool_choice not converted: %#v", choice)
	}
}

func TestResponsesToChatCompletionsWriterHandlesItemIDToolArgumentDone(t *testing.T) {
	var out strings.Builder
	writer := &responsesToChatCompletionsWriter{w: &out}
	_, _ = writer.Write([]byte("event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"model\":\"gpt-5.5\"}}\n\n"))
	_, _ = writer.Write([]byte("event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"item_1\",\"call_id\":\"call_1\",\"name\":\"lookup\"}}\n\n"))
	_, _ = writer.Write([]byte("event: response.function_call_arguments.done\ndata: {\"type\":\"response.function_call_arguments.done\",\"item_id\":\"item_1\",\"arguments\":\"{\\\"q\\\":\\\"x\\\"}\"}\n\n"))
	_, _ = writer.Write([]byte("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}}\n\n"))

	got := out.String()
	if !strings.Contains(got, `"id":"call_1"`) || !strings.Contains(got, `"name":"lookup"`) {
		t.Fatalf("tool call start missing: %s", got)
	}
	if !strings.Contains(got, `"arguments":"{\"q\":\"x\"}"`) {
		t.Fatalf("tool arguments from item_id done event missing: %s", got)
	}
	if !strings.Contains(got, `"finish_reason":"tool_calls"`) {
		t.Fatalf("tool finish reason missing: %s", got)
	}
}
