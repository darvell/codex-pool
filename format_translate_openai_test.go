package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTranslateCompletionsToResponses(t *testing.T) {
	body := []byte(`{
		"model":"gpt-5.4-mini",
		"prompt":"say hi",
		"max_tokens":4,
		"temperature":0.2,
		"stream":false,
		"stop":["END"]
	}`)

	out, err := translateCompletionsToResponses(body)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, out)
	}
	if got["model"] != "gpt-5.4-mini" {
		t.Fatalf("model = %#v", got["model"])
	}
	if stream, _ := got["stream"].(bool); !stream {
		t.Fatalf("stream = %#v, want true", got["stream"])
	}
	if store, _ := got["store"].(bool); store {
		t.Fatalf("store = %#v, want false", got["store"])
	}
	if _, ok := got["max_tokens"]; ok {
		t.Fatalf("max_tokens should not be forwarded to Codex: %#v", got)
	}
	if _, ok := got["temperature"]; ok {
		t.Fatalf("temperature should not be forwarded to Codex: %#v", got)
	}
	input := got["input"].([]any)
	msg := input[0].(map[string]any)
	content := msg["content"].([]any)
	if content[0].(map[string]any)["text"] != "say hi" {
		t.Fatalf("prompt not converted: %#v", got["input"])
	}
	if key, _ := got["prompt_cache_key"].(string); !strings.HasPrefix(key, "pc_") {
		t.Fatalf("prompt_cache_key missing: %#v", got)
	}
}

func TestTranslateResponsesToCompletions(t *testing.T) {
	body := []byte(`{
		"id":"resp_1",
		"model":"gpt-5.4-mini",
		"status":"completed",
		"output":[{"type":"message","content":[{"type":"output_text","text":"hello"}]}],
		"usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}
	}`)

	out, err := translateResponsesToCompletions(body)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, out)
	}
	if got["object"] != "text_completion" {
		t.Fatalf("object = %#v", got["object"])
	}
	choice := got["choices"].([]any)[0].(map[string]any)
	if choice["text"] != "hello" || choice["finish_reason"] != "stop" {
		t.Fatalf("choice = %#v", choice)
	}
	usage := got["usage"].(map[string]any)
	if usage["prompt_tokens"].(float64) != 3 || usage["completion_tokens"].(float64) != 2 {
		t.Fatalf("usage = %#v", usage)
	}
}

func TestResponsesToCompletionsWriters(t *testing.T) {
	var streamed strings.Builder
	sw := &responsesToCompletionsWriter{w: &streamed}
	_, _ = sw.Write([]byte("event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"model\":\"gpt-5.4-mini\"}}\n\n"))
	_, _ = sw.Write([]byte("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hel\"}\n\n"))
	_, _ = sw.Write([]byte("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"usage\":{\"input_tokens\":1,\"output_tokens\":2,\"total_tokens\":3}}}\n\n"))
	gotStream := streamed.String()
	if !strings.Contains(gotStream, `"object":"text_completion.chunk"`) || !strings.Contains(gotStream, `"text":"hel"`) || !strings.Contains(gotStream, "data: [DONE]") {
		t.Fatalf("bad streamed completions output: %s", gotStream)
	}

	bw := &responsesToCompletionsBufferingWriter{}
	_, _ = bw.Write([]byte("event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"model\":\"gpt-5.4-mini\"}}\n\n"))
	_, _ = bw.Write([]byte("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hel\"}\n\n"))
	_, _ = bw.Write([]byte("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"lo\"}\n\n"))
	_, _ = bw.Write([]byte("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}}\n\n"))
	var got map[string]any
	if err := json.Unmarshal(bw.Result(), &got); err != nil {
		t.Fatalf("unmarshal buffered output: %v", err)
	}
	choice := got["choices"].([]any)[0].(map[string]any)
	if choice["text"] != "hello" {
		t.Fatalf("buffered text = %#v", choice["text"])
	}
}

func TestTranslateChatCompletionsToResponsesHandlesLegacyFunctionsAndHostedSearch(t *testing.T) {
	body := []byte(`{
		"model":"gpt-5.5",
		"messages":[
			{"role":"system","content":[{"type":"text","text":"one"},{"type":"text","text":"two"}]},
			{"role":"user","content":[{"type":"text","text":"look"},{"type":"image_url","image_url":"data:image/png;base64,abc"}]},
			{"role":"assistant","function_call":{"name":"lookup","arguments":"{\"q\":\"x\"}"}},
			{"role":"function","name":"lookup","content":"found"}
		],
		"functions":[{"name":"lookup","parameters":{"type":"object"},"strict":true}],
		"tools":[{"type":"web_search_preview","search_context_size":"low"}],
		"response_format":{"type":"json_schema","json_schema":{"name":"answer","schema":{"type":"object"},"strict":true}},
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
	if key, _ := got["prompt_cache_key"].(string); !strings.HasPrefix(key, "pc_") {
		t.Fatalf("prompt_cache_key missing: %#v", got)
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
	functionTool := tools[1].(map[string]any)
	if functionTool["strict"] != true {
		t.Fatalf("strict function tool flag not preserved: %#v", functionTool)
	}
	params := functionTool["parameters"].(map[string]any)
	if _, ok := params["properties"]; !ok {
		t.Fatalf("object schema missing properties: %#v", params)
	}
	if params["additionalProperties"] != false {
		t.Fatalf("object schema missing additionalProperties=false: %#v", params)
	}
	format := got["text"].(map[string]any)["format"].(map[string]any)
	if format["type"] != "json_schema" || format["name"] != "answer" || format["strict"] != true {
		t.Fatalf("response_format not converted: %#v", got["text"])
	}
	choice := got["tool_choice"].(map[string]any)
	if choice["type"] != "function" || choice["name"] != "lookup" {
		t.Fatalf("tool_choice not converted: %#v", choice)
	}
}

func TestResponsesUsageComputesTotalWhenMissing(t *testing.T) {
	usage := openAIUsageFromResponsesUsage(map[string]any{
		"input_tokens":  float64(7),
		"output_tokens": float64(5),
	})
	if usage["total_tokens"] != int64(12) {
		t.Fatalf("total_tokens = %#v, want 12", usage["total_tokens"])
	}
}

func TestResponsesBufferingWriterPreservesFunctionCalls(t *testing.T) {
	bw := &responsesBufferingWriter{}
	_, _ = bw.Write([]byte("event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"model\":\"gpt-5.5\"}}\n\n"))
	_, _ = bw.Write([]byte("event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"item_1\",\"call_id\":\"call_1\",\"name\":\"lookup\"}}\n\n"))
	_, _ = bw.Write([]byte("event: response.function_call_arguments.done\ndata: {\"type\":\"response.function_call_arguments.done\",\"item_id\":\"item_1\",\"arguments\":\"{\\\"q\\\":\\\"x\\\"}\"}\n\n"))
	_, _ = bw.Write([]byte("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}}\n\n"))

	var got map[string]any
	if err := json.Unmarshal(bw.Result(), &got); err != nil {
		t.Fatalf("unmarshal buffered responses output: %v", err)
	}
	output := got["output"].([]any)
	call := output[0].(map[string]any)
	if call["type"] != "function_call" || call["call_id"] != "call_1" || call["name"] != "lookup" || call["arguments"] != `{"q":"x"}` {
		t.Fatalf("function call not preserved: %#v", output)
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
