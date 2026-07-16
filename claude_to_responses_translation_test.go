package main

import (
	"encoding/json"
	"testing"
)

func TestClaudeToResponsesUsesCodexCompatibleRequestShape(t *testing.T) {
	body := []byte(`{
		"model":"gpt-5.6-luna",
		"max_tokens":8,
		"temperature":0.2,
		"top_p":0.8,
		"system":[
			{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.161.abc; cc_entrypoint=cli;"},
			{"type":"text","text":"Keep answers terse."}
		],
		"tool_choice":{"type":"tool","name":"lookup"},
		"tools":[{"name":"lookup","description":"Lookup","input_schema":{"type":"object"}}],
		"messages":[{"role":"user","content":"hello"}]
	}`)

	out, err := translateClaudeToResponsesRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["temperature"]; ok {
		t.Fatalf("reasoning model received temperature: %#v", got)
	}
	if _, ok := got["top_p"]; ok {
		t.Fatalf("reasoning model received top_p: %#v", got)
	}
	if _, ok := got["max_output_tokens"]; ok {
		t.Fatalf("Codex backend does not accept max_output_tokens: %#v", got)
	}
	if got["parallel_tool_calls"] != true || got["store"] != false {
		t.Fatalf("missing Responses defaults: %#v", got)
	}
	choice := got["tool_choice"].(map[string]any)
	if choice["type"] != "function" || choice["name"] != "lookup" {
		t.Fatalf("tool_choice = %#v", choice)
	}
	input := got["input"].([]any)
	developer := input[0].(map[string]any)
	if developer["role"] != "developer" {
		t.Fatalf("first input item = %#v", developer)
	}
	content := developer["content"].([]any)
	if len(content) != 1 || content[0].(map[string]any)["text"] != "Keep answers terse." {
		t.Fatalf("developer content = %#v", content)
	}
}

func TestClaudeToResponsesMapsServerWebSearchTool(t *testing.T) {
	body := []byte(`{
		"model":"gpt-5.6-luna",
		"tools":[{"type":"web_search_20250305","name":"web_search"}],
		"messages":[{"role":"user","content":"search"}]
	}`)
	out, err := translateClaudeToResponsesRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	tools := got["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["type"] != "web_search" {
		t.Fatalf("tools = %#v", tools)
	}
}
