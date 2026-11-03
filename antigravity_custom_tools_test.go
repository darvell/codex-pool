package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const applyPatchGrammar = "start: begin_patch hunk+ end_patch\nbegin_patch: \"*** Begin Patch\" LF"

func applyPatchRequest() map[string]any {
	return map[string]any{
		"model": "gemini-3.5-flash",
		"tools": []any{
			map[string]any{"type": "function", "name": "shell", "parameters": map[string]any{"type": "object", "properties": map[string]any{"cmd": map[string]any{"type": "string"}}}},
			map[string]any{"type": "custom", "name": "apply_patch", "description": "Edit files.", "format": map[string]any{"type": "grammar", "syntax": "lark", "definition": applyPatchGrammar}},
		},
		"input": []any{
			map[string]any{"type": "message", "role": "user", "content": "fix the bug"},
			map[string]any{"type": "custom_tool_call", "call_id": "call_patch", "name": "apply_patch", "input": "*** Begin Patch\n*** End Patch"},
			map[string]any{"type": "custom_tool_call_output", "call_id": "call_patch", "output": "Done!"},
			map[string]any{"type": "agent_message", "content": []any{
				map[string]any{"type": "input_text", "text": "Message Type: NEW_TASK\nPayload:\n"},
				map[string]any{"type": "encrypted_content", "encrypted_content": "Review the code"},
			}},
			map[string]any{"type": "agent_message", "content": []any{}},
		},
	}
}

func TestAntigravityResponsesLowersCustomTools(t *testing.T) {
	gemini, err := antigravityResponsesToGemini(applyPatchRequest(), "gemini-3.5-flash")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(gemini)

	var declaration map[string]any
	for _, raw := range anySlice(mapValue(anySlice(gemini["tools"])[0])["functionDeclarations"]) {
		if stringValue(mapValue(raw)["name"]) == "apply_patch" {
			declaration = mapValue(raw)
		}
	}
	if declaration == nil {
		t.Fatalf("apply_patch was not declared: %s", encoded)
	}
	params := mapValue(declaration["parameters"])
	input := mapValue(mapValue(params["properties"])["input"])
	if stringValue(input["type"]) != "string" || len(anySlice(params["required"])) != 1 {
		t.Fatalf("apply_patch parameters = %#v", params)
	}
	description := stringValue(declaration["description"])
	if !strings.HasPrefix(description, "Edit files.") || !strings.Contains(description, applyPatchGrammar) || !strings.Contains(description, "lark") {
		t.Fatalf("apply_patch description lacks the grammar: %q", description)
	}

	contents := anySlice(gemini["contents"])
	if len(contents) != 4 {
		t.Fatalf("contents = %s", encoded)
	}
	call := mapValue(mapValue(anySlice(mapValue(contents[1])["parts"])[0])["functionCall"])
	if call["name"] != "apply_patch" || call["id"] != "call_patch" || mapValue(call["args"])["input"] != "*** Begin Patch\n*** End Patch" {
		t.Fatalf("custom call history = %#v", call)
	}
	response := mapValue(mapValue(anySlice(mapValue(contents[2])["parts"])[0])["functionResponse"])
	if response["name"] != "apply_patch" || response["id"] != "call_patch" {
		t.Fatalf("custom output history = %#v", response)
	}
	agent := mapValue(contents[3])
	if agent["role"] != "user" || stringValue(mapValue(anySlice(agent["parts"])[0])["text"]) != "Message Type: NEW_TASK\nPayload:\nReview the code" {
		t.Fatalf("agent message = %#v", agent)
	}
}

func geminiCallResponse(name string, args map[string]any) map[string]any {
	return map[string]any{"candidates": []any{map[string]any{
		"content":      map[string]any{"parts": []any{map[string]any{"functionCall": map[string]any{"name": name, "id": "call-1", "args": args}}}},
		"finishReason": "STOP",
	}}}
}

func TestAntigravityResponsesRestoresCustomToolCalls(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: a.txt\n+hi\n*** End Patch"
	request := applyPatchRequest()

	got := antigravityGeminiToResponsesWithRequest(geminiCallResponse("apply_patch", map[string]any{"input": patch}), "gemini-3.5-flash", request, nil)
	item := mapValue(anySlice(got["output"])[0])
	if item["type"] != "custom_tool_call" || item["name"] != "apply_patch" || item["input"] != patch || item["call_id"] != "call-1" {
		t.Fatalf("non-stream custom call = %#v", item)
	}

	got = antigravityGeminiToResponsesWithRequest(geminiCallResponse("shell", map[string]any{"cmd": "ls"}), "gemini-3.5-flash", request, nil)
	if item := mapValue(anySlice(got["output"])[0]); item["type"] != "function_call" || item["arguments"] != `{"cmd":"ls"}` {
		t.Fatalf("function call changed: %#v", item)
	}

	var out bytes.Buffer
	writer := newAntigravityStreamWriter(&out, antigravityFormatResponses, "gemini-3.5-flash")
	writer.setResponsesRequest(request)
	chunk, _ := json.Marshal(map[string]any{"response": geminiCallResponse("apply_patch", map[string]any{"input": patch})})
	if _, err := writer.Write([]byte("data: " + string(chunk) + "\n\n")); err != nil {
		t.Fatal(err)
	}
	events := map[string]map[string]any{}
	for _, block := range strings.Split(strings.TrimSpace(out.String()), "\n\n") {
		lines := strings.Split(block, "\n")
		var data map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[1], "data: ")), &data); err != nil {
			t.Fatal(err)
		}
		events[strings.TrimPrefix(lines[0], "event: ")] = data
	}
	if events["response.custom_tool_call_input.done"]["input"] != patch {
		t.Fatalf("stream lacks custom input done: %s", out.String())
	}
	done := mapValue(events["response.output_item.done"]["item"])
	if done["type"] != "custom_tool_call" || done["input"] != patch || done["name"] != "apply_patch" {
		t.Fatalf("stream item = %#v", done)
	}
	completed := anySlice(mapValue(events["response.completed"]["response"])["output"])
	if len(completed) != 1 || mapValue(completed[0])["type"] != "custom_tool_call" {
		t.Fatalf("completed output = %#v", completed)
	}
}

func TestAgentMessageBecomesUserMessage(t *testing.T) {
	body := `{"model":"grok-4","input":[{"type":"message","role":"user","content":"start"},{"type":"agent_message","content":[{"type":"input_text","text":"Payload:\n"},{"type":"encrypted_content","encrypted_content":"task"}]},{"type":"agent_message","content":[]}]}`

	var grok map[string]any
	if err := json.Unmarshal(sanitizeGrokRequestBody([]byte(body), "grok-4"), &grok); err != nil {
		t.Fatal(err)
	}
	input := anySlice(grok["input"])
	if len(input) != 2 || mapValue(input[1])["role"] != "user" || mapValue(input[1])["content"] != "Payload:\ntask" {
		t.Fatalf("grok input = %#v", input)
	}

	claudeBody, err := translateResponsesToClaudeRequest([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	var claude map[string]any
	if err := json.Unmarshal(claudeBody, &claude); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(claudeBody), `"Payload:\ntask"`) || strings.Contains(string(claudeBody), "agent_message") {
		t.Fatalf("claude messages = %s", claudeBody)
	}
}
