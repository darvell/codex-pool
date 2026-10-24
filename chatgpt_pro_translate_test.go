package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func proRequest(t *testing.T, input any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(input)
	out, err := translateChatGPTRequest(body, "gpt-6-pro", "parent-id")
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func proTools() []any {
	return []any{map[string]any{"type": "function", "name": "handoff", "description": "Transfer work", "parameters": map[string]any{"type": "object", "properties": map[string]any{"prompt": map[string]any{"type": "string", "description": "Task"}, "reason": map[string]any{"type": "string", "description": "Why"}}, "required": []any{"prompt", "reason"}, "additionalProperties": false}}}
}
func TestChatGPTProRequestShape(t *testing.T) {
	out := proRequest(t, map[string]any{"input": "Hello", "instructions": "Full\nsystem instructions", "tools": proTools()})
	for key, value := range map[string]any{"action": "next", "model": "gpt-6-pro", "parent_message_id": "parent-id", "history_and_training_disabled": true, "is_do_not_remember": true, "temporary_chat_requests_personalization": false} {
		if out[key] != value {
			t.Fatalf("%s = %#v", key, out[key])
		}
	}
	if _, ok := out["supported_encodings"]; ok {
		t.Fatal("must use full snapshots")
	}
	messages := out["messages"].([]any)
	if len(messages) != 2 {
		t.Fatal(messages)
	}
	for i, role := range []string{"system", "user"} {
		message := messages[i].(map[string]any)
		if message["id"] == "" || message["recipient"] != "all" || message["author"].(map[string]any)["role"] != role {
			t.Fatal(message)
		}
	}
	signature := out["local_function_signatures"].([]any)[0].(map[string]any)
	want := map[string]any{"name": "handoff", "description": "Transfer work", "type": "kwargs", "params": []any{map[string]any{"name": "prompt", "required": true, "type": map[string]any{"type": "string", "description": "Task"}}, map[string]any{"name": "reason", "required": true, "type": map[string]any{"type": "string", "description": "Why"}}}}
	if !reflect.DeepEqual(signature, want) {
		t.Fatalf("signature = %#v", signature)
	}
	if !reflect.DeepEqual(out["local_function_names"], []any{"handoff"}) {
		t.Fatal(out)
	}
	empty := proRequest(t, map[string]any{"input": []any{}})
	if len(empty["messages"].([]any)) != 0 || len(empty["local_function_signatures"].([]any)) != 0 {
		t.Fatal(empty)
	}
}
func TestChatGPTProNestedSchema(t *testing.T) {
	schema := map[string]any{"type": "object", "properties": map[string]any{"items": map[string]any{"type": "array", "items": map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "integer", "minimum": 1}}, "required": []any{"value"}}}}, "required": []any{"items"}}
	tools := []any{map[string]any{"type": "function", "name": "nested", "parameters": schema}}
	out := proRequest(t, map[string]any{"tools": tools, "input": "Go"})
	typ := out["local_function_signatures"].([]any)[0].(map[string]any)["params"].([]any)[0].(map[string]any)["type"]
	original, _ := json.Marshal(schema["properties"].(map[string]any)["items"])
	got, _ := json.Marshal(typ)
	if string(original) != string(got) {
		t.Fatalf("nested schema lost: %s", got)
	}
}
func TestChatGPTProTwoTurnTools(t *testing.T) {
	input := []any{
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "input_text", "text": "Do work"}}},
		map[string]any{"type": "function_call", "call_id": "call-a", "name": "handoff", "arguments": "{\"prompt\":\"one\",\"reason\":\"first\"}"},
		map[string]any{"type": "function_call", "call_id": "call-b", "name": "handoff", "arguments": "{\"prompt\":\"two\",\"reason\":\"second\"}"},
		map[string]any{"type": "function_call_output", "call_id": "call-b", "output": "result two"},
		map[string]any{"type": "function_call_output", "call_id": "call-a", "output": "result one"},
		map[string]any{"type": "reasoning", "encrypted_content": "PRIVATE"},
		map[string]any{"role": "developer", "content": "Continue with care"},
	}
	out := proRequest(t, map[string]any{"tools": proTools(), "input": input})
	messages := out["messages"].([]any)
	if len(messages) != 6 {
		t.Fatal(messages)
	}
	call := messages[1].(map[string]any)
	if call["id"] != "call-a" || call["recipient"] != "local.handoff" {
		t.Fatal(call)
	}
	result := messages[3].(map[string]any)
	if result["author"].(map[string]any)["name"] != "handoff" || result["end_turn"] != nil || result["metadata"].(map[string]any)["is_visually_hidden_from_conversation"] != true {
		t.Fatal(result)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(result["content"].(map[string]any)["text"].(string)), &payload); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(payload, map[string]any{"call_id": "call-b", "result": "result two", "tool": "handoff"}) {
		t.Fatal(payload)
	}
	bytes, _ := json.Marshal(out)
	if strings.Contains(string(bytes), "PRIVATE") {
		t.Fatal("reasoning leaked")
	}
}
func TestChatGPTProRejectRequest(t *testing.T) {
	cases := []map[string]any{
		{"tools": []any{map[string]any{"type": "custom", "name": "apply_patch", "format": map[string]any{"type": "grammar", "syntax": "unknown", "definition": "start: /.+/"}}}},
		{"tools": proTools(), "tool_choice": "required"},
		{"tools": proTools(), "tool_choice": map[string]any{"type": "function", "name": "handoff"}},
		{"tools": proTools(), "parallel_tool_calls": false},
		{"previous_response_id": "resp_old"},
		{"input": []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "input_image", "image_url": "url"}}}}},
		{"input": []any{map[string]any{"type": "function_call_output", "call_id": "absent", "output": "result"}}},
		{"tools": proTools(), "input": []any{map[string]any{"type": "function_call", "call_id": "a", "name": "handoff", "arguments": "{}"}}},
		{"tools": []any{map[string]any{"type": "function", "name": "bad", "parameters": map[string]any{"type": "object", "properties": map[string]any{}, "required": []any{"missing"}}}}},
		{"tools": []any{map[string]any{"type": "function", "name": "bad", "parameters": map[string]any{"type": "object", "properties": map[string]any{}, "oneOf": []any{}}}}},
	}
	for i, request := range cases {
		body, _ := json.Marshal(request)
		if _, err := translateChatGPTRequest(body, "model", "parent"); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	out := proRequest(t, map[string]any{"input": "Hi", "tools": proTools(), "tool_choice": "none"})
	if len(out["local_function_names"].([]any)) != 0 {
		t.Fatal("none still advertises tools")
	}
}

func proSnapshot(id, recipient, channel, text, status string, end bool) map[string]any {
	content := map[string]any{"content_type": "text", "parts": []any{text}}
	if strings.HasPrefix(recipient, "local.") || strings.HasPrefix(recipient, "functions.") || strings.HasPrefix(recipient, "function.") {
		content = map[string]any{"content_type": "code", "text": text}
	}
	return map[string]any{"conversation_id": "conv-1", "message": map[string]any{"id": id, "author": map[string]any{"role": "assistant"}, "recipient": recipient, "channel": channel, "content": content, "status": status, "end_turn": end, "metadata": map[string]any{}}}
}
func proFrame(frame any) string {
	body, _ := json.Marshal(frame)
	return "data: " + string(body) + "\r\n\r\n"
}
func proDecode(t *testing.T, wire string, byteChunks bool, definitions ...map[string]bool) (chatGPTStreamState, []map[string]any, error) {
	t.Helper()
	var events []map[string]any
	stream := newChatGPTStream("resp-1", "gpt-6-pro", func(event map[string]any) error { events = append(events, event); return nil }, definitions...)
	if byteChunks {
		for _, b := range []byte(wire) {
			if err := stream.Feed([]byte{b}); err != nil {
				state, _ := stream.Finish()
				return state, events, err
			}
		}
	} else if err := stream.Feed([]byte(wire)); err != nil {
		state, _ := stream.Finish()
		return state, events, err
	}
	state, err := stream.Finish()
	return state, events, err
}
func TestChatGPTProCumulativeStream(t *testing.T) {
	wire := ": keepalive\r\n\r\n" + proFrame(proSnapshot("a", "all", "final", "hé", "in_progress", false)) + proFrame(proSnapshot("a", "all", "final", "héllo", "in_progress", false)) + proFrame(proSnapshot("a", "all", "final", "héllo", "finished_successfully", true)) + "data: [DONE]\r\n\r\n"
	state, events, err := proDecode(t, wire, true)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Completed || state.ConversationID != "conv-1" || len(state.Output) != 1 {
		t.Fatal(state)
	}
	var deltas strings.Builder
	kinds := []string{}
	for i, event := range events {
		if event["sequence_number"] != i {
			t.Fatal(event)
		}
		kinds = append(kinds, event["type"].(string))
		if event["type"] == "response.output_text.delta" {
			deltas.WriteString(event["delta"].(string))
		}
	}
	if deltas.String() != "héllo" {
		t.Fatal(deltas.String())
	}
	want := []string{"response.created", "response.in_progress", "response.output_item.added", "response.content_part.added", "response.output_text.delta", "response.output_text.delta", "response.output_text.done", "response.content_part.done", "response.output_item.done", "response.completed"}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatal(kinds)
	}
	final := events[len(events)-1]["response"].(map[string]any)["output"]
	if !reflect.DeepEqual(final, state.Output) {
		t.Fatal("completed output differs from streamed output")
	}
}
func TestChatGPTProDefaultRecipient(t *testing.T) {
	for _, missing := range []bool{false, true} {
		frame := proSnapshot("answer", "all", "final", "Answer", "finished_successfully", true)
		message := frame["message"].(map[string]any)
		message["recipient"] = nil
		if missing {
			delete(message, "recipient")
		}
		state, _, err := proDecode(t, proFrame(frame)+"data: [DONE]\n\n", true)
		if err != nil || !state.Completed || len(state.Output) != 1 {
			t.Fatalf("native default recipient rejected (missing=%v): %v", missing, err)
		}
		content := state.Output[0]["content"].([]any)[0].(map[string]any)
		if content["text"] != "Answer" {
			t.Fatal("default-recipient message was not emitted as text")
		}
	}
}

func TestChatGPTProParallelToolStream(t *testing.T) {
	wire := proFrame(proSnapshot("a", "local.handoff", "commentary", "{", "in_progress", false)) + proFrame(proSnapshot("b", "functions.handoff", "commentary", "{\"reason\":", "in_progress", false)) + proFrame(proSnapshot("a", "local.handoff", "commentary", "{\"prompt\":\"one\"}", "finished_successfully", false)) + proFrame(proSnapshot("b", "functions.handoff", "commentary", "{\"reason\":\"two\"}", "finished_successfully", false)) + "data: [DONE]\n\n"
	state, events, err := proDecode(t, wire, true, map[string]bool{"handoff": false})
	if err != nil {
		t.Fatal(err)
	}
	if !state.Completed || len(state.Output) != 2 || state.Output[0]["call_id"] != "a" || state.Output[1]["call_id"] != "b" {
		t.Fatal(state)
	}
	counts := map[any]int{}
	args := map[any]string{}
	for _, event := range events {
		if event["type"] == "response.output_item.added" {
			counts[event["output_index"]]++
		}
		if event["type"] == "response.function_call_arguments.delta" {
			args[event["item_id"]] += event["delta"].(string)
		}
	}
	if counts[0] != 1 || counts[1] != 1 || args["fc_a"] != state.Output[0]["arguments"] || args["fc_b"] != state.Output[1]["arguments"] {
		t.Fatal(counts, args)
	}
}
func TestChatGPTProHiddenAndNoFakeCalls(t *testing.T) {
	hidden := proSnapshot("hidden", "all", "final", "SECRET", "finished_successfully", true)
	hidden["message"].(map[string]any)["metadata"] = map[string]any{"is_visually_hidden_from_conversation": true}
	tool := proSnapshot("tool", "all", "final", "SECRET_TOOL", "finished_successfully", true)
	tool["message"].(map[string]any)["author"] = map[string]any{"role": "tool"}
	wire := proFrame(hidden) + proFrame(tool) + proFrame(proSnapshot("thought", "all", "analysis", "SECRET_REASONING", "finished_successfully", true)) + proFrame(proSnapshot("answer", "all", "final", "{\"name\":\"handoff\",\"arguments\":{}}", "finished_successfully", true)) + "data: [DONE]\n\n"
	state, events, err := proDecode(t, wire, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Output) != 1 || state.Output[0]["type"] != "message" {
		t.Fatal(state)
	}
	data, _ := json.Marshal(events)
	if strings.Contains(string(data), "SECRET") {
		t.Fatal("hidden content leaked")
	}
}
func TestChatGPTProHandoff(t *testing.T) {
	wire := proFrame(proSnapshot("a", "all", "final", "Wait", "in_progress", false)) + "event: async_stream_handoff\r\ndata: {\"resume_conversation_token\":\"PRIVATE_TOKEN\",\r\ndata: \"conversation_id\":\"conv-1\"}\r\n\r\ndata: [DONE]\r\n\r\n"
	state, events, err := proDecode(t, wire, true)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Handoff || state.Completed || state.ResumeToken != "PRIVATE_TOKEN" {
		t.Fatal("incorrect handoff state")
	}
	for _, event := range events {
		if event["type"] == "response.completed" {
			t.Fatal("handoff falsely completed")
		}
	}
	data, _ := json.Marshal(events)
	public, _ := json.Marshal(state)
	if strings.Contains(string(data), "PRIVATE_TOKEN") || strings.Contains(string(public), "PRIVATE_TOKEN") {
		t.Fatal("resume token leaked")
	}
}
func TestChatGPTProStreamFailures(t *testing.T) {
	snapshot := func(text, status string) string {
		return proFrame(proSnapshot("a", "all", "final", text, status, true))
	}
	cases := map[string]string{
		"empty":            "data: [DONE]\n\n",
		"unfinished":       snapshot("partial", "in_progress") + "data: [DONE]\n\n",
		"missing done":     snapshot("answer", "finished_successfully"),
		"rewrite":          snapshot("abc", "in_progress") + snapshot("abX", "finished_successfully"),
		"rewrite finished": snapshot("abc", "finished_successfully") + snapshot("abcd", "finished_successfully"),
		"error":            "event: error\ndata: {\"message\":\"sensitive upstream detail\"}\n\n",
		"error field":      "data: {\"error\":{\"code\":\"bad\"}}\n\n",
		"delta":            "event: delta\ndata: {}\n\n",
		"encoding":         "data: {\"type\":\"delta_encoding\"}\n\n",
		"bad arguments":    proFrame(proSnapshot("a", "local.handoff", "commentary", "not JSON", "finished_successfully", false)),
		"failed status":    snapshot("bad", "failed"),
		"commentary only":  proFrame(proSnapshot("a", "all", "commentary", "working", "finished_successfully", true)) + "data: [DONE]\n\n",
		"malformed JSON":   "data: {\n\n",
		"oversized":        "data: " + strings.Repeat("x", chatGPTEventLimit),
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			state, events, err := proDecode(t, wire, true)
			if err == nil {
				t.Fatal("expected error")
			}
			if state.Completed {
				t.Fatal("false completion")
			}
			for _, event := range events {
				if event["type"] == "response.completed" {
					t.Fatal("false completion event")
				}
			}
			if strings.Contains(err.Error(), "sensitive") {
				t.Fatal("error leaked upstream detail")
			}
		})
	}
}
func TestChatGPTProResume(t *testing.T) {
	var events []map[string]any
	stream := newChatGPTStream("resp", "model", func(event map[string]any) error {
		events = append(events, event)
		return nil
	})
	if err := stream.Resume(); err == nil {
		t.Fatal("resumed before handoff")
	}
	first := proFrame(proSnapshot("a", "all", "final", "Par", "in_progress", false)) + "id: 17\ndata: {\"type\":\"resume_conversation_token\",\"token\":\"PRIVATE\"}\n\ndata: {\"type\":\"stream_handoff\"}\n\ndata: [DONE]\n\n"
	if err := stream.Feed([]byte(first)); err != nil {
		t.Fatal(err)
	}
	state, err := stream.Finish()
	if err != nil || !state.Handoff || state.Completed || state.ResumeToken != "PRIVATE" || state.Offset != 17 || state.LastEventID != "17" {
		t.Fatal("incorrect initial handoff", err)
	}
	if err := stream.Resume(); err != nil {
		t.Fatal(err)
	}
	second := "id: 18\n" + proFrame(proSnapshot("a", "all", "final", "Partial answer", "finished_successfully", true)) + "data: [DONE]\n\n"
	if err := stream.Feed([]byte(second)); err != nil {
		t.Fatal(err)
	}
	state, err = stream.Finish()
	if err != nil || !state.Completed || state.Handoff || state.Offset != 18 || len(state.Output) != 1 {
		t.Fatal("incorrect resumed completion", err)
	}
	var text strings.Builder
	adds, created := 0, 0
	for _, event := range events {
		switch event["type"] {
		case "response.output_text.delta":
			text.WriteString(event["delta"].(string))
		case "response.output_item.added":
			adds++
		case "response.created":
			created++
		}
	}
	if text.String() != "Partial answer" || adds != 1 || created != 1 {
		t.Fatal("resume duplicated output", text.String(), adds, created)
	}
	if err := stream.Resume(); err == nil {
		t.Fatal("resumed completed response")
	}
	again, err := stream.Finish()
	if err != nil || len(again.Output) != 1 {
		t.Fatal("Finish is not idempotent", err)
	}
}

const proPatchGrammar = `start: begin_patch patch+ end_patch
begin_patch: "*** Begin Patch" LF
end_patch: "*** End Patch" LF?
patch: "*** Add File: " path LF added_line+
path: /[^\n]+/
added_line: "+" /[^\n]*/ LF
LF: "\n"
`

func proCustomTools() []any {
	return append(proTools(), map[string]any{"type": "custom", "name": "apply_patch", "description": "Apply a patch to files.", "format": map[string]any{"type": "grammar", "syntax": "lark", "definition": proPatchGrammar}})
}

func TestChatGPTProCustomSignature(t *testing.T) {
	out := proRequest(t, map[string]any{"tools": proCustomTools(), "input": "Add hello.txt"})
	signature := out["local_function_signatures"].([]any)[1].(map[string]any)
	wantParams := []any{map[string]any{"name": "input", "required": true, "type": map[string]any{"type": "string"}}}
	if signature["name"] != "apply_patch" || signature["type"] != "kwargs" || !reflect.DeepEqual(signature["params"], wantParams) {
		t.Fatal(signature)
	}
	description := signature["description"].(string)
	if !strings.HasPrefix(description, "Apply a patch to files.") || !strings.Contains(description, proPatchGrammar) {
		t.Fatal("description or exact grammar lost", description)
	}
	for _, tool := range []map[string]any{{"type": "custom", "name": "text"}, {"type": "custom", "name": "text", "format": map[string]any{"type": "text"}}} {
		proRequest(t, map[string]any{"tools": []any{tool}})
	}
}

func TestChatGPTProMixedCustomRoundTrip(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: hello.txt\n+héllo \\\"world\\\"\n+\n*** End Patch\n"
	encoded, _ := json.Marshal(map[string]any{"input": patch})
	args := string(encoded)
	wire := proFrame(proSnapshot("patch-id", "local.apply_patch", "commentary", args[:len(args)/2], "in_progress", false)) +
		proFrame(proSnapshot("json-id", "function.handoff", "commentary", "{", "in_progress", false)) +
		proFrame(proSnapshot("patch-id", "local.apply_patch", "commentary", args, "finished_successfully", false)) +
		proFrame(proSnapshot("json-id", "function.handoff", "commentary", `{"prompt":"Check file","reason":"Verify"}`, "finished_successfully", false)) + "data: [DONE]\n\n"
	state, events, err := proDecode(t, wire, true, map[string]bool{"apply_patch": true, "handoff": false})
	if err != nil || !state.Completed || len(state.Output) != 2 {
		t.Fatal(state, err)
	}
	call := state.Output[0]
	if call["type"] != "custom_tool_call" || call["input"] != patch || call["call_id"] != "patch-id" || state.Output[1]["type"] != "function_call" {
		t.Fatal(state.Output)
	}
	var delta strings.Builder
	dones, adds := 0, 0
	for _, event := range events {
		switch event["type"] {
		case "response.custom_tool_call_input.delta":
			if event["item_id"] != "ct_patch-id" || event["output_index"] != 0 {
				t.Fatal(event)
			}
			delta.WriteString(event["delta"].(string))
		case "response.custom_tool_call_input.done":
			dones++
			if event["input"] != patch {
				t.Fatal(event)
			}
		case "response.output_item.added":
			adds++
		}
	}
	if delta.String() != patch || dones != 1 || adds != 2 {
		t.Fatal(delta.String(), dones, adds)
	}
	input := []any{map[string]any{"role": "user", "content": "Add hello.txt"}, state.Output[0], state.Output[1],
		map[string]any{"type": "function_call_output", "call_id": "json-id", "output": "Verified"},
		map[string]any{"type": "custom_tool_call_output", "call_id": "patch-id", "output": "Success. Updated hello.txt\n"}}
	out := proRequest(t, map[string]any{"tools": proCustomTools(), "input": input})
	messages := out["messages"].([]any)
	callMessage := messages[1].(map[string]any)
	if callMessage["id"] != "patch-id" || callMessage["recipient"] != "local.apply_patch" || callMessage["content"].(map[string]any)["text"] != args {
		t.Fatal(callMessage)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(messages[4].(map[string]any)["content"].(map[string]any)["text"].(string)), &result); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, map[string]any{"call_id": "patch-id", "tool": "apply_patch", "result": "Success. Updated hello.txt\n"}) {
		t.Fatal(result)
	}
}

func TestChatGPTProCustomFailures(t *testing.T) {
	for _, args := range []string{`null`, `[]`, `{}`, `{"input":null}`, `{"input":1}`, `{"input":"patch","extra":true}`, `{"input":"patch"`, `{"input":"patch"} trailing`} {
		wire := proFrame(proSnapshot("a", "local.apply_patch", "commentary", args, "finished_successfully", false)) + "data: [DONE]\n\n"
		state, events, err := proDecode(t, wire, true, map[string]bool{"apply_patch": true})
		if err == nil || state.Completed {
			t.Fatal("accepted malformed custom arguments", args)
		}
		for _, event := range events {
			if strings.HasPrefix(event["type"].(string), "response.custom_tool_call_input.") {
				t.Fatal("invalid input published", event)
			}
		}
	}
	for _, recipient := range []string{"local.unknown", "function.unknown", "functions.unknown", "local.apply_patch", "python"} {
		wire := proFrame(proSnapshot("a", recipient, "commentary", `{"input":"patch"}`, "finished_successfully", false)) + "data: [DONE]\n\n"
		state, events, err := proDecode(t, wire, true)
		if err == nil || state.Completed || len(events) != 0 {
			t.Fatal("undeclared tool accepted", recipient, state, err)
		}
	}
	for _, item := range []map[string]any{
		{"type": "custom_tool_call", "name": "apply_patch", "call_id": "a", "input": nil},
		{"type": "function_call", "name": "apply_patch", "call_id": "a", "arguments": `{}`},
		{"type": "custom_tool_call", "name": "handoff", "call_id": "a", "input": "text"},
		{"type": "custom_tool_call_output", "call_id": "absent", "output": "result"},
	} {
		body, _ := json.Marshal(map[string]any{"tools": proCustomTools(), "input": []any{item}})
		if _, err := translateChatGPTRequest(body, "model", "parent"); err == nil {
			t.Fatal("invalid history accepted", item)
		}
	}
	wire := proFrame(proSnapshot("a", "all", "final", "*** Begin Patch\n*** End Patch", "finished_successfully", true)) + "data: [DONE]\n\n"
	state, _, err := proDecode(t, wire, true, map[string]bool{"apply_patch": true})
	if err != nil || state.Output[0]["type"] != "message" {
		t.Fatal("plain text treated as a call", err)
	}
}

func TestChatGPTProEmitFailure(t *testing.T) {
	expected := fmt.Errorf("writer failed")
	stream := newChatGPTStream("resp", "model", func(map[string]any) error { return expected })
	if err := stream.Feed([]byte(proFrame(proSnapshot("a", "all", "final", "hi", "finished_successfully", true)))); err != expected {
		t.Fatal(err)
	}
	if _, err := stream.Finish(); err != expected {
		t.Fatal(err)
	}
	stream = newChatGPTStream("resp", "model", func(event map[string]any) error {
		if event["type"] == "response.completed" {
			return expected
		}
		return nil
	})
	wire := proFrame(proSnapshot("a", "all", "final", "hi", "finished_successfully", true)) + "data: [DONE]\n\n"
	if err := stream.Feed([]byte(wire)); err != expected {
		t.Fatal(err)
	}
	state, err := stream.Finish()
	if err != expected || state.Completed {
		t.Fatal("completion write failure was reported as complete", err)
	}
}
