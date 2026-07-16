package main

import (
	"encoding/json"
	"testing"
)

func TestTranslateResponsesToClaudePairsParallelToolsAndDropsInvalidHistory(t *testing.T) {
	body := []byte(`{
		"model":"claude-sonnet-4-5",
		"input":[
			{"type":"message","role":"user","content":"start"},
			{"type":"function_call","call_id":"call_one","name":"first","arguments":"{\"value\":1}"},
			{"type":"function_call","call_id":"call_two","name":"second","arguments":"{\"value\":2}"},
			{"type":"function_call","call_id":"call_dangling","name":"missing","arguments":"{}"},
			{"type":"message","role":"user","content":"injected"},
			{"type":"function_call_output","call_id":"call_two","output":"two"},
			{"type":"function_call_output","call_id":"call_orphan","output":"orphan"},
			{"type":"function_call_output","call_id":"call_one","output":"one"},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"done"}]},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"merged"}]}
		]
	}`)

	got := translateResponsesToClaudeForToolPairingTest(t, body)
	messages := got["messages"].([]any)
	if len(messages) != 4 {
		t.Fatalf("messages = %#v, want 4 entries", messages)
	}

	assertClaudeMessageText(t, messages[0], "user", "start")
	assertClaudeToolBlocks(t, messages[1], "assistant", "tool_use", []string{"call_one", "call_two"})
	assertClaudeToolBlocks(t, messages[2], "user", "tool_result", []string{"call_one", "call_two"})
	resultBlocks := messages[2].(map[string]any)["content"].([]any)
	if len(resultBlocks) != 3 || resultBlocks[2].(map[string]any)["text"] != "injected" {
		t.Fatalf("consecutive user content was not merged after tool results: %#v", messages[2])
	}

	last := messages[3].(map[string]any)
	if last["role"] != "assistant" {
		t.Fatalf("last role = %#v, want assistant", last["role"])
	}
	blocks := last["content"].([]any)
	if len(blocks) != 2 || blocks[0].(map[string]any)["text"] != "done" || blocks[1].(map[string]any)["text"] != "merged" {
		t.Fatalf("consecutive assistant messages were not merged: %#v", last)
	}
}

func TestTranslateResponsesToClaudeKeepsAssistantTextWhenDroppingDanglingCall(t *testing.T) {
	body := []byte(`{
		"model":"claude-sonnet-4-5",
		"input":[
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"before call"}]},
			{"type":"function_call","call_id":"call_dangling","name":"missing","arguments":"{}"},
			{"type":"message","role":"user","content":"continue"},
			{"type":"function_call_output","call_id":"call_orphan","output":"orphan"}
		]
	}`)

	got := translateResponsesToClaudeForToolPairingTest(t, body)
	messages := got["messages"].([]any)
	if len(messages) != 2 {
		t.Fatalf("messages = %#v, want 2 entries", messages)
	}
	assertClaudeMessageText(t, messages[0], "assistant", "before call")
	assertClaudeMessageText(t, messages[1], "user", "continue")
}

func translateResponsesToClaudeForToolPairingTest(t *testing.T, body []byte) map[string]any {
	t.Helper()
	out, err := translateResponsesToClaudeRequest(body)
	if err != nil {
		t.Fatalf("translateResponsesToClaudeRequest: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal translated request: %v", err)
	}
	return got
}

func assertClaudeMessageText(t *testing.T, raw any, role, text string) {
	t.Helper()
	message := raw.(map[string]any)
	if message["role"] != role {
		t.Fatalf("role = %#v, want %q", message["role"], role)
	}
	if content, ok := message["content"].(string); ok {
		if content != text {
			t.Fatalf("content = %q, want %q", content, text)
		}
		return
	}
	blocks, ok := message["content"].([]any)
	if !ok || len(blocks) != 1 || blocks[0].(map[string]any)["text"] != text {
		t.Fatalf("content = %#v, want text %q", message["content"], text)
	}
}

func assertClaudeToolBlocks(t *testing.T, raw any, role, blockType string, ids []string) {
	t.Helper()
	message := raw.(map[string]any)
	if message["role"] != role {
		t.Fatalf("role = %#v, want %q", message["role"], role)
	}
	blocks := message["content"].([]any)
	if len(blocks) < len(ids) {
		t.Fatalf("blocks = %#v, want at least %d", blocks, len(ids))
	}
	for i := range ids {
		block := blocks[i].(map[string]any)
		if block["type"] != blockType {
			t.Fatalf("block %d type = %#v, want %q", i, block["type"], blockType)
		}
		idKey := "id"
		if blockType == "tool_result" {
			idKey = "tool_use_id"
		}
		if block[idKey] != ids[i] {
			t.Fatalf("block %d %s = %#v, want %q", i, idKey, block[idKey], ids[i])
		}
	}
}
