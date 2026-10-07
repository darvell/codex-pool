package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestToolResultKeepsUserContent(t *testing.T) {
	body, err := translateClaudeReqToOpenAI([]byte(`{"model":"mistral/mistral-large-latest","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"call1","content":"42"},{"type":"text","text":"Now summarize the result"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	if len(request.Messages) != 2 || request.Messages[0].Role != "tool" || request.Messages[0].Content != "42" || request.Messages[1].Role != "user" || request.Messages[1].Content != "Now summarize the result" {
		t.Fatalf("lost tool result or user instructions: %s", body)
	}
}

func TestParallelToolStreamKeepsIndices(t *testing.T) {
	var out bytes.Buffer
	writer := &sseTranslateWriter{w: &out, direction: TranslateOAIToClaude, finishOnReason: true}
	chunks := []string{
		`{"choices":[{"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call0","function":{"name":"first","arguments":"{\"value\":"}},{"index":1,"id":"call1","function":{"name":"second","arguments":"{\"value\":"}}]}}]}`,
		`{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"1}"}}]}}]}`,
		`{"choices":[{"delta":{"tool_calls":[{"index":1,"function":{"arguments":"2}"}}]},"finish_reason":"tool_calls"}],"usage":{"completion_tokens":9}}`,
	}
	for _, chunk := range chunks {
		if _, err := writer.Write([]byte("data: " + chunk + "\n\n")); err != nil {
			t.Fatal(err)
		}
	}
	arguments := map[int]string{}
	ids := map[int]string{}
	stopped := map[int]bool{}
	for _, event := range strings.Split(strings.TrimSpace(out.String()), "\n\n") {
		_, data := parseSSEEvent([]byte(event))
		var obj struct {
			Type  string `json:"type"`
			Index int    `json:"index"`
			Block struct {
				ID string `json:"id"`
			} `json:"content_block"`
			Delta struct {
				JSON string `json:"partial_json"`
			} `json:"delta"`
		}
		if err := json.Unmarshal(data, &obj); err != nil {
			t.Fatal(err)
		}
		switch obj.Type {
		case "content_block_start":
			ids[obj.Index] = obj.Block.ID
		case "content_block_delta":
			if stopped[obj.Index] {
				t.Fatalf("delta after block stop: %s", event)
			}
			arguments[obj.Index] += obj.Delta.JSON
		case "content_block_stop":
			if ids[obj.Index] == "" || stopped[obj.Index] {
				t.Fatalf("stop without open block: %s", event)
			}
			stopped[obj.Index] = true
		}
	}
	if ids[0] != "call0" || ids[1] != "call1" || arguments[0] != `{"value":1}` || arguments[1] != `{"value":2}` || !stopped[0] || !stopped[1] {
		t.Fatalf("corrupted parallel tool calls: %s", out.String())
	}
	if strings.Count(out.String(), "event: message_stop") != 1 {
		t.Fatalf("missing terminal event: %s", out.String())
	}
}
