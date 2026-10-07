package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestMistralTranslatedStreamClosesWithoutDone(t *testing.T) {
	var out bytes.Buffer
	w := &sseTranslateWriter{w: &out, direction: TranslateOAIToClaude, finishOnReason: true}
	input := "data: {\"id\":\"msg1\",\"model\":\"mistral-small-latest\",\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"hi\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\n"
	if _, err := w.Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "event: message_stop") || !strings.Contains(out.String(), `"output_tokens":2`) {
		t.Fatalf("incomplete translated stream: %s", out.String())
	}
	if _, err := w.Write([]byte("data: [DONE]\n\n")); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "event: message_stop") != 1 {
		t.Fatalf("duplicate terminal event: %s", out.String())
	}
}

func TestMistralSSEWriterNormalizesStructuredThinkingAndKeepsUsage(t *testing.T) {
	var out bytes.Buffer
	w := &mistralSSEWriter{w: &out}
	input := `data: {"choices":[{"delta":{"content":[{"type":"thinking","thinking":[{"type":"text","text":"private"}]}]}}]}` + "\n\n" +
		`data: {"choices":[{"delta":{"content":[{"type":"text","text":"answer"}]}}],"usage":{"prompt_tokens":4}}` + "\n\n" +
		"data: [DONE]\n\n"
	for _, part := range []string{input[:19], input[19:65], input[65:]} {
		if _, err := w.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(out.String(), "[DONE]") {
		t.Fatalf("stream missing terminator: %s", out.String())
	}
	for _, event := range strings.Split(strings.TrimSpace(out.String()), "\n\n") {
		if strings.Contains(event, "[DONE]") {
			continue
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content   string `json:"content"`
					Reasoning string `json:"reasoning_content"`
				} `json:"delta"`
			} `json:"choices"`
			Usage map[string]any `json:"usage"`
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(event, "data: ")), &chunk); err != nil {
			t.Fatal(err)
		}
		if len(chunk.Choices) != 1 {
			t.Fatalf("lost choice: %s", event)
		}
		if chunk.Usage == nil && (chunk.Choices[0].Delta.Content != "" || chunk.Choices[0].Delta.Reasoning != "private") {
			t.Fatalf("lost structured thinking: %s", event)
		}
		if chunk.Usage != nil && (chunk.Choices[0].Delta.Content != "answer" || chunk.Usage["prompt_tokens"] != float64(4)) {
			t.Fatalf("lost answer or usage: %s", event)
		}
	}
}

func TestMistralReasoningRoundTripsAcrossToolTurn(t *testing.T) {
	// First expose Mistral's native thinking block in the generic field Pi
	// records from the streamed assistant tool-call turn.
	chunk := normalizeMistralChunk([]byte(`{"choices":[{"delta":{"content":[{"type":"thinking","thinking":[{"type":"text","text":"inspect notes"}]}],"tool_calls":[{"index":0,"id":"call_notes","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"notes.txt\"}"}}]}}]}`))
	var normalized map[string]any
	if err := json.Unmarshal(chunk, &normalized); err != nil {
		t.Fatal(err)
	}
	delta := normalized["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)
	if delta["reasoning_content"] != "inspect notes" {
		t.Fatalf("outgoing reasoning was not normalized: %#v", delta)
	}

	// Then model the next request: Pi replays that generic assistant message
	// together with its tool call, followed by the linked tool result.
	replay := map[string]any{
		"model": "mistral/magistral-medium-latest",
		"messages": []any{
			map[string]any{
				"role":              "assistant",
				"content":           nil,
				"reasoning_content": delta["reasoning_content"],
				"tool_calls": []any{map[string]any{
					"id": "call_notes", "type": "function",
					"function": map[string]any{"name": "read_file", "arguments": `{"path":"notes.txt"}`},
				}},
			},
			map[string]any{"role": "tool", "tool_call_id": "call_notes", "content": "hello"},
		},
	}
	replayJSON, err := json.Marshal(replay)
	if err != nil {
		t.Fatal(err)
	}
	var upstream map[string]any
	if err := json.Unmarshal(rewriteMistralRequestBody(replayJSON, "mistral/magistral-medium-latest"), &upstream); err != nil {
		t.Fatal(err)
	}
	messages := upstream["messages"].([]any)
	assistant := messages[0].(map[string]any)
	if _, present := assistant["reasoning_content"]; present {
		t.Fatalf("generic reasoning leaked upstream: %#v", assistant)
	}
	content := assistant["content"].([]any)
	thinking := content[0].(map[string]any)
	parts := thinking["thinking"].([]any)
	if thinking["type"] != "thinking" || parts[0].(map[string]any)["text"] != "inspect notes" {
		t.Fatalf("reasoning was not restored to native shape: %#v", content)
	}
	if assistant["tool_calls"].([]any)[0].(map[string]any)["id"] != "call_notes" || messages[1].(map[string]any)["tool_call_id"] != "call_notes" {
		t.Fatalf("tool linkage was not preserved: %#v", messages)
	}
}
