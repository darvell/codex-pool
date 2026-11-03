package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestCodexToolReplayCollectorMinesToolCallsFromCompleted(t *testing.T) {
	completed := []byte(`{"type":"response.completed","response":{"id":"resp_1","output":[
		{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]},
		{"id":"fc_1","type":"function_call","call_id":"call_1","name":"inspect","arguments":"{}"}
	]}}`)

	var c codexToolReplayCollector
	c.AddEvent("response.completed", completed)

	if len(c.Items()) != 1 {
		t.Fatalf("tool items = %d, want 1", len(c.Items()))
	}
	if got := string(c.Items()[0]); !bytes.Contains([]byte(got), []byte(`"call_id":"call_1"`)) {
		t.Fatalf("tool item lost call_id: %s", got)
	}
	if len(c.AllItems()) != 2 {
		t.Fatalf("all items = %d, want 2", len(c.AllItems()))
	}
}

func TestCodexToolReplayCollectorDeduplicates(t *testing.T) {
	item := []byte(`{"type":"response.output_item.done","item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"x","arguments":"{}"}}`)
	var c codexToolReplayCollector
	c.AddEvent("response.output_item.done", item)
	c.AddEvent("response.output_item.done", item)
	if len(c.AllItems()) != 1 {
		t.Fatalf("all items = %d, want 1", len(c.AllItems()))
	}
}

func TestBuildRedialPayloadReplaysFullTranscript(t *testing.T) {
	history := []json.RawMessage{
		json.RawMessage(`{"type":"message","role":"user","content":[{"type":"input_text","text":"first"}]}`),
		json.RawMessage(`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"first-ok"}]}`),
	}
	request := []byte(`{"type":"response.create","model":"gpt-5.6-sol","previous_response_id":"resp_old","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"second"}]}]}`)

	out := buildRedialPayload(request, history)

	if bytes.Contains(out, []byte(`previous_response_id`)) {
		t.Fatalf("previous_response_id not stripped: %s", out)
	}
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("replay is not valid json: %v\n%s", err, out)
	}
	input := obj["input"].([]any)
	if len(input) != 3 {
		t.Fatalf("input items = %d, want 3: %s", len(input), out)
	}
}

func TestBuildRedialPayloadPrefersClientFullTranscript(t *testing.T) {
	history := []json.RawMessage{
		json.RawMessage(`{"type":"message","role":"user","content":[{"type":"input_text","text":"first"}]}`),
	}
	// The client already resends the full transcript as a prefix.
	request := []byte(`{"type":"response.create","model":"gpt-5.6-sol","previous_response_id":"resp_old","input":[
		{"type":"message","role":"user","content":[{"type":"input_text","text":"first"}]},
		{"type":"message","role":"user","content":[{"type":"input_text","text":"second"}]}
	]}`)

	out := buildRedialPayload(request, history)

	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("replay invalid: %v", err)
	}
	if got := len(obj["input"].([]any)); got != 2 {
		t.Fatalf("input items = %d, want 2 (no duplication): %s", got, out)
	}
}

func TestBuildRedialPayloadFallsBackWhenOutputUncovered(t *testing.T) {
	history := []json.RawMessage{
		json.RawMessage(`{"type":"message","role":"user","content":[{"type":"input_text","text":"first"}]}`),
	}
	// Current input carries a tool output whose call_id has no context item.
	request := []byte(`{"type":"response.create","model":"gpt-5.6-sol","previous_response_id":"resp_old","input":[{"type":"function_call_output","call_id":"orphan","output":"done"}]}`)

	out := buildRedialPayload(request, history)

	if bytes.Contains(out, []byte(`previous_response_id`)) {
		t.Fatalf("expected id strip fallback, got: %s", out)
	}
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("fallback invalid: %v", err)
	}
	// Fallback keeps the original delta input (not the transcript).
	if got := len(obj["input"].([]any)); got != 1 {
		t.Fatalf("fallback input items = %d, want 1: %s", got, out)
	}
}

func TestBuildRedialPayloadNoHistoryStripsID(t *testing.T) {
	request := []byte(`{"type":"response.create","model":"gpt-5.6-sol","previous_response_id":"resp_old","input":"continue"}`)
	out := buildRedialPayload(request, nil)
	if bytes.Contains(out, []byte(`previous_response_id`)) {
		t.Fatalf("previous_response_id not stripped: %s", out)
	}
}

func TestAnalyzeToolOutputCoverage(t *testing.T) {
	items := []json.RawMessage{
		json.RawMessage(`{"type":"function_call","call_id":"call_1","name":"x","arguments":"{}"}`),
		json.RawMessage(`{"type":"function_call_output","call_id":"call_1","output":"done"}`),
	}
	hasOutput, coversAll := analyzeToolOutputCoverage(items)
	if !hasOutput || !coversAll {
		t.Fatalf("coverage = (%v,%v), want (true,true)", hasOutput, coversAll)
	}

	orphan := []json.RawMessage{
		json.RawMessage(`{"type":"function_call_output","call_id":"orphan","output":"done"}`),
	}
	hasOutput, coversAll = analyzeToolOutputCoverage(orphan)
	if !hasOutput || coversAll {
		t.Fatalf("orphan coverage = (%v,%v), want (true,false)", hasOutput, coversAll)
	}
}

func TestCapHistoryBoundsItems(t *testing.T) {
	var items []json.RawMessage
	for i := 0; i < codexReplayHistoryMaxItems+10; i++ {
		items = append(items, json.RawMessage(`{"i":0}`))
	}
	capped := capHistory(items)
	if len(capped) > codexReplayHistoryMaxItems {
		t.Fatalf("capped items = %d, want <= %d", len(capped), codexReplayHistoryMaxItems)
	}
}
