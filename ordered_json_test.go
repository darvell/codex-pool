package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestOrderedMarshal(t *testing.T) {
	m := map[string]any{
		"stream":     true,
		"model":      "claude-sonnet-4-5",
		"max_tokens": 1024,
		"messages":   []any{},
	}
	out, err := orderedMarshal(m, []string{"model", "messages", "max_tokens", "stream"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"model":"claude-sonnet-4-5","messages":[],"max_tokens":1024,"stream":true}`
	if string(out) != want {
		t.Fatalf("ordered JSON = %s, want %s", out, want)
	}
}

func TestOrderedMarshalRemainingKeys(t *testing.T) {
	m := map[string]any{
		"model":  "test",
		"extra":  "value",
		"alpha":  "first",
		"stream": true,
	}
	out, err := orderedMarshal(m, []string{"missing", "model", "stream"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"model":"test","stream":true,"alpha":"first","extra":"value"}`
	if string(out) != want {
		t.Fatalf("remaining key order = %s, want %s", out, want)
	}
}

func TestOrderedMarshalNull(t *testing.T) {
	out, err := orderedMarshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "null" {
		t.Errorf("expected null, got %s", out)
	}
}

func TestOrderedMarshalEmpty(t *testing.T) {
	out, err := orderedMarshal(map[string]any{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "{}" {
		t.Errorf("expected {}, got %s", out)
	}
}

func TestClaudeOrderedBody(t *testing.T) {
	m := map[string]any{
		"stream":   true,
		"model":    "claude-sonnet-4-5",
		"messages": []any{},
		"system":   "hello",
	}
	out, err := claudeOrderedBody(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"model":"claude-sonnet-4-5","messages":[],"system":"hello","stream":true}`
	if string(out) != want {
		t.Fatalf("Claude body = %s, want %s", out, want)
	}
}

func TestOrderedMarshalPreservesValues(t *testing.T) {
	m := map[string]any{
		"model": "claude-sonnet-4-5",
		"nested": map[string]any{
			"deep": []any{1, 2, 3},
		},
		"flag": true,
	}
	out, err := orderedMarshal(m, []string{"model", "nested", "flag"})
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	want := map[string]any{
		"model": "claude-sonnet-4-5",
		"nested": map[string]any{
			"deep": []any{float64(1), float64(2), float64(3)},
		},
		"flag": true,
	}
	if !reflect.DeepEqual(parsed, want) {
		t.Fatalf("decoded values = %#v, want %#v", parsed, want)
	}
}
