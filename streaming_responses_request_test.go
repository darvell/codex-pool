package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestStreamCodexResponsesRequestLargePayloadAndFiltering(t *testing.T) {
	huge := strings.Repeat("x", 20*1024*1024)
	src := `{"model":"alias","temperature":0.7,"store":true,"stream":false,` +
		`"input":[{"content":"` + huge + `","type":"message"},{"payload":"secret","type":"mcp_call"}],` +
		`"tools":[{"name":"bad","type":"mcp"},{"name":"ok","type":"function"}],` +
		`"tool_choice":{"server":"bad","type":"mcp"}}`
	got, err := streamCodexResponsesRequest(strings.NewReader(src), 64*1024*1024, func(model string) string {
		if model == "alias" {
			return "gpt-5.6"
		}
		return model
	})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if got.Size < int64(len(huge)) {
		t.Fatalf("spooled size %d", got.Size)
	}
	body, err := io.ReadAll(got.File)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("secret")) || bytes.Contains(body, []byte(`"name":"bad"`)) || bytes.Contains(body, []byte("tool_choice")) {
		t.Fatalf("hosted MCP data survived: tail=%s", body[len(body)-300:])
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["model"] != "gpt-5.6" || obj["store"] != false || obj["stream"] != true || obj["instructions"] != "" {
		t.Fatalf("invariants: %#v", obj)
	}
	if _, ok := obj["temperature"]; ok {
		t.Fatal("temperature survived")
	}
	input := obj["input"].([]any)
	if len(input) != 1 {
		t.Fatalf("input len=%d", len(input))
	}
	if len(input[0].(map[string]any)["content"].(string)) != len(huge) {
		t.Fatal("large payload changed")
	}
}

func TestStreamCodexResponsesRequestWrapsStringInput(t *testing.T) {
	got, err := streamCodexResponsesRequest(strings.NewReader(`{"model":"gpt-5.6","input":"hello\nworld"}`), 64*1024*1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	body, _ := io.ReadAll(got.File)
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	input := obj["input"].([]any)[0].(map[string]any)
	content := input["content"].([]any)[0].(map[string]any)
	if content["text"] != "hello\nworld" {
		t.Fatalf("%#v", content)
	}
}

func TestStreamCodexResponsesRequestFindsTypeAfterHugeField(t *testing.T) {
	huge := strings.Repeat("z", 10*1024*1024)
	src := `{"model":"gpt-5.6","input":[{"payload":"` + huge + `","type":"mcp_approval_response"},{"type":"message","content":"ok"}]}`
	got, err := streamCodexResponsesRequest(strings.NewReader(src), 64*1024*1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	body, _ := io.ReadAll(got.File)
	if bytes.Contains(body, []byte(huge[:1024])) {
		t.Fatal("late-type MCP item survived")
	}
}

func TestStreamCodexResponsesRequestPreservesDefaultFields(t *testing.T) {
	got, err := streamCodexResponsesRequest(strings.NewReader(`{"model":"gpt-5.6","stream":true,"instructions":"hello","custom":{"ok":true}}`), 64*1024*1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	body, _ := io.ReadAll(got.File)
	if !json.Valid(body) {
		t.Fatalf("invalid JSON: %s", body)
	}
	var obj map[string]any
	_ = json.Unmarshal(body, &obj)
	if obj["instructions"] != "hello" {
		t.Fatalf("%#v", obj)
	}
}

func TestStreamCodexResponsesRequestRejectsDuplicateTypeBypass(t *testing.T) {
	_, err := streamCodexResponsesRequest(strings.NewReader(`{"model":"gpt-5.6","stream":true,"input":[{"type":"message","type":"mcp_call","payload":"secret"}]}`), 64*1024*1024, nil)
	if err == nil || !strings.Contains(err.Error(), "duplicate type") {
		t.Fatalf("err=%v", err)
	}
}

func TestStreamCodexResponsesRequestNormalizesToolSchema(t *testing.T) {
	got, err := streamCodexResponsesRequest(strings.NewReader(`{"model":"gpt-5.6","stream":true,"tools":[{"type":"function","name":"x","parameters":{"type":"object"}}]}`), 64*1024*1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	body, _ := io.ReadAll(got.File)
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatal(err)
	}
	params := obj["tools"].([]any)[0].(map[string]any)["parameters"].(map[string]any)
	if params["additionalProperties"] != false || params["properties"] == nil {
		t.Fatalf("%#v", params)
	}
}

func TestStreamCodexResponsesRequestEnforcesSpoolLimit(t *testing.T) {
	_, err := streamCodexResponsesRequest(strings.NewReader(`{"model":"gpt-5.6","stream":true,"input":"`+strings.Repeat("x", 2048)+`"}`), 1024, nil)
	if !errors.Is(err, errResponsesSpoolTooLarge) {
		t.Fatalf("err=%v", err)
	}
}

type repeatedJSONReader struct {
	prefix, suffix []byte
	remaining      int64
	phase          int
}

func (r *repeatedJSONReader) Read(p []byte) (int, error) {
	if r.phase == 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		if len(r.prefix) == 0 {
			r.phase = 1
		}
		return n, nil
	}
	if r.phase == 1 {
		if r.remaining == 0 {
			r.phase = 2
		} else {
			n := len(p)
			if int64(n) > r.remaining {
				n = int(r.remaining)
			}
			for i := 0; i < n; i++ {
				p[i] = 'x'
			}
			r.remaining -= int64(n)
			return n, nil
		}
	}
	if r.phase == 2 {
		n := copy(p, r.suffix)
		r.suffix = r.suffix[n:]
		if len(r.suffix) == 0 {
			r.phase = 3
		}
		return n, nil
	}
	return 0, io.EOF
}
func benchmarkStreamResponses(b *testing.B, size int64) {
	prefix := []byte(`{"model":"gpt-5.6","stream":true,"input":[{"type":"message","content":"`)
	suffix := []byte(`"}]}`)
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := &repeatedJSONReader{prefix: append([]byte(nil), prefix...), suffix: append([]byte(nil), suffix...), remaining: size}
		got, err := streamCodexResponsesRequest(r, size+int64(len(prefix)+len(suffix))+1, nil)
		if err != nil {
			b.Fatal(err)
		}
		got.Close()
	}
}
func BenchmarkStreamResponses16MiB(b *testing.B) { benchmarkStreamResponses(b, 16*1024*1024) }
func BenchmarkStreamResponses64MiB(b *testing.B) { benchmarkStreamResponses(b, 64*1024*1024) }
