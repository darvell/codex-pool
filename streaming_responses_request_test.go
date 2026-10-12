package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
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
	got, err := streamCodexResponsesRequest(strings.NewReader(`{"model":"gpt-5.6","stream":true,"tools":[{"type":"function","name":"x","parameters":{"type":"object","properties":{"nested":{"type":"object","required":null}},"required":null}}]}`), 64*1024*1024, nil)
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
	if required, ok := params["required"].([]any); !ok || len(required) != 0 {
		t.Fatalf("top-level required = %#v", params["required"])
	}
	nested := params["properties"].(map[string]any)["nested"].(map[string]any)
	if required, ok := nested["required"].([]any); !ok || len(required) != 0 {
		t.Fatalf("nested required = %#v", nested["required"])
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
func compressedResponsesBody(t *testing.T, encoding string, body []byte) []byte {
	t.Helper()
	switch encoding {
	case "gzip":
		var out bytes.Buffer
		zw := gzip.NewWriter(&out)
		if _, err := zw.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	case "zstd":
		zw, err := zstd.NewWriter(nil)
		if err != nil {
			t.Fatal(err)
		}
		defer zw.Close()
		return zw.EncodeAll(body, nil)
	default:
		return body
	}
}

func TestResponsesStreamingCompressionAndIndependentLimits(t *testing.T) {
	plain := []byte(`{"model":"gpt-5.6","stream":true,"input":"` + strings.Repeat("image-like-data", 8192) + `"}`)
	for _, encoding := range []string{"gzip", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			wire := compressedResponsesBody(t, encoding, plain)
			decoded, err := decodeResponsesRequest(context.Background(), bytes.NewReader(wire), encoding, int64(len(wire)+1), int64(len(plain)+1024))
			if err != nil {
				t.Fatal(err)
			}
			spooled, err := streamResponsesRequest(decoded, int64(len(plain)+1024), responsesStreamOptions{})
			decoded.Close()
			if err != nil {
				t.Fatal(err)
			}
			defer spooled.Close()
			got, err := io.ReadAll(spooled.File)
			if err != nil || !bytes.Contains(got, []byte(strings.Repeat("image-like-data", 128))) {
				t.Fatalf("decoded payload incomplete: bytes=%d err=%v", len(got), err)
			}

			decoded, err = decodeResponsesRequest(context.Background(), bytes.NewReader(wire), encoding, int64(len(wire)-1), int64(len(plain)+1024))
			if err == nil {
				_, err = io.ReadAll(decoded)
				decoded.Close()
			}
			if !errors.Is(err, errResponsesWireTooLarge) {
				t.Fatalf("wire limit error = %v", err)
			}

			decoded, err = decodeResponsesRequest(context.Background(), bytes.NewReader(wire), encoding, int64(len(wire)+1), int64(len(plain)+1024))
			if err != nil {
				t.Fatal(err)
			}
			_, err = streamResponsesRequest(decoded, 1024, responsesStreamOptions{})
			decoded.Close()
			if !errors.Is(err, errResponsesSpoolTooLarge) {
				t.Fatalf("decoded limit error = %v", err)
			}
		})
	}
}

func TestResponsesPassthroughLexicalModePreservesSemantics(t *testing.T) {
	src := `{"model":"gpt-5.6-high-fast","store":true,"stream":false,"input":"hello","reasoning":{"effort":"xhigh"},"tools":[{"type":"mcp","secret":"drop"},{"type":"function","parameters":{"type":"object","required":null}}]}`
	got, err := streamResponsesRequest(strings.NewReader(src), 1<<20, responsesStreamOptions{passthrough: true})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	body, _ := io.ReadAll(got.File)
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["model"] != "gpt-5.6-high-fast" || obj["store"] != true || obj["stream"] != false || obj["input"] != "hello" {
		t.Fatalf("passthrough semantics changed: %s", body)
	}
	tools := obj["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["parameters"].(map[string]any)["required"] != nil || bytes.Contains(body, []byte("secret")) {
		t.Fatalf("passthrough filtering/schema changed: %s", body)
	}
}

func TestResponsesPooledSuffixAndEffortCap(t *testing.T) {
	src := `{"reasoning":{"effort":"max"},"model":"gpt-5.6-high-fast","stream":true,"input":[]}`
	got, err := streamResponsesRequest(strings.NewReader(src), 1<<20, responsesStreamOptions{effortLimit: "medium"})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	body, _ := io.ReadAll(got.File)
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatal(err)
	}
	reasoning := obj["reasoning"].(map[string]any)
	if obj["model"] != "gpt-5.6" || obj["service_tier"] != "priority" || reasoning["effort"] != "medium" || reasoning["summary"] != "auto" {
		t.Fatalf("pooled controls differ: %s", body)
	}
}

func TestResponsesLexicalAdmissionBounds(t *testing.T) {
	var fields strings.Builder
	fields.WriteString(`{"model":"gpt-5.6"`)
	for i := 0; i < maxResponsesTopLevelFields; i++ {
		fields.WriteString(`,"field`)
		fields.WriteString(fmt.Sprint(i))
		fields.WriteString(`":null`)
	}
	fields.WriteByte('}')
	if got, err := streamResponsesRequest(strings.NewReader(fields.String()), int64(fields.Len()+1), responsesStreamOptions{}); err == nil {
		got.Close()
		t.Fatal("top-level field admission limit was not enforced")
	}

	body := `{"model":"gpt-5.6","stream":true}`
	if got, err := streamResponsesRequest(strings.NewReader(body+" "), int64(len(body)), responsesStreamOptions{}); !errors.Is(err, errResponsesSpoolTooLarge) {
		if got != nil {
			got.Close()
		}
		t.Fatalf("trailing decoded limit error = %v", err)
	}
}

func TestResponsesLexicalValidationAndCleanup(t *testing.T) {
	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "codex-pool-responses-*.json"))
	for _, src := range []string{
		`{"model":"gpt-5.6","input":"bad\x"}`,
		`{"model":"gpt-5.6","input":` + strings.Repeat("[", maxResponsesJSONDepth+2) + `0` + strings.Repeat("]", maxResponsesJSONDepth+2) + `}`,
	} {
		if got, err := streamResponsesRequest(strings.NewReader(src), 1<<20, responsesStreamOptions{}); err == nil {
			got.Close()
			t.Fatalf("malformed input accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	decoded, err := decodeResponsesRequest(ctx, strings.NewReader(`{"model":"gpt-5.6"}`), "", 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := streamResponsesRequest(decoded, 1<<20, responsesStreamOptions{}); !errors.Is(err, context.Canceled) {
		if got != nil {
			got.Close()
		}
		t.Fatalf("cancel error = %v", err)
	}
	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "codex-pool-responses-*.json"))
	if len(after) != len(before) {
		t.Fatalf("temporary files leaked: before=%d after=%d", len(before), len(after))
	}
}

func BenchmarkStreamResponses16MiB(b *testing.B) { benchmarkStreamResponses(b, 16*1024*1024) }
func BenchmarkStreamResponses64MiB(b *testing.B) { benchmarkStreamResponses(b, 64*1024*1024) }
