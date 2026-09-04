package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestGrokSpoolParity(t *testing.T) {
	cases := []string{
		`{"model":"grok-4.5-build","metadata":{"a":1},"input":[{"external_web_access":true,"content":"keep"}]}`,
		`{"response_format":{"type":"json_schema","schema":{"external_web_access":true,"properties":{"x":{"type":"string"}}}},"reasoningEffort":" \t high \u2003"}`,
		`{"text":null,"response_format":{"type":"json_object"},"reasoning":null,"reasoningEffort":"high"}`,
		`{"tools":[{"type":"image_generation","description":"drop"}],"tool_choice":"auto","parallel_tool_calls":true}`,
		`{"tools":[],"tool_choice":"auto","parallel_tool_calls":false}`,
		`{"tools":[null,3,"image_generation",{"type":"function","parameters":{"external_web_access":true}},{"type":"image_generation"}],"tool_choice":"auto"}`,
		`{"tools":null,"tool_choice":"auto","reasoningEffort":3}`,
		`{"reasoningEffort":"\t\u2003 ","external_web_access":false}`,
		`{"tools":[{"type":"image_generation","type":"function"},{"type":"function","type":"image_generation"}]}`,
		`{"tools":[{"type":"function"}],"tools":[],"response_format":1,"response_format":2}`,
		`{"nested":{"external_web_access":true,"external_web_access":false,"keep":[{"external_web_access":null,"x":1}]}}`,
		`{"\u0065xternal_web_access":true,"tools":[{"t\u0079pe":"image\u005fgeneration"}],"reasoningEffort":"\\ \" x \n"}`,
		`{"input":"` + strings.Repeat("x", 128*1024) + `","` + strings.Repeat("k", 128*1024) + `":{"external_web_access":true},"reasoningEffort":"  ` + strings.Repeat("e", 128*1024) + `  "}`,
	}
	for _, model := range []string{"grok-4.5-build", "grok-4.6"} {
		for i, body := range cases {
			t.Run(model+"/"+string(rune('A'+i)), func(t *testing.T) {
				s := newGrokTestSpool(t, strings.NewReader(body), model)
				if err := sanitizeSpooledGrokRequest(s); err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(s.File)
				if err != nil {
					t.Fatal(err)
				}
				var wantValue, gotValue any
				if err := json.Unmarshal(rewriteAndSanitizeGrokRequestBody([]byte(body), model), &wantValue); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(got, &gotValue); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(gotValue, wantValue) {
					t.Fatalf("sanitation differs: got %.1000s", got)
				}
				if s.Size != int64(len(got)) {
					t.Fatalf("size = %d, body = %d", s.Size, len(got))
				}
				if _, err := s.File.Seek(0, io.SeekStart); err != nil {
					t.Fatal(err)
				}
				replay, err := io.ReadAll(s.File)
				if err != nil || !bytes.Equal(got, replay) {
					t.Fatalf("replay differs: %v", err)
				}
			})
		}
	}
}

func newGrokTestSpool(t *testing.T, body io.Reader, model string) *streamedResponsesRequest {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "grok-input-*.json")
	if err != nil {
		t.Fatal(err)
	}
	s := &streamedResponsesRequest{File: f, Model: model}
	t.Cleanup(s.Close)
	s.Size, err = io.Copy(f, body)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Generate the payload before measuring; neither the fixture nor the oracle
// allocates the large string that the sanitizer must leave on disk.
func TestGrokSpoolBoundedMemory(t *testing.T) {
	const payloadSize = 16 * 1024 * 1024
	s := newGrokTestSpool(t, io.MultiReader(
		strings.NewReader(`{"model":"grok-4.6","input":"`),
		io.LimitReader(grokRepeatReader{}, payloadSize),
		strings.NewReader(`","metadata":{},"nested":{"external_web_access":true,"keep":1}}`),
	), "grok-4.6")
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := sanitizeSpooledGrokRequest(s); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 4*1024*1024 {
		t.Fatalf("sanitizing a %d-byte string allocated %d bytes", payloadSize, allocated)
	}
	prefix := make([]byte, len(`{"input":"`))
	if _, err := io.ReadFull(s.File, prefix); err != nil || string(prefix) != `{"input":"` {
		t.Fatalf("prefix = %q, error = %v", prefix, err)
	}
	if n, err := io.CopyN(io.Discard, s.File, payloadSize); err != nil || n != payloadSize {
		t.Fatalf("payload = %d, error = %v", n, err)
	}
	tail, err := io.ReadAll(s.File)
	if err != nil || string(tail) != `","nested":{"keep":1},"model":"grok-4.6"}` {
		t.Fatalf("tail = %q, error = %v", tail, err)
	}
}

func TestGrokSpoolOpaqueJSON(t *testing.T) {
	for _, body := range []string{
		`{"model":"grok-4.6","input":"invalid \x escape","metadata":{}}`,
		`{"model":"grok-4.6","input":1e999,"metadata":{}}`,
	} {
		s := newGrokTestSpool(t, strings.NewReader(body), "grok-4.6")
		if err := sanitizeSpooledGrokRequest(s); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(s.File)
		if err != nil || !bytes.Equal(got, rewriteAndSanitizeGrokRequestBody([]byte(body), s.Model)) {
			t.Fatalf("opaque body changed: %q, error = %v", got, err)
		}
	}
}

func TestGrokSpoolLargeFields(t *testing.T) {
	const payloadSize = 8 * 1024 * 1024
	cases := []struct {
		name, prefix, suffix string
	}{
		{"key", `{"`, `":{"external_web_access":true}}`},
		{"effort", `{"reasoningEffort":"  `, `  "}`},
		{"schema", `{"tools":[{"type":"function","parameters":{"description":"`, `","external_web_access":true}}]}`},
		{"type", `{"tools":[{"type":"`, `","external_web_access":true}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newGrokTestSpool(t, io.MultiReader(
				strings.NewReader(tc.prefix), io.LimitReader(grokRepeatReader{}, payloadSize), strings.NewReader(tc.suffix),
			), "grok-4.5")
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			if err := sanitizeSpooledGrokRequest(s); err != nil {
				t.Fatal(err)
			}
			runtime.ReadMemStats(&after)
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 4*1024*1024 {
				t.Fatalf("sanitizing large %s allocated %d bytes", tc.name, allocated)
			}
			if s.Size < payloadSize {
				t.Fatalf("large %s was lost: size = %d", tc.name, s.Size)
			}
		})
	}
}

func TestGrokSpoolFileOwnership(t *testing.T) {
	s := newGrokTestSpool(t, strings.NewReader(`{"model":"grok-4.6","metadata":{}}`), "grok-4.6")
	s.ClientWantsNonStreaming = true
	original := s.File.Name()
	if err := sanitizeSpooledGrokRequest(s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(original); !os.IsNotExist(err) {
		t.Fatalf("original spool still exists: %v", err)
	}
	if s.Model != "grok-4.6" || !s.ClientWantsNonStreaming {
		t.Fatal("rewrite changed routing metadata")
	}
	replacement := s.File.Name()
	s.Close()
	if _, err := os.Stat(replacement); !os.IsNotExist(err) {
		t.Fatalf("replacement spool still exists after Close: %v", err)
	}
}

func TestGrokSpoolFailureKeepsInput(t *testing.T) {
	body := `{"model":"grok-4.6","metadata":{}}`
	s := newGrokTestSpool(t, strings.NewReader(body), "grok-4.6")
	original := s.File
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	if err := sanitizeSpooledGrokRequest(s); err == nil {
		t.Fatal("expected replacement creation to fail")
	}
	if s.File != original || s.Size != int64(len(body)) {
		t.Fatal("failed rewrite changed the spool")
	}
	if _, err := s.File.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(s.File)
	if err != nil || string(got) != body {
		t.Fatalf("original body = %q, error = %v", got, err)
	}
}

func TestGrokSpoolPipeline(t *testing.T) {
	body := `{"model":"grok-4.5-build","stream":true,"input":"hello","response_format":{"type":"json_object"},"reasoningEffort":" high ","tools":[{"type":"image_generation"},{"type":"web_search","external_web_access":true}]}`
	s, err := streamCodexResponsesRequest(strings.NewReader(body), 1024*1024, grokCanonicalModel)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	before, err := io.ReadAll(s.File)
	if err != nil {
		t.Fatal(err)
	}
	if err := sanitizeSpooledGrokRequest(s); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(s.File)
	if err != nil {
		t.Fatal(err)
	}
	var wantValue, gotValue any
	if err := json.Unmarshal(rewriteAndSanitizeGrokRequestBody(before, s.Model), &wantValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("pipeline sanitation differs: %s", got)
	}
}

type grokRepeatReader struct{}

func (grokRepeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
