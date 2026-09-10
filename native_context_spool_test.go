package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const spoolTestSession = "123e4567-e89b-12d3-a456-426614174000"

func contextTestSpool(t *testing.T, body string) *streamedResponsesRequest {
	t.Helper()
	spooled, err := streamCodexResponsesRequest(strings.NewReader(body), int64(len(body))+1, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(spooled.Close)
	return spooled
}

func contextSpoolBody(t *testing.T, spooled *streamedResponsesRequest) string {
	t.Helper()
	data, err := io.ReadAll(io.NewSectionReader(spooled.File, 0, spooled.Size))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestContextSpoolMetadata(t *testing.T) {
	metadata := `{"session_id":"` + spoolTestSession + `","counter":9007199254740993,"custom":{"preserve":true}}`
	spooled := contextTestSpool(t, `{"model":"gpt-6-astra","input":[],"client_metadata":`+metadata+`,"reasoning":{"context":"all_turns","effort":"high"}}`)
	if contextSessionID(spooled.contextMetadata) != spoolTestSession || !contextRequested(spooled.contextMetadata) || len(spooled.contextMetadata) != 2 {
		t.Fatalf("context metadata missing: %#v", spooled.contextMetadata)
	}
	if !strings.Contains(contextSpoolBody(t, spooled), metadata) {
		t.Fatal("metadata changed on wire")
	}
}

func TestContextSpoolOpaque(t *testing.T) {
	large := strings.Repeat(`text\\\"\n`, 20000)
	input := `[{"content":[{"type":"input_text","text":"` + large + `"}],"type":"message"},"` + large + `",{"payload":"` + large + `","type":"future_native"},{"output":[{"encrypted_content":"opaque-ciphertext","type":"encrypted_content"},{"text":"` + large + `","type":"input_text"}],"type":"function_call_output"}]`
	spooled := contextTestSpool(t, `{"model":"gpt-6-astra","input":`+input+`}`)
	before := contextSpoolBody(t, spooled)
	var service *nativeContext
	if err := service.prepareSpool("principal", "", spooled); err != nil {
		t.Fatal(err)
	}
	if got := contextSpoolBody(t, spooled); got != before || !strings.Contains(got, input) {
		t.Fatal("opaque input changed")
	}
	if len(spooled.contextMetadata) != 0 || strings.Contains(before, "client_metadata") {
		t.Fatal("routine turn gained context metadata")
	}
}

func TestContextSpoolExpand(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	a, b := contextTestAccount("a", "user-a"), contextTestAccount("b", "user-b")
	s := contextTestService(t, "http://localhost", a, b)
	ownerA, _, _ := contextIdentity(a)
	ownerB, _, _ := contextIdentity(b)
	token, err := s.store.pack("principal", spoolTestSession, []contextResult{
		{Account: ownerA, Value: json.RawMessage(`{"encrypted_output":"native-a","images":[{"data":"aW1hZ2U=","mime_type":"image/png","detail":"high"}]}`)},
		{Account: ownerB, Value: json.RawMessage(`{"encrypted_output":"native-b"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	part, _ := json.Marshal(map[string]any{"type": "encrypted_content", "encrypted_content": token})
	large := strings.Repeat("large text", 20000)
	preserved := `{"type":"input_text","text":"` + large + `","n":9007199254740993}`
	spooled := contextTestSpool(t, `{"model":"gpt-6-astra","input":[{"call_id":"call-1","output":[`+preserved+`,`+string(part)+`,{"type":"encrypted_content","encrypted_content":"opaque"}],"type":"function_call_output"},{"type":"mcp_call","id":"filtered"}],"client_metadata":{"session_id":"`+spoolTestSession+`"},"reasoning":{"context":"all_turns"}}`)
	oldFile, oldName, oldSize := spooled.File, spooled.File.Name(), spooled.Size
	if err := s.prepareSpool("principal", "", spooled); err != nil {
		t.Fatal(err)
	}
	body := contextSpoolBody(t, spooled)
	for _, want := range []string{preserved, "native-a", "native-b", "History partition 1 of 2", "History partition 2 of 2", "data:image/png;base64,aW1hZ2U=", `"encrypted_content":"opaque"`, `"call_id":"call-1"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing expanded or preserved content %q", want[:min(len(want), 80)])
		}
	}
	if strings.Contains(body, contextEnvelopePrefix) || strings.Contains(body, "filtered") || !json.Valid([]byte(body)) {
		t.Fatal("envelope or MCP item leaked, or invalid JSON")
	}
	if spooled.Size != int64(len(body)) || spooled.Size == oldSize {
		t.Fatalf("size=%d actual=%d old=%d", spooled.Size, len(body), oldSize)
	}
	if pos, err := spooled.File.Seek(0, io.SeekCurrent); err != nil || pos != 0 {
		t.Fatalf("position=%d err=%v", pos, err)
	}
	if _, err := oldFile.Stat(); err == nil {
		t.Fatal("old file is still open")
	}
	if _, err := os.Stat(oldName); !os.IsNotExist(err) {
		t.Fatalf("old spool remains: %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(os.TempDir(), "codex-pool-*.json"))
	if !reflect.DeepEqual(files, []string{spooled.File.Name()}) {
		t.Fatalf("scratch files remain: %v", files)
	}
	name := spooled.File.Name()
	spooled.Close()
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Fatalf("Close left spool: %v", err)
	}
}

func TestContextSpoolControlLimit(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	body := `{"input":[],"client_metadata":{"extra":"` + strings.Repeat("x", contextRequestLimit) + `"}}`
	if _, err := streamCodexResponsesRequest(strings.NewReader(body), int64(len(body))+1, nil); err == nil {
		t.Fatal("oversized metadata accepted")
	}
	files, _ := filepath.Glob(filepath.Join(os.TempDir(), "codex-pool-*.json"))
	if len(files) != 0 {
		t.Fatalf("failed metadata capture left scratch files: %v", files)
	}
}

func TestContextSpoolExpansionBudget(t *testing.T) {
	a := contextTestAccount("a", "user-a")
	s := contextTestService(t, "http://localhost", a)
	owner, _, _ := contextIdentity(a)
	token, err := s.store.pack("principal", spoolTestSession, []contextResult{{Account: owner, Value: json.RawMessage(`{"encrypted_output":"native"}`)}})
	if err != nil {
		t.Fatal(err)
	}
	part, _ := json.Marshal(map[string]any{"type": "encrypted_content", "encrypted_content": token})
	expanded, _ := json.Marshal(map[string]any{"type": "encrypted_content", "encrypted_content": "native"})
	rewrite := &contextSpoolRewrite{service: s, scope: "principal", metadata: contextInference(spoolTestSession), expandedBytes: contextExpansionLimit - 2*len(expanded) + 1}
	if err := rewrite.part(newJSONLex(strings.NewReader(string(part))), io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := rewrite.part(newJSONLex(strings.NewReader(string(part))), io.Discard); err == nil {
		t.Fatal("second token reset the request expansion budget")
	}
}

func TestContextSpoolEscapedPrefix(t *testing.T) {
	a := contextTestAccount("a", "user-a")
	s := contextTestService(t, "http://localhost", a)
	owner, _, _ := contextIdentity(a)
	token, err := s.store.pack("principal", spoolTestSession, []contextResult{{Account: owner, Value: json.RawMessage(`{"encrypted_output":"native"}`)}})
	if err != nil {
		t.Fatal(err)
	}
	var escaped strings.Builder
	for _, char := range contextEnvelopePrefix {
		fmt.Fprintf(&escaped, `\u%04x`, char)
	}
	escaped.WriteString(strings.TrimPrefix(token, contextEnvelopePrefix))
	spooled := contextTestSpool(t, `{"input":[{"output":[{"encrypted_content":"`+escaped.String()+`","type":"encrypted_content"}],"type":"function_call_output"}],"client_metadata":{"session_id":"`+spoolTestSession+`"}}`)
	if err := s.prepareSpool("principal", "", spooled); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(contextSpoolBody(t, spooled), `"encrypted_content":"native"`) {
		t.Fatal("escaped envelope was forwarded without expansion")
	}
}

func BenchmarkContextSpool(b *testing.B) {
	for _, size := range []int64{16 << 20, 64 << 20} {
		for _, kind := range []string{"message", "opaque-ciphertext"} {
			b.Run(fmt.Sprintf("%s/%dMiB", kind, size>>20), func(b *testing.B) {
				prefix := `{"input":[{"type":"message","content":"`
				suffix := `"}]}`
				if kind == "opaque-ciphertext" {
					prefix = `{"input":[{"type":"function_call_output","output":[{"type":"encrypted_content","encrypted_content":"`
					suffix = `"}]}]}`
				}
				reader := &repeatedJSONReader{prefix: []byte(prefix), suffix: []byte(suffix), remaining: size}
				spooled, err := streamCodexResponsesRequest(reader, size+int64(len(prefix)+len(suffix))+1, nil)
				if err != nil {
					b.Fatal(err)
				}
				defer spooled.Close()
				var service *nativeContext
				b.SetBytes(size)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := service.prepareSpool("principal", "", spooled); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func TestContextSpoolFailureAtomic(t *testing.T) {
	for _, scenario := range []string{"malformed", "wrong-session", "missing-session", "wrong-scope", "changed-source", "blocked-ip"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			a := contextTestAccount("a", "user-a")
			s := contextTestService(t, "http://localhost", a)
			owner, _, _ := contextIdentity(a)
			token, err := s.store.pack("principal", spoolTestSession, []contextResult{{Account: owner, Value: json.RawMessage(`{"encrypted_output":"native"}`)}})
			if err != nil {
				t.Fatal(err)
			}
			badToken, session, scope := token, spoolTestSession, "principal"
			switch scenario {
			case "malformed":
				badToken = contextEnvelopePrefix + "invalid"
			case "wrong-session":
				session = "223e4567-e89b-12d3-a456-426614174000"
			case "missing-session":
				session = ""
			case "wrong-scope":
				scope = "other"
			case "changed-source":
				a.AccessToken = contextTestAccount("a", "other").AccessToken
			case "blocked-ip":
				a.AllowedSourceIPs = []string{"192.0.2.1"}
			}
			part := func(value string) string {
				encoded, _ := json.Marshal(map[string]any{"type": "encrypted_content", "encrypted_content": value})
				return string(encoded)
			}
			spooled := contextTestSpool(t, `{"input":[{"type":"function_call_output","output":[`+part(token)+`,`+part(badToken)+`]}],"client_metadata":{"session_id":"`+session+`"}}`)
			before, file, size := contextSpoolBody(t, spooled), spooled.File, spooled.Size
			if err := s.prepareSpool(scope, "198.51.100.1", spooled); err == nil {
				t.Fatal("invalid replay accepted")
			}
			if spooled.File != file || spooled.Size != size || contextSpoolBody(t, spooled) != before {
				t.Fatal("failed replay partially mutated spool")
			}
			if pos, err := file.Seek(0, io.SeekCurrent); err != nil || pos != 0 {
				t.Fatalf("failed replay moved position: %d %v", pos, err)
			}
			files, _ := filepath.Glob(filepath.Join(os.TempDir(), "codex-pool-*.json"))
			if !reflect.DeepEqual(files, []string{file.Name()}) {
				t.Fatalf("failure left scratch files: %v", files)
			}
		})
	}
}
