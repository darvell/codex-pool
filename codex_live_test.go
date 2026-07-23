package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"testing"
)

func TestRewriteCodexLiveCall(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("sdp", "v=0\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("session", `{"model":"gpt-live-1-boulder-alpha","delegation":{"type":"client"}}`); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := rewriteCodexLiveCall(body.Bytes(), writer.FormDataContentType())
	if err != nil {
		t.Fatalf("rewriteCodexLiveCall: %v", err)
	}
	var parsed struct {
		SDP     string          `json:"sdp"`
		Session json.RawMessage `json:"session"`
	}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.SDP != "v=0\r\n" {
		t.Fatalf("sdp = %q", parsed.SDP)
	}
	if string(parsed.Session) != `{"model":"gpt-live-1-boulder-alpha","delegation":{"type":"client"}}` {
		t.Fatalf("session = %s", parsed.Session)
	}
}
