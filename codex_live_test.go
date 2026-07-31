package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/url"
	"testing"
)

func TestCodexRealtimeCallIdentity(t *testing.T) {
	if got := codexRealtimeCallIDFromLocation("https://api.openai.com/v1/realtime/calls/rtc_test?foo=bar"); got != "rtc_test" {
		t.Fatalf("location call ID = %q, want rtc_test", got)
	}
	if got := codexRealtimeCallIDFromRequest("/v1/realtime", url.Values{"call_id": []string{"rtc_test"}}); got != "rtc_test" {
		t.Fatalf("query call ID = %q, want rtc_test", got)
	}
	for _, path := range []string{"/live/rtc_test", "/v1/live/rtc_test"} {
		if got := codexRealtimeCallIDFromRequest(path, nil); got != "rtc_test" {
			t.Fatalf("live path %s call ID = %q, want rtc_test", path, got)
		}
	}
	if got := codexRealtimeCallPinKey("rtc_test"); got != "realtime-call:rtc_test" {
		t.Fatalf("pin key = %q", got)
	}
}

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
	var session map[string]any
	if err := json.Unmarshal(parsed.Session, &session); err != nil {
		t.Fatal(err)
	}
	if got, _ := session["model"].(string); got != "gpt-live-1-boulder-alpha" {
		t.Fatalf("Codex Live session model = %q", got)
	}
	if delegation, ok := session["delegation"].(map[string]any); !ok || delegation["type"] != "client" {
		t.Fatalf("session delegation = %#v", session["delegation"])
	}
}
