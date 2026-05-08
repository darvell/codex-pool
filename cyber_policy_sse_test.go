package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestCyberPolicySSESuppressorForwardsAndPins verifies the HTTP/SSE
// Codex path: an upstream cyber_policy SSE event is forwarded to the
// client unchanged (no fabricated assistant text), the conversation is
// pinned to a cyber_access account so the next turn lands there, and
// the relay does not terminate the stream early.
func TestCyberPolicySSESuppressorForwardsAndPins(t *testing.T) {
	cyber := &Account{ID: "cyber", Type: AccountTypeCodex, CyberAccess: true, AccessToken: "tok"}
	plain := &Account{ID: "plain", Type: AccountTypeCodex, AccessToken: "tok"}
	h := &proxyHandler{
		cfg:     &config{},
		metrics: newMetrics(),
		pool:    newPoolState([]*Account{plain, cyber}, false),
	}

	var clientOut bytes.Buffer
	pinned := false
	suppressor := &cyberPolicyHTTPSuppressor{
		h:              h,
		reqID:          "sse-test",
		conversationID: "conv-sse",
		accountID:      "plain",
		pinned:         &pinned,
	}
	intercept := &sseInterceptWriter{
		w:       &clientOut,
		onEvent: suppressor.onEvent,
	}

	// Frame 1: a normal lifecycle event — passes through.
	if _, err := intercept.Write([]byte(`event: response.created
data: {"type":"response.created","response":{"id":"resp_a"}}

`)); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	// Frame 2: cyber_policy error — must pass through unchanged.
	cyberFrame := `event: error
data: {"type":"error","error":{"type":"invalid_request","code":"cyber_policy","message":"This content was flagged for possible cybersecurity risk."}}

`
	if _, err := intercept.Write([]byte(cyberFrame)); err != nil {
		t.Fatalf("write 2: %v", err)
	}

	out := clientOut.String()
	if !strings.Contains(out, `"code":"cyber_policy"`) {
		t.Fatalf("expected upstream cyber_policy frame to be forwarded; got %s", out)
	}
	if !pinned {
		t.Errorf("expected conversation to be pinned to cyber account")
	}

	// Subsequent writes must continue to pass through (no termination).
	pre := clientOut.Len()
	if _, err := intercept.Write([]byte(`event: response.completed
data: {"type":"response.completed","response":{"id":"resp_a","status":"completed"}}

`)); err != nil {
		t.Fatalf("write 3: %v", err)
	}
	if clientOut.Len() == pre {
		t.Errorf("expected post-cyber_policy frames to keep flowing")
	}

	snap := h.metrics.cyberPolicySnapshot()
	if snap[cyberPolicyKey{"plain", "suppressed_sse"}] == 0 {
		t.Errorf("expected suppressed_sse counter, got %v", snap)
	}
}

// TestSseInterceptWriterLegacyPassthroughUnchanged guards the
// non-Codex / non-suppressing case: when onEvent is nil the writer
// must continue forwarding bytes verbatim like before.
func TestSseInterceptWriterLegacyPassthroughUnchanged(t *testing.T) {
	var sink bytes.Buffer
	var seen [][]byte
	w := &sseInterceptWriter{
		w: &sink,
		callback: func(data []byte) {
			seen = append(seen, append([]byte(nil), data...))
		},
	}
	frames := []string{
		"event: response.created\ndata: {\"type\":\"response.created\"}\n\n",
		"event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n",
	}
	for _, f := range frames {
		if _, err := w.Write([]byte(f)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	want := strings.Join(frames, "")
	if sink.String() != want {
		t.Fatalf("legacy passthrough mismatch:\nwant: %q\ngot:  %q", want, sink.String())
	}
	if len(seen) != 2 {
		t.Errorf("expected 2 callbacks, got %d", len(seen))
	}
}
