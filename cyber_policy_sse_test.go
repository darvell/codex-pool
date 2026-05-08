package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestCyberPolicySSESuppressorDropsEventAndEmitsSyntheticTurn verifies
// the HTTP/SSE Codex path: when an upstream cyber_policy SSE event hits
// the intercept writer, the bytes for that event are dropped and a
// complete synthetic Responses turn (`response.created` … `response.completed`)
// is emitted to the underlying writer instead.
func TestCyberPolicySSESuppressorDropsEventAndEmitsSyntheticTurn(t *testing.T) {
	var clientOut bytes.Buffer
	cancelled := false
	cancel := func() { cancelled = true }

	suppressor := &cyberPolicyHTTPSuppressor{
		reqID:           "sse-test",
		conversationID:  "conv-sse",
		accountID:       "shiv_1",
		underlyingWrite: &clientOut,
		cancel:          cancel,
	}
	intercept := &sseInterceptWriter{
		w:       &clientOut,
		onEvent: suppressor.onEvent,
	}

	// Frame 1: a normal lifecycle event — should pass through.
	if _, err := intercept.Write([]byte(`event: response.created
data: {"type":"response.created","response":{"id":"resp_a"}}

`)); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	// Frame 2: the cyber_policy error — should be dropped, synthetic turn emitted.
	if _, err := intercept.Write([]byte(`event: error
data: {"type":"error","error":{"type":"invalid_request","code":"cyber_policy","message":"This content was flagged for possible cybersecurity risk."}}

`)); err != nil {
		t.Fatalf("write 2: %v", err)
	}

	out := clientOut.String()
	if strings.Contains(out, "cyber_policy") || strings.Contains(out, "cybersecurity") {
		t.Fatalf("client output leaked policy text: %s", out)
	}
	requiredFrames := []string{
		`"type":"response.created"`,
		`"type":"response.in_progress"`,
		`"type":"response.output_item.added"`,
		`"type":"response.output_text.delta"`,
		`"type":"response.completed"`,
	}
	for _, want := range requiredFrames {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in output", want)
		}
	}
	if !cancelled {
		t.Errorf("expected suppressor to call cancel()")
	}

	// Subsequent writes after termination must be silently absorbed.
	pre := clientOut.Len()
	if _, err := intercept.Write([]byte(`event: response.output_text.delta
data: {"type":"response.output_text.delta","delta":"leaked text from upstream after suppression"}

`)); err != nil {
		t.Fatalf("write 3: %v", err)
	}
	if clientOut.Len() != pre {
		t.Errorf("post-termination bytes leaked into output: %s", clientOut.String()[pre:])
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

// TestSyntheticRefusalSSEFramesAreParseable ensures the SSE wrapper we
// emit is well-formed (event:/data: pairs, terminated by \n\n).
func TestSyntheticRefusalSSEFramesAreParseable(t *testing.T) {
	out := syntheticRefusalSSEFrames()
	if !bytes.HasSuffix(out, []byte("\n\n")) {
		tailStart := len(out) - 12
		if tailStart < 0 {
			tailStart = 0
		}
		t.Fatalf("synthetic SSE blob must end with \\n\\n; got tail %q", out[tailStart:])
	}
	for _, want := range []string{
		"event: response.created\ndata:",
		"event: response.in_progress\ndata:",
		"event: response.output_text.delta\ndata:",
		"event: response.completed\ndata:",
	} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("missing SSE block %q", want)
		}
	}
	if bytes.Contains(out, []byte("cyber_policy")) || bytes.Contains(out, []byte("cybersecurity")) {
		t.Fatalf("synthetic SSE must not echo policy text")
	}
}

// TestCyberPolicySSESuppressorWithoutTrailingPartialEvent guards against
// a partial event arriving in the SAME Write() call as a complete
// cyber_policy event. The complete event must be suppressed; the partial
// must be held until completed.
func TestCyberPolicySSESuppressorWithoutTrailingPartialEvent(t *testing.T) {
	var clientOut bytes.Buffer
	suppressor := &cyberPolicyHTTPSuppressor{
		reqID:           "sse-test",
		underlyingWrite: &clientOut,
		cancel:          func() {},
	}
	intercept := &sseInterceptWriter{
		w:       &clientOut,
		onEvent: suppressor.onEvent,
	}
	// Two events in one Write — first cyber_policy (drop), second partial.
	chunk := []byte(`event: error
data: {"type":"error","error":{"type":"invalid_request","code":"cyber_policy","message":"flagged"}}

event: response.output_text.delta
data: {"type":"response.output_text.delta","delta":"`)
	if _, err := intercept.Write(chunk); err != nil {
		t.Fatalf("write: %v", err)
	}
	if strings.Contains(clientOut.String(), "cyber_policy") {
		t.Fatalf("policy bytes leaked")
	}
	// After termination, the partial second event is also discarded.
	pre := clientOut.Len()
	if _, err := intercept.Write([]byte("post-termination text\"}\n\n")); err != nil {
		t.Fatalf("write tail: %v", err)
	}
	if clientOut.Len() != pre {
		t.Errorf("bytes leaked after termination: %s", clientOut.String()[pre:])
	}
}

// suppress unused-import diagnostic on `context` — used by the WS tests file.
var _ = context.Background