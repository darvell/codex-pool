package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestSSESuppressionWriterRejectsUnterminatedOversizedEvent(t *testing.T) {
	var sink bytes.Buffer
	w := &sseInterceptWriter{
		w:       &sink,
		onEvent: func([]byte) (bool, bool) { return false, false },
	}

	_, err := w.Write([]byte("data: " + strings.Repeat("x", sseInterceptMaxBufferedBytes)))
	if err == nil {
		t.Fatal("expected oversized unterminated SSE event to error")
	}
	if sink.Len() != 0 {
		t.Fatalf("unexpected forwarded bytes: %d", sink.Len())
	}
}

func TestSSESuppressionWriterAllowsLargeTerminatedEvent(t *testing.T) {
	var sink bytes.Buffer
	payload := `{"type":"response.completed","response":{"output_text":"` + strings.Repeat("x", sseInterceptMaxBufferedBytes+1) + `"}}`
	seen := 0
	w := &sseInterceptWriter{
		w: &sink,
		onEvent: func(data []byte) (bool, bool) {
			seen++
			if string(data) != payload {
				t.Fatalf("inspection received a different completed event")
			}
			return false, false
		},
	}
	frame := []byte("data: " + payload + "\n\n")
	if len(frame) <= sseInterceptMaxBufferedBytes {
		t.Fatal("completed frame does not exceed the incomplete-event limit")
	}
	if n, err := w.Write(frame); err != nil || n != len(frame) {
		t.Fatalf("write = (%d, %v), want (%d, nil)", n, err, len(frame))
	}
	if seen != 1 || !bytes.Equal(sink.Bytes(), frame) {
		t.Fatalf("completed event: inspected=%d, forwarded=%d bytes, want %d", seen, sink.Len(), len(frame))
	}
}
