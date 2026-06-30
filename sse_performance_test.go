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
	w := &sseInterceptWriter{
		w:       &sink,
		onEvent: func([]byte) (bool, bool) { return false, false },
	}
	frame := []byte("data: " + strings.Repeat("x", sseInterceptMaxBufferedBytes-32) + "\n\n")
	if _, err := w.Write(frame); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(sink.Bytes(), frame) {
		t.Fatalf("forwarded frame mismatch")
	}
}
