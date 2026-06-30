package main

import (
	"io"
	"net/http"
	"sync"
	"time"
)

const heartbeatInterval = 15 * time.Second

// heartbeatWriter wraps an io.Writer (typically a flushWriter) and sends
// SSE comment heartbeats if no data is written for heartbeatInterval.
// This prevents intermediate proxies from timing out during slow upstream
// streaming responses.
type heartbeatWriter struct {
	w       io.Writer
	flusher http.Flusher

	mu      sync.Mutex
	timer   *time.Timer
	stopped bool
}

func newHeartbeatWriter(w io.Writer, flusher http.Flusher) *heartbeatWriter {
	hw := &heartbeatWriter{
		w:       w,
		flusher: flusher,
	}
	hw.timer = time.AfterFunc(heartbeatInterval, hw.sendHeartbeat)
	return hw
}

func (hw *heartbeatWriter) resetTimerLocked() {
	if hw.stopped || hw.timer == nil {
		return
	}
	hw.timer.Reset(heartbeatInterval)
}

func (hw *heartbeatWriter) sendHeartbeat() {
	hw.mu.Lock()
	defer hw.mu.Unlock()
	if hw.stopped {
		return
	}

	// SSE comment line — ignored by all SSE parsers. Hold the same mutex as
	// Write so heartbeat bytes cannot interleave with upstream event bytes.
	if _, err := hw.w.Write([]byte(": heartbeat\n\n")); err != nil {
		return
	}
	if hw.flusher != nil {
		hw.flusher.Flush()
	}
	hw.resetTimerLocked()
}

func (hw *heartbeatWriter) Write(p []byte) (int, error) {
	hw.mu.Lock()
	defer hw.mu.Unlock()
	// Reset heartbeat timer on each real write.
	hw.resetTimerLocked()
	return hw.w.Write(p)
}

// Stop cancels the heartbeat timer. Safe to call multiple times.
func (hw *heartbeatWriter) Stop() {
	hw.mu.Lock()
	defer hw.mu.Unlock()
	hw.stopped = true
	if hw.timer != nil {
		hw.timer.Stop()
	}
}
