package main

import (
	"bytes"
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
	w     io.Writer
	flush func() error

	mu      sync.Mutex
	timer   *time.Timer
	stopped bool
	err     error
	tail    [4]byte
	tailLen int
}

func newHeartbeatWriter(w io.Writer, flusher http.Flusher) *heartbeatWriter {
	hw := &heartbeatWriter{w: w}
	// A buffered writer owns flushing; bypassing it would race its timer.
	if f, ok := w.(interface{ flush() error }); ok {
		hw.flush = f.flush
	} else {
		hw.flush = func() error { return flushHTTP(flusher) }
	}
	hw.mu.Lock()
	hw.timer = time.AfterFunc(heartbeatInterval, hw.sendHeartbeat)
	hw.mu.Unlock()
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
	if hw.stopped || hw.err != nil {
		return
	}

	// A mutex protects writes, but an upstream event can span several writes.
	if !hw.atEventBoundary() {
		hw.resetTimerLocked()
		return
	}

	// Hold the Write mutex so heartbeat bytes cannot interleave with events.
	frame := []byte(": heartbeat\n\n")
	n, err := hw.w.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = hw.flush()
	}
	hw.err = err
	if err == nil {
		hw.resetTimerLocked()
	}
}

func (hw *heartbeatWriter) Write(p []byte) (int, error) {
	hw.mu.Lock()
	defer hw.mu.Unlock()
	if hw.err != nil {
		return 0, hw.err
	}
	if hw.stopped {
		return 0, io.ErrClosedPipe
	}

	n, err := hw.w.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	hw.err = err
	if err != nil {
		hw.timer.Stop()
		return n, err
	}
	hw.trackEventTail(p[:n])
	hw.resetTimerLocked()
	return n, nil
}

func (hw *heartbeatWriter) atEventBoundary() bool {
	tail := hw.tail[:hw.tailLen]
	return len(tail) == 0 || bytes.HasSuffix(tail, []byte("\n\n")) || bytes.HasSuffix(tail, []byte("\r\n\r\n"))
}

func (hw *heartbeatWriter) trackEventTail(p []byte) {
	if len(p) >= len(hw.tail) {
		hw.tailLen = copy(hw.tail[:], p[len(p)-len(hw.tail):])
		return
	}
	kept := min(hw.tailLen, len(hw.tail)-len(p))
	copy(hw.tail[:], hw.tail[hw.tailLen-kept:hw.tailLen])
	hw.tailLen = kept + copy(hw.tail[kept:], p)
}

// Stop cancels heartbeats and waits for any active write. Safe to repeat.
func (hw *heartbeatWriter) Stop() error {
	hw.mu.Lock()
	defer hw.mu.Unlock()
	hw.stopped = true
	if hw.timer != nil {
		hw.timer.Stop()
	}
	return hw.err
}
