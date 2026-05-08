package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"
)

// idleTimeoutReader wraps an io.ReadCloser and returns an error if no data
// is received for longer than the configured idle timeout. This prevents
// zombie SSE connections where the upstream stops sending data but never
// closes the TCP connection.
type idleTimeoutReader struct {
	rc      io.ReadCloser
	timeout time.Duration
	timer   *time.Timer
	done    chan struct{}
	cancel  func() // cancel the request context
	closed  bool
}

func newIdleTimeoutReader(rc io.ReadCloser, timeout time.Duration, cancel func()) *idleTimeoutReader {
	r := &idleTimeoutReader{
		rc:      rc,
		timeout: timeout,
		timer:   time.NewTimer(timeout),
		done:    make(chan struct{}),
		cancel:  cancel,
	}
	go r.watchdog()
	return r
}

func (r *idleTimeoutReader) watchdog() {
	select {
	case <-r.timer.C:
		// Idle timeout expired - cancel the request context which will
		// cause the Read to return with a context error.
		r.cancel()
	case <-r.done:
		r.timer.Stop()
	}
}

func (r *idleTimeoutReader) Read(p []byte) (int, error) {
	n, err := r.rc.Read(p)
	if n > 0 {
		// Got data - reset the idle timer
		r.timer.Reset(r.timeout)
	}
	if err != nil {
		// Wrap context.Canceled with a more descriptive message
		if err.Error() == "context canceled" || err.Error() == "context deadline exceeded" {
			// Check if our timer fired (as opposed to a client disconnect)
			select {
			case <-r.timer.C:
				return n, fmt.Errorf("SSE stream idle for %v, closing", r.timeout)
			default:
			}
		}
	}
	return n, err
}

func (r *idleTimeoutReader) Close() error {
	if !r.closed {
		r.closed = true
		close(r.done)
		r.timer.Stop()
	}
	return r.rc.Close()
}

type limitedWriter struct {
	w io.Writer
	n int64
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.n <= 0 {
		return len(p), nil
	}
	if int64(len(p)) > lw.n {
		p = p[:lw.n]
	}
	n, err := lw.w.Write(p)
	lw.n -= int64(n)
	return len(p), err
}

type loggingReadCloser struct {
	io.ReadCloser
	onClose func()
}

func (rc *loggingReadCloser) Close() error {
	if rc.onClose != nil {
		rc.onClose()
	}
	return rc.ReadCloser.Close()
}

type flushWriter struct {
	w             http.ResponseWriter
	f             http.Flusher
	flushInterval time.Duration
	lastFlush     time.Time
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	now := time.Now()
	if fw.flushInterval <= 0 || fw.lastFlush.IsZero() || now.Sub(fw.lastFlush) >= fw.flushInterval {
		fw.f.Flush()
		fw.lastFlush = now
	}
	return n, err
}

func (fw *flushWriter) stop() {}

// sseInterceptWriter wraps a writer and scans the SSE stream for token_count events.
// It passes all data through to the underlying writer while extracting token data inline.
//
// The optional onEvent hook can divert the stream: returning drop=true
// causes the offending event's bytes to be withheld from the output;
// returning terminate=true tells the writer to stop forwarding any
// further upstream bytes (the writer's caller is responsible for
// emitting any synthetic terminal events directly to the wrapped
// writer afterwards). When onEvent is set the writer buffers each
// event boundary before flushing, so a drop decision actually
// suppresses the bytes rather than chasing them after they're on the
// wire.
type sseInterceptWriter struct {
	w         io.Writer
	buf       []byte
	callback  func(eventData []byte)
	onEvent   func(eventData []byte) (drop bool, terminate bool)
	terminated bool
}

func (sw *sseInterceptWriter) Write(p []byte) (int, error) {
	if sw.onEvent == nil {
		// Legacy mode: write-through, then scan after the fact. This
		// matches the long-standing behavior used by every non-Codex
		// caller that just wants usage extraction.
		n, err := sw.w.Write(p)
		sw.buf = append(sw.buf, p[:n]...)
		sw.scanForEventsLegacy()
		return n, err
	}

	// Suppression mode: buffer the bytes first, scan for full event
	// boundaries, and only forward the bytes the inspector approves.
	if sw.terminated {
		// We already decided to stop forwarding; pretend we wrote
		// everything so the upstream copy loop drains and ends
		// without back-pressure stalling the relay.
		return len(p), nil
	}
	sw.buf = append(sw.buf, p...)
	for {
		event, advance, ok := sw.takeNextEvent()
		if !ok {
			break
		}
		eventBytes := append([]byte(nil), sw.buf[:advance]...)
		sw.buf = sw.buf[advance:]
		drop, terminate := sw.invokeInspect(event)
		if !drop {
			if _, err := sw.w.Write(eventBytes); err != nil {
				return len(p), err
			}
		}
		if terminate {
			sw.terminated = true
			sw.buf = nil
			return len(p), nil
		}
	}
	return len(p), nil
}

// takeNextEvent locates the next \n\n or \r\n\r\n boundary in the
// remaining buffer and returns the event payload bytes plus the number
// of buffer bytes the event occupies (including its terminator).
func (sw *sseInterceptWriter) takeNextEvent() (event []byte, advance int, ok bool) {
	idx := bytes.Index(sw.buf, []byte("\n\n"))
	if idx >= 0 {
		return sw.buf[:idx], idx + 2, true
	}
	idx = bytes.Index(sw.buf, []byte("\r\n\r\n"))
	if idx >= 0 {
		return sw.buf[:idx], idx + 4, true
	}
	return nil, 0, false
}

func (sw *sseInterceptWriter) invokeInspect(event []byte) (drop, terminate bool) {
	data := extractSSEEventData(event)
	if len(data) == 0 {
		return false, false
	}
	if sw.callback != nil {
		sw.callback(data)
	}
	if sw.onEvent != nil {
		drop, terminate = sw.onEvent(data)
	}
	return drop, terminate
}

func (sw *sseInterceptWriter) scanForEventsLegacy() {
	for {
		event, advance, ok := sw.takeNextEvent()
		if !ok {
			if len(sw.buf) > 32*1024 {
				cutPoint := len(sw.buf) - 16*1024
				for cutPoint < len(sw.buf) && cutPoint > 0 && sw.buf[cutPoint]&0xC0 == 0x80 {
					cutPoint++
				}
				sw.buf = sw.buf[cutPoint:]
			}
			return
		}
		sw.processEvent(event)
		sw.buf = sw.buf[advance:]
	}
}

func (sw *sseInterceptWriter) processEvent(event []byte) {
	if sw.callback == nil {
		return
	}
	data := extractSSEEventData(event)
	if len(data) > 0 {
		sw.callback(data)
	}
}

func extractSSEEventData(event []byte) []byte {
	dataIdx := bytes.Index(event, []byte("data: "))
	if dataIdx < 0 {
		dataIdx = bytes.Index(event, []byte("data:"))
	}

	var data []byte
	if dataIdx >= 0 {
		data = event[dataIdx:]
		if bytes.HasPrefix(data, []byte("data: ")) {
			data = data[6:]
		} else if bytes.HasPrefix(data, []byte("data:")) {
			data = data[5:]
		}
	} else {
		trimmed := bytes.TrimSpace(event)
		if len(trimmed) > 0 && (trimmed[0] == '[' || trimmed[0] == '{') {
			data = trimmed
		} else {
			return nil
		}
	}
	return bytes.TrimSpace(data)
}
