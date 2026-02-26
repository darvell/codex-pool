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
type sseInterceptWriter struct {
	w        io.Writer
	buf      []byte
	callback func(eventData []byte)
}

func (sw *sseInterceptWriter) Write(p []byte) (int, error) {
	// Always write to underlying writer first
	n, err := sw.w.Write(p)

	// Append to our buffer for scanning
	sw.buf = append(sw.buf, p[:n]...)

	// Look for complete SSE events (separated by \n\n)
	sw.scanForEvents()

	return n, err
}

func (sw *sseInterceptWriter) scanForEvents() {
	for {
		// Find double newline which marks end of SSE event
		idx := bytes.Index(sw.buf, []byte("\n\n"))
		if idx < 0 {
			// Also check for \r\n\r\n
			idx = bytes.Index(sw.buf, []byte("\r\n\r\n"))
			if idx < 0 {
				// Keep buffer bounded - if it gets too big without events, truncate front
				if len(sw.buf) > 32*1024 {
					cutPoint := len(sw.buf) - 16*1024
					// Advance past any partial UTF-8 sequence at the cut point
					for cutPoint < len(sw.buf) && cutPoint > 0 && sw.buf[cutPoint]&0xC0 == 0x80 {
						cutPoint++
					}
					sw.buf = sw.buf[cutPoint:]
				}
				return
			}
			// Extract and consume the event
			event := sw.buf[:idx]
			sw.buf = sw.buf[idx+4:] // Skip \r\n\r\n
			sw.processEvent(event)
			continue
		}

		// Extract and consume the event
		event := sw.buf[:idx]
		sw.buf = sw.buf[idx+2:] // Skip \n\n
		sw.processEvent(event)
	}
}

func (sw *sseInterceptWriter) processEvent(event []byte) {
	// Look for usage in the response
	// OpenAI/Codex format: "usage":{"input_tokens":N,...}
	// Claude format: "type":"message_start" or "type":"message_delta" with usage
	// Gemini format: "usageMetadata":{"promptTokenCount":N,...}
	hasCodexUsage := bytes.Contains(event, []byte(`"usage":{"`)) && bytes.Contains(event, []byte(`"input_tokens":`))
	hasClaudeUsage := (bytes.Contains(event, []byte(`"type":"message_start"`)) || bytes.Contains(event, []byte(`"type":"message_delta"`))) && bytes.Contains(event, []byte(`"usage":`))
	hasGeminiUsage := bytes.Contains(event, []byte(`"usageMetadata":{"`)) && bytes.Contains(event, []byte(`"promptTokenCount":`))
	if !hasCodexUsage && !hasClaudeUsage && !hasGeminiUsage {
		return
	}

	// Find the data: prefix and extract JSON from there
	dataIdx := bytes.Index(event, []byte("data: "))
	if dataIdx < 0 {
		dataIdx = bytes.Index(event, []byte("data:"))
	}

	var data []byte
	if dataIdx >= 0 {
		// Standard SSE format with data: prefix
		data = event[dataIdx:]
		if bytes.HasPrefix(data, []byte("data: ")) {
			data = data[6:]
		} else if bytes.HasPrefix(data, []byte("data:")) {
			data = data[5:]
		}
	} else {
		// Gemini may send JSON array directly without data: prefix
		// Look for JSON starting with [ or {
		trimmed := bytes.TrimSpace(event)
		if len(trimmed) > 0 && (trimmed[0] == '[' || trimmed[0] == '{') {
			data = trimmed
		} else {
			return
		}
	}
	data = bytes.TrimSpace(data)

	if len(data) > 0 && sw.callback != nil {
		sw.callback(data)
	}
}
