package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Claude can wait before sending upstream headers. Start SSE liveness only
// after the normal heartbeat interval, preserving fast HTTP error responses.
// stopWait joins the callback before the handler touches headers or body again.
type claudePrelude struct {
	w         http.ResponseWriter
	flusher   http.Flusher
	cancel    func()
	mu        sync.Mutex
	timer     *time.Timer
	committed bool
	err       error
}

func newClaudePrelude(w http.ResponseWriter, cancel func()) *claudePrelude {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil
	}
	return &claudePrelude{w: w, flusher: flusher, cancel: cancel}
}

func (p *claudePrelude) startWait() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.timer = time.AfterFunc(heartbeatInterval, p.ping)
}

func (p *claudePrelude) ping() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.timer == nil || p.err != nil {
		return
	}
	if !p.committed {
		p.w.Header().Set("Content-Type", "text/event-stream")
		p.w.Header().Del("Content-Length")
		p.w.Header().Del("Content-Encoding")
		applyStreamingResponseHeaders(p.w.Header())
		p.w.WriteHeader(http.StatusOK)
		p.committed = true
	}
	frame := ": heartbeat\n\n"
	n, err := io.WriteString(p.w, frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = flushHTTP(p.flusher)
	}
	p.err = err
	if err != nil {
		p.cancel()
		return
	}
	p.timer.Reset(heartbeatInterval)
}

func (p *claudePrelude) stopWait() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
}

func (p *claudePrelude) started() bool {
	return p != nil && p.committed
}

func (p *claudePrelude) writeError(w http.ResponseWriter, status int, body []byte) {
	if !p.started() {
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}
	if p.err != nil {
		return
	}
	var envelope struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Type != "error" || envelope.Error.Type == "" || envelope.Error.Message == "" {
		envelope.Type = "error"
		envelope.Error.Type = "api_error"
		if status == http.StatusTooManyRequests {
			envelope.Error.Type = "rate_limit_error"
		}
		envelope.Error.Message = "Upstream request failed. Retry the request."
	}
	encoded, _ := json.Marshal(envelope)
	_, _ = fmt.Fprintf(w, "event: error\ndata: %s\n\n", encoded)
	_ = flushHTTP(p.flusher)
}

func (p *claudePrelude) httpError(w http.ResponseWriter, message string, status int) {
	if !p.started() {
		http.Error(w, message, status)
		return
	}
	p.writeError(w, status, []byte(message))
}
