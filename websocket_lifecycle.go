package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

type webSocketTermination struct {
	Side    string
	Code    websocket.StatusCode
	Outcome string
	Reason  string
	Err     error
}

func classifyWebSocketTermination(err error) webSocketTermination {
	term := webSocketTermination{Side: "relay", Code: websocket.StatusNormalClosure, Outcome: "normal", Err: err}
	if err == nil {
		term.Reason = "relay completed"
		return term
	}

	message := err.Error()
	term.Reason = message
	switch {
	case strings.HasPrefix(message, "upstream->client read:"), strings.HasPrefix(message, "client->upstream write:"), strings.HasPrefix(message, "upstream heartbeat:"):
		term.Side = "upstream"
	case strings.HasPrefix(message, "client->upstream read:"), strings.HasPrefix(message, "upstream->client write:"), strings.HasPrefix(message, "client heartbeat:"):
		term.Side = "client"
	}

	if code := websocket.CloseStatus(err); code != -1 {
		term.Code = code
	} else {
		term.Code = websocket.StatusAbnormalClosure
	}

	switch {
	case errors.Is(err, context.Canceled):
		term.Outcome = "canceled"
	case term.Code == websocket.StatusNormalClosure || term.Code == websocket.StatusGoingAway:
		term.Outcome = "normal"
	case term.Side == "client" && (strings.Contains(message, "EOF") || strings.Contains(message, "closed")):
		term.Outcome = "canceled"
	default:
		term.Outcome = "error"
	}
	return term
}

func (t webSocketTermination) accountFailure() bool {
	return t.Outcome == "error" && t.Side != "client"
}

func (t webSocketTermination) wireCloseCode() websocket.StatusCode {
	switch t.Code {
	case websocket.StatusNormalClosure, websocket.StatusGoingAway,
		websocket.StatusProtocolError, websocket.StatusUnsupportedData,
		websocket.StatusPolicyViolation, websocket.StatusMessageTooBig,
		websocket.StatusMandatoryExtension, websocket.StatusInternalError,
		websocket.StatusServiceRestart, websocket.StatusTryAgainLater, websocket.StatusBadGateway:
		return t.Code
	default:
		if t.Outcome == "normal" || t.Outcome == "canceled" {
			return websocket.StatusGoingAway
		}
		return websocket.StatusInternalError
	}
}

func (t webSocketTermination) wireReason() string {
	reason := t.Reason
	if reason == "" {
		reason = t.Outcome
	}
	if len(reason) > 120 {
		reason = reason[:120]
	}
	return reason
}

type webSocketCloser interface {
	Close(websocket.StatusCode, string) error
}

// beginWebSocketClose gives the close frame a brief chance to reach the peer
// without making the handler wait for coder/websocket's full five-second close
// handshake. Returning immediately races request-context cancellation, which
// turns the intended close into a raw EOF at the client.
func beginWebSocketClose(conn webSocketCloser, code websocket.StatusCode, reason string) {
	done := make(chan struct{})
	go func() {
		_ = conn.Close(code, reason)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(50 * time.Millisecond):
	}
}

type trackedWebSocketSession struct {
	registry *webSocketRegistry
	conn     webSocketCloser
	active   atomic.Bool
	started  atomic.Bool
	terminal atomic.Bool
	closing  atomic.Bool
}

func (s *trackedWebSocketSession) setActive(active bool) {
	if s == nil {
		return
	}
	s.active.Store(active)
	if active {
		s.started.Store(true)
		s.terminal.Store(false)
	} else if s.started.Load() {
		s.terminal.Store(true)
	}
	if !active && s.registry.isDraining() {
		s.requestRestart()
	}
}

func normalizeCompletedWebSocketTermination(term webSocketTermination, session *trackedWebSocketSession) webSocketTermination {
	if session != nil && session.terminal.Load() && term.Side == "upstream" && term.Code == websocket.StatusAbnormalClosure {
		term.Code = websocket.StatusNormalClosure
		term.Outcome = "normal"
		term.Reason = "upstream closed after completed response"
	}
	return term
}

func (s *trackedWebSocketSession) requestRestart() {
	if s == nil || !s.closing.CompareAndSwap(false, true) {
		return
	}
	go beginWebSocketClose(s.conn, websocket.StatusServiceRestart, "server restarting")
}

type webSocketRegistry struct {
	mu       sync.Mutex
	sessions map[*trackedWebSocketSession]struct{}
	draining bool
}

func newWebSocketRegistry() *webSocketRegistry {
	return &webSocketRegistry{sessions: make(map[*trackedWebSocketSession]struct{})}
}

func (h *proxyHandler) webSocketRegistry() *webSocketRegistry {
	if h == nil {
		return nil
	}
	h.webSocketRegistryMu.Lock()
	defer h.webSocketRegistryMu.Unlock()
	if h.webSockets == nil {
		h.webSockets = newWebSocketRegistry()
	}
	return h.webSockets
}

func (h *proxyHandler) recordWebSocketTermination(reqID, account string, term webSocketTermination, duration time.Duration) {
	if h != nil && h.metrics != nil {
		h.metrics.incWebSocketTermination(account, term)
	}
	log.Printf("[%s] websocket closed account=%s side=%s code=%d outcome=%s duration_ms=%d reason=%q",
		reqID, account, term.Side, term.Code, term.Outcome, duration.Milliseconds(), term.wireReason())
}

func (r *webSocketRegistry) register(conn webSocketCloser) *trackedWebSocketSession {
	session := &trackedWebSocketSession{registry: r, conn: conn}
	r.mu.Lock()
	r.sessions[session] = struct{}{}
	draining := r.draining
	r.mu.Unlock()
	if draining {
		session.requestRestart()
	}
	return session
}

func (r *webSocketRegistry) unregister(session *trackedWebSocketSession) {
	if r == nil || session == nil {
		return
	}
	r.mu.Lock()
	delete(r.sessions, session)
	r.mu.Unlock()
}

func (r *webSocketRegistry) isDraining() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.draining
}

func (r *webSocketRegistry) beginDrain() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.draining = true
	sessions := make([]*trackedWebSocketSession, 0, len(r.sessions))
	for session := range r.sessions {
		sessions = append(sessions, session)
	}
	r.mu.Unlock()
	for _, session := range sessions {
		if !session.active.Load() {
			session.requestRestart()
		}
	}
}

func (r *webSocketRegistry) forceCloseAll() {
	if r == nil {
		return
	}
	r.mu.Lock()
	sessions := make([]*trackedWebSocketSession, 0, len(r.sessions))
	for session := range r.sessions {
		sessions = append(sessions, session)
	}
	r.mu.Unlock()
	for _, session := range sessions {
		session.requestRestart()
	}
}

func (r *webSocketRegistry) count() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

func (r *webSocketRegistry) wait(ctx context.Context) bool {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if r.count() == 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

type webSocketPinger interface {
	Ping(context.Context) error
}

func startWebSocketHeartbeat(ctx context.Context, dst webSocketPinger, interval time.Duration, label string) (<-chan error, func()) {
	if interval <= 0 {
		return nil, func() {}
	}
	errCh := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		timer := time.NewTimer(interval)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-timer.C:
				if err := dst.Ping(ctx); err != nil {
					select {
					case errCh <- fmt.Errorf("%s heartbeat: %w", label, err):
					default:
					}
					return
				}
				timer.Reset(interval)
			}
		}
	}()
	var once sync.Once
	return errCh, func() { once.Do(func() { close(done) }) }
}
