package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// defaultUpstreamFirstByteTimeout is below Cloudflare's ~100s proxy read
// timeout. Silence longer than this becomes our error instead of an HTML 524.
const defaultUpstreamFirstByteTimeout = 30 * time.Second

// errUpstreamFirstByteTimeout is returned when an upstream connection accepts
// the dial or request and then produces no response bytes before the deadline.
// It is not a client cancellation and must be written to the caller before
// Cloudflare synthesizes its own timeout page.
var errUpstreamFirstByteTimeout = errors.New("upstream produced no response before the first-byte deadline")

// errPreviousResponseUnreplayable means a newly dialed socket was asked to
// continue a connection-scoped previous_response_id and the pool does not
// have a full transcript to rebuild. The client must resend the conversation.
var errPreviousResponseUnreplayable = errors.New("previous_response_id is not valid on a new upstream connection")

func previousResponseNotFoundFrame() []byte {
	return []byte(`{"type":"error","error":{"type":"invalid_request_error","code":"previous_response_not_found","message":"Previous response is not available on a new upstream connection. Resend the conversation without previous_response_id."}}`)
}

func upstreamFirstByteTimeoutFrame() []byte {
	return []byte(`{"type":"error","error":{"type":"upstream_timeout","message":"Upstream produced no response before the first-byte deadline."}}`)
}

func writeUpstreamFirstByteTimeout(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", "1")
	w.WriteHeader(http.StatusGatewayTimeout)
	_, _ = w.Write([]byte(`{"error":{"type":"upstream_timeout","message":"Upstream produced no response headers before the first-byte deadline."}}`))
}

// firstByteDeadline cancels ctx only if the deadline fires before disarm.
// Disarm does not cancel, so a successful handshake can keep using ctx for
// the response body. Canceling a dial context after Dial returns would close
// the websocket, because the HTTP transport owns that body.
type firstByteDeadline struct {
	ctx      context.Context
	cancel   context.CancelCauseFunc
	timer    *time.Timer
	mu       sync.Mutex
	disarmed bool
	fired    bool
}

func beginFirstByteDeadline(parent context.Context, timeout time.Duration) (context.Context, func() bool) {
	if parent == nil {
		parent = context.Background()
	}
	if timeout <= 0 {
		return parent, func() bool { return false }
	}
	ctx, cancel := context.WithCancelCause(parent)
	d := &firstByteDeadline{ctx: ctx, cancel: cancel}
	d.timer = time.AfterFunc(timeout, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.disarmed {
			return
		}
		d.fired = true
		cancel(errUpstreamFirstByteTimeout)
	})
	return ctx, d.disarm
}

func (d *firstByteDeadline) disarm() bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.disarmed = true
	if d.timer != nil {
		d.timer.Stop()
	}
	return d.fired
}

func (h *proxyHandler) roundTripWithFirstByteDeadline(req *http.Request) (*http.Response, error) {
	if h == nil || h.transport == nil || req == nil {
		return nil, errors.New("missing transport")
	}
	timeout := time.Duration(0)
	if h.cfg != nil {
		timeout = h.cfg.upstreamFirstByteTimeout
	}
	ctx, disarm := beginFirstByteDeadline(req.Context(), timeout)
	resp, err := h.transport.RoundTrip(req.WithContext(ctx))
	if disarm() || errors.Is(context.Cause(ctx), errUpstreamFirstByteTimeout) {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, errUpstreamFirstByteTimeout
	}
	return resp, err
}

// relayIdleGuard closes src when the next frame does not arrive in time.
// Before the first frame, firstTimeout applies. After that, idleTimeout
// applies, and a zero idle timeout means a long generation is left alone.
type relayIdleGuard struct {
	src        *websocket.Conn
	idle       time.Duration
	first      time.Duration
	saw        atomic.Bool
	firstFired atomic.Bool
	mu         sync.Mutex
	timer      *time.Timer
}

func newRelayIdleGuard(src *websocket.Conn, idle, first time.Duration) *relayIdleGuard {
	return &relayIdleGuard{src: src, idle: idle, first: first}
}

func (g *relayIdleGuard) arm() {
	if g == nil || g.src == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	d := g.idle
	if !g.saw.Load() && g.first > 0 {
		d = g.first
	}
	if d <= 0 {
		if g.timer != nil {
			g.timer.Stop()
			g.timer = nil
		}
		return
	}
	if g.timer == nil {
		g.timer = time.AfterFunc(d, g.fire)
		return
	}
	g.timer.Reset(d)
}

func (g *relayIdleGuard) fire() {
	if g == nil || g.src == nil {
		return
	}
	if !g.saw.Load() && g.first > 0 {
		g.firstFired.Store(true)
		g.src.Close(websocket.StatusPolicyViolation, "upstream first-byte timeout")
		return
	}
	g.src.Close(websocket.StatusPolicyViolation, fmt.Sprintf("idle for %v", g.idle))
}

func (g *relayIdleGuard) markFrame() {
	if g != nil {
		g.saw.Store(true)
	}
}

func (g *relayIdleGuard) stop() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.timer != nil {
		g.timer.Stop()
	}
}

func (g *relayIdleGuard) wrap(err error) error {
	if err == nil || g == nil {
		return err
	}
	if g.firstFired.Load() {
		return errUpstreamFirstByteTimeout
	}
	return err
}
