package main

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type fakeWebSocketPinger struct {
	err    error
	called chan struct{}
}

func (f *fakeWebSocketPinger) Ping(context.Context) error {
	select {
	case f.called <- struct{}{}:
	default:
	}
	return f.err
}

func TestWebSocketHeartbeatReportsPingFailure(t *testing.T) {
	want := errors.New("ping failed")
	pinger := &fakeWebSocketPinger{err: want, called: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh, stop := startWebSocketHeartbeat(ctx, pinger, time.Millisecond, "upstream")
	defer stop()
	select {
	case err := <-errCh:
		if !errors.Is(err, want) {
			t.Fatalf("heartbeat error = %v, want %v", err, want)
		}
	case <-time.After(time.Second):
		t.Fatal("heartbeat failure was not reported")
	}
}

type fakeWebSocketCloser struct {
	mu     sync.Mutex
	code   websocket.StatusCode
	reason string
	closed chan struct{}
}

func newFakeWebSocketCloser() *fakeWebSocketCloser {
	return &fakeWebSocketCloser{closed: make(chan struct{}, 1)}
}

func (f *fakeWebSocketCloser) Close(code websocket.StatusCode, reason string) error {
	f.mu.Lock()
	f.code = code
	f.reason = reason
	f.mu.Unlock()
	select {
	case f.closed <- struct{}{}:
	default:
	}
	return nil
}

func TestWebSocketDrainClosesIdleAndWaitsForActiveTurn(t *testing.T) {
	registry := newWebSocketRegistry()
	idleConn := newFakeWebSocketCloser()
	activeConn := newFakeWebSocketCloser()
	idle := registry.register(idleConn)
	active := registry.register(activeConn)
	active.setActive(true)

	registry.beginDrain()
	select {
	case <-idleConn.closed:
	case <-time.After(time.Second):
		t.Fatal("idle websocket was not closed for restart")
	}
	select {
	case <-activeConn.closed:
		t.Fatal("active websocket closed before its turn completed")
	case <-time.After(20 * time.Millisecond):
	}

	registry.unregister(idle)
	active.setActive(false)
	select {
	case <-activeConn.closed:
	case <-time.After(time.Second):
		t.Fatal("active websocket was not closed after its turn completed")
	}
	registry.unregister(active)

	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !registry.wait(waitCtx) {
		t.Fatal("websocket registry did not finish draining")
	}
	if idleConn.code != websocket.StatusServiceRestart || activeConn.code != websocket.StatusServiceRestart {
		t.Fatalf("restart close codes = idle %d active %d, want 1012", idleConn.code, activeConn.code)
	}
}

func TestServeUntilShutdownForcesActiveSessionAfterGrace(t *testing.T) {
	h := &proxyHandler{}
	registry := h.webSocketRegistry()
	conn := newFakeWebSocketCloser()
	session := registry.register(conn)
	session.setActive(true)
	shutdown := make(chan struct{})
	close(shutdown)

	started := time.Now()
	err := serveUntilShutdown(&http.Server{Addr: "127.0.0.1:0", Handler: http.NewServeMux()}, h, shutdown, 25*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 20*time.Millisecond {
		t.Fatalf("shutdown forced active session before grace elapsed: %s", elapsed)
	}
	select {
	case <-conn.closed:
	case <-time.After(time.Second):
		t.Fatal("active websocket was not force-closed after shutdown grace")
	}
	registry.unregister(session)
}
