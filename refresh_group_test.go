package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const refreshTestTimeout = 3 * time.Second

type refreshJoinContext struct {
	context.Context
	joined chan struct{}
	once   sync.Once
}

func (c *refreshJoinContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.joined) })
	return c.Context.Done()
}

type refreshFixture struct {
	handler   *proxyHandler
	waiting   *Account
	newAccess string
	calls     atomic.Int32
	release   func()
	done      chan struct{}
	err       error
}

func newRefreshFixture(t *testing.T) *refreshFixture {
	t.Helper()
	_, account := codexFixture(t)
	fixture := &refreshFixture{newAccess: jwtWithExp(time.Now().Add(10 * 24 * time.Hour).Unix()), done: make(chan struct{})}
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	fixture.release = func() { releaseOnce.Do(func() { close(release) }) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.calls.Add(1)
		enteredOnce.Do(func() { close(entered) })
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": fixture.newAccess, "refresh_token": "waiter-fixture-refresh"})
	}))
	t.Cleanup(server.Close)
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	provider := NewCodexProvider(base, base, base)
	fixture.waiting = readCodexFixture(t, provider, account.File)
	fixture.handler = &proxyHandler{cfg: &config{}, registry: NewProviderRegistry(provider, nil, nil), refreshTransport: server.Client().Transport}
	ctx, cancel := context.WithTimeout(context.Background(), refreshTestTimeout)
	go func() {
		fixture.err = fixture.handler.refreshAccount(ctx, account)
		close(fixture.done)
	}()
	t.Cleanup(func() {
		fixture.release()
		cancel()
		select {
		case <-fixture.done:
		case <-time.After(refreshTestTimeout):
			t.Error("refresh worker did not stop")
		}
	})
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("refresh did not reach the loopback upstream")
	}
	return fixture
}

func (f *refreshFixture) finish(t *testing.T) {
	t.Helper()
	f.release()
	select {
	case <-f.done:
		if f.err != nil {
			t.Fatal(f.err)
		}
	case <-time.After(refreshTestTimeout):
		t.Fatal("shared refresh did not finish")
	}
	if f.calls.Load() != 1 {
		t.Fatalf("refresh requests = %d, want 1", f.calls.Load())
	}
}
