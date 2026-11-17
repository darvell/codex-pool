package main

import (
	"context"
	"sync"
)

type refreshRole int

const (
	refreshStarted refreshRole = iota
	refreshJoined
)

type refreshCall struct {
	done chan struct{}
	err  error
}

type refreshGroup struct {
	mu    sync.Mutex
	calls map[string]*refreshCall
}

func (g *refreshGroup) run(ctx context.Context, key string, refresh func() error) (refreshRole, error) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = make(map[string]*refreshCall)
	}
	if call := g.calls[key]; call != nil {
		g.mu.Unlock()
		select {
		case <-call.done:
			return refreshJoined, call.err
		case <-ctx.Done():
			return refreshJoined, ctx.Err()
		}
	}
	call := &refreshCall{done: make(chan struct{})}
	g.calls[key] = call
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		delete(g.calls, key)
		g.mu.Unlock()
		close(call.done)
	}()
	call.err = refresh()
	return refreshStarted, call.err
}
