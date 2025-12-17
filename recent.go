package main

import "sync"

type recentErrors struct {
	mu   sync.Mutex
	max  int
	list []string
}

func newRecentErrors(max int) *recentErrors {
	return &recentErrors{max: max}
}

func (r *recentErrors) add(msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.list = append([]string{msg}, r.list...)
	if len(r.list) > r.max {
		r.list = r.list[:r.max]
	}
}

func (r *recentErrors) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.list))
	copy(out, r.list)
	return out
}
