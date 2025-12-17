package main

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
)

type metrics struct {
	mu        sync.Mutex
	requests  map[string]int64            // status -> count
	accStatus map[string]map[string]int64 // account -> status -> count
}

func newMetrics() *metrics {
	return &metrics{
		requests:  make(map[string]int64),
		accStatus: make(map[string]map[string]int64),
	}
}

func (m *metrics) inc(status string, account string) {
	m.mu.Lock()
	m.requests[status]++
	if account != "" {
		mp, ok := m.accStatus[account]
		if !ok {
			mp = make(map[string]int64)
			m.accStatus[account] = mp
		}
		mp[status]++
	}
	m.mu.Unlock()
}

func (m *metrics) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	m.mu.Lock()
	defer m.mu.Unlock()
	// overall
	statuses := make([]string, 0, len(m.requests))
	for s := range m.requests {
		statuses = append(statuses, s)
	}
	sort.Strings(statuses)
	for _, s := range statuses {
		fmt.Fprintf(w, "codexpool_requests_total{status=\"%s\"} %d\n", s, m.requests[s])
	}
	// per account
	accs := make([]string, 0, len(m.accStatus))
	for a := range m.accStatus {
		accs = append(accs, a)
	}
	sort.Strings(accs)
	for _, a := range accs {
		st := m.accStatus[a]
		sts := make([]string, 0, len(st))
		for s := range st {
			sts = append(sts, s)
		}
		sort.Strings(sts)
		for _, s := range sts {
			fmt.Fprintf(w, "codexpool_account_requests_total{account=\"%s\",status=\"%s\"} %d\n", a, s, st[s])
		}
	}
}
