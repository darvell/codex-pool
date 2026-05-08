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
	// cyberPolicy counts cyber_policy-related actions taken by the
	// proxy. The keys are `(account, action)` pairs. Action is one of:
	//   suppressed_ws            — WS cyber_policy frame seen
	//   suppressed_sse           — streaming SSE cyber_policy seen
	//   suppressed_buffered      — buffered translation hit
	//   swap_succeeded           — WS hot-swap to cyber upstream done
	//   swap_no_candidate        — saw cyber_policy but no cyber candidate
	//   retry_buffered           — buffered translation retried on cyber
	cyberPolicy map[cyberPolicyKey]int64
}

type cyberPolicyKey struct {
	account string
	action  string
}

func newMetrics() *metrics {
	return &metrics{
		requests:    make(map[string]int64),
		accStatus:   make(map[string]map[string]int64),
		cyberPolicy: make(map[cyberPolicyKey]int64),
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

// incCyberPolicy bumps the (account, action) counter. account may be
// empty for actions that are not tied to a single account.
func (m *metrics) incCyberPolicy(account, action string) {
	if action == "" {
		return
	}
	m.mu.Lock()
	m.cyberPolicy[cyberPolicyKey{account: account, action: action}]++
	m.mu.Unlock()
}

// cyberPolicySnapshot returns a copy of the cyber_policy counter map
// for use by admin/status endpoints.
func (m *metrics) cyberPolicySnapshot() map[cyberPolicyKey]int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[cyberPolicyKey]int64, len(m.cyberPolicy))
	for k, v := range m.cyberPolicy {
		out[k] = v
	}
	return out
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

	// cyber_policy actions: per-(account, action) counters so operators
	// can alert on suppressions firing without successful swaps.
	cyberKeys := make([]cyberPolicyKey, 0, len(m.cyberPolicy))
	for k := range m.cyberPolicy {
		cyberKeys = append(cyberKeys, k)
	}
	sort.Slice(cyberKeys, func(i, j int) bool {
		if cyberKeys[i].account != cyberKeys[j].account {
			return cyberKeys[i].account < cyberKeys[j].account
		}
		return cyberKeys[i].action < cyberKeys[j].action
	})
	for _, k := range cyberKeys {
		fmt.Fprintf(w, "codexpool_cyber_policy_actions_total{account=\"%s\",action=\"%s\"} %d\n", k.account, k.action, m.cyberPolicy[k])
	}
}
