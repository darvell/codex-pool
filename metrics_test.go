package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsServe(t *testing.T) {
	m := newMetrics()
	m.inc("200", "acct1")
	m.inc("429", "acct1")
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.serve(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if len(body) == 0 {
		t.Fatalf("expected metrics output")
	}
}

// TestCyberPolicyMetricsExposed locks down the (account, action)
// counters that operators rely on to alert when suppressions fire
// without successful swaps. Each known action is counted with a
// distinct label so dashboards can break down by what the proxy did.
func TestCyberPolicyMetricsExposed(t *testing.T) {
	m := newMetrics()
	m.incCyberPolicy("shiv_1", "suppressed_ws")
	m.incCyberPolicy("shiv_1", "suppressed_ws")
	m.incCyberPolicy("darv", "swap_succeeded")
	m.incCyberPolicy("shiv_1", "swap_no_candidate")
	m.incCyberPolicy("shiv_1", "synthetic_refusal_ws")
	m.incCyberPolicy("shiv_1", "suppressed_sse")
	m.incCyberPolicy("shiv_1", "synthetic_refusal_sse")
	m.incCyberPolicy("shiv_1", "suppressed_buffered")
	m.incCyberPolicy("shiv_1", "retry_buffered")
	m.incCyberPolicy("shiv_1", "retry_4xx")

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.serve(w, req)
	body := w.Body.String()

	want := []string{
		`codexpool_cyber_policy_actions_total{account="darv",action="swap_succeeded"} 1`,
		`codexpool_cyber_policy_actions_total{account="shiv_1",action="suppressed_ws"} 2`,
		`codexpool_cyber_policy_actions_total{account="shiv_1",action="swap_no_candidate"} 1`,
		`codexpool_cyber_policy_actions_total{account="shiv_1",action="synthetic_refusal_ws"} 1`,
		`codexpool_cyber_policy_actions_total{account="shiv_1",action="suppressed_sse"} 1`,
		`codexpool_cyber_policy_actions_total{account="shiv_1",action="synthetic_refusal_sse"} 1`,
		`codexpool_cyber_policy_actions_total{account="shiv_1",action="suppressed_buffered"} 1`,
		`codexpool_cyber_policy_actions_total{account="shiv_1",action="retry_buffered"} 1`,
		`codexpool_cyber_policy_actions_total{account="shiv_1",action="retry_4xx"} 1`,
	}
	for _, line := range want {
		if !strings.Contains(body, line) {
			t.Errorf("missing metric line %q\nbody:\n%s", line, body)
		}
	}
}

func TestCyberPolicyMetricsSnapshotCopiesMap(t *testing.T) {
	m := newMetrics()
	m.incCyberPolicy("a", "suppressed_ws")
	snap := m.cyberPolicySnapshot()
	if snap[cyberPolicyKey{"a", "suppressed_ws"}] != 1 {
		t.Fatalf("expected 1, got %d", snap[cyberPolicyKey{"a", "suppressed_ws"}])
	}
	// Mutating the snapshot must not affect future reads.
	snap[cyberPolicyKey{"a", "suppressed_ws"}] = 999
	again := m.cyberPolicySnapshot()
	if again[cyberPolicyKey{"a", "suppressed_ws"}] != 1 {
		t.Fatalf("snapshot mutation leaked into source: got %d", again[cyberPolicyKey{"a", "suppressed_ws"}])
	}
}

func TestCyberPolicyMetricsIgnoresEmptyAction(t *testing.T) {
	m := newMetrics()
	m.incCyberPolicy("acct", "")
	if got := len(m.cyberPolicySnapshot()); got != 0 {
		t.Fatalf("empty action should not increment, got snapshot len %d", got)
	}
}

func TestComputeCyberPolicyStatsHealthSignals(t *testing.T) {
	cyberLive := &Account{ID: "cyber-live", Type: AccountTypeCodex, CyberAccess: true}
	cyberDead := &Account{ID: "cyber-dead", Type: AccountTypeCodex, CyberAccess: true, Dead: true}
	plain := &Account{ID: "plain", Type: AccountTypeCodex}

	cases := []struct {
		name             string
		accounts         []*Account
		bumps            map[string]map[string]int // action -> account -> n
		wantHealthy      bool
		wantCandidates   int
		wantSuppressedWS int64
	}{
		{
			name:           "no suppressions, cyber candidate available -> healthy",
			accounts:       []*Account{plain, cyberLive},
			wantHealthy:    true,
			wantCandidates: 1,
		},
		{
			name:           "no suppressions and no cyber candidate -> degraded",
			accounts:       []*Account{plain},
			wantHealthy:    false,
			wantCandidates: 0,
		},
		{
			name:     "suppression paired with swap -> healthy",
			accounts: []*Account{plain, cyberLive},
			bumps: map[string]map[string]int{
				"suppressed_ws":  {"plain": 3},
				"swap_succeeded": {"cyber-live": 3},
			},
			wantHealthy:      true,
			wantCandidates:   1,
			wantSuppressedWS: 3,
		},
		{
			name:     "synthetic refusal fired -> degraded",
			accounts: []*Account{plain, cyberLive},
			bumps: map[string]map[string]int{
				"suppressed_ws":        {"plain": 1},
				"synthetic_refusal_ws": {"plain": 1},
				"swap_no_candidate":    {"plain": 1},
			},
			wantHealthy:      false,
			wantCandidates:   1,
			wantSuppressedWS: 1,
		},
		{
			name:     "suppressions outpace resolutions -> degraded",
			accounts: []*Account{plain, cyberLive},
			bumps: map[string]map[string]int{
				"suppressed_ws":  {"plain": 5},
				"swap_succeeded": {"cyber-live": 2},
			},
			wantHealthy:      false,
			wantCandidates:   1,
			wantSuppressedWS: 5,
		},
		{
			name:           "dead cyber account doesn't count as candidate",
			accounts:       []*Account{plain, cyberDead},
			wantHealthy:    false,
			wantCandidates: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &proxyHandler{
				cfg:     &config{},
				metrics: newMetrics(),
				pool:    newPoolState(tc.accounts, false),
			}
			for action, byAcc := range tc.bumps {
				for acc, n := range byAcc {
					for i := 0; i < n; i++ {
						h.metrics.incCyberPolicy(acc, action)
					}
				}
			}
			got := h.computeCyberPolicyStats(tc.accounts)
			if got.Healthy != tc.wantHealthy {
				t.Errorf("Healthy = %v, want %v", got.Healthy, tc.wantHealthy)
			}
			if got.CyberCandidatesAvailable != tc.wantCandidates {
				t.Errorf("CyberCandidatesAvailable = %d, want %d", got.CyberCandidatesAvailable, tc.wantCandidates)
			}
			if got.Counters["suppressed_ws"] != tc.wantSuppressedWS {
				t.Errorf("suppressed_ws = %d, want %d", got.Counters["suppressed_ws"], tc.wantSuppressedWS)
			}
		})
	}
}
