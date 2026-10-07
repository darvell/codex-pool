package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestProMaxHasProAccess(t *testing.T) {
	for _, plan := range []string{"promax", "PROMAX", " ProMax "} {
		if !isCodexProAccessPlan(plan) || !planMatchesRequired(plan, "pro") || accountTier(AccountTypeCodex, plan) != 1 {
			t.Fatalf("Pro Max plan %q lacks Pro routing eligibility", plan)
		}
	}
}

func TestProMaxRequestRouting(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "promax-test-secret")
	for _, mode := range []string{"buffered", "chunked"} {
		t.Run(mode, func(t *testing.T) {
			var dispatched string
			h := preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				dispatched = req.Header.Get("ChatGPT-Account-ID")
				return preflightReply(), nil
			}))
			h.cfg.maxSpoolBodyBytes = 1 << 20
			h.pool = newPoolState([]*Account{
				{ID: "pro", Type: AccountTypeCodex, PlanType: "pro", AccessToken: "fixture-pro", AccountID: "pro-seat", CyberAccess: true},
				{ID: "max", Type: AccountTypeCodex, PlanType: "promax", AccessToken: "fixture-max", AccountID: "max-seat", CyberAccess: true},
			}, false)
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-5.5","stream":true,"input":"Reply OK"}`))
			req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("promax-test-secret", "promax-user"))
			req.Header.Set("Content-Type", "application/json")
			if mode == "chunked" {
				req.ContentLength = -1
			}
			w := httptest.NewRecorder()
			h.proxyRequest(w, req, "promax-routing")
			if w.Code != http.StatusOK || dispatched != "max-seat" || !strings.Contains(w.Body.String(), "response.completed") {
				t.Fatalf("status=%d seat=%q body=%s", w.Code, dispatched, w.Body.String())
			}
		})
	}
}

func TestProMaxWebSocketRouting(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "promax-test-secret")
	var dispatched string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dispatched = r.Header.Get("ChatGPT-Account-ID")
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer upstream.Close()
	base, _ := url.Parse(upstream.URL)
	h := preflightHandler(http.DefaultTransport)
	h.registry = NewProviderRegistry(NewCodexProvider(base, base, nil), nil, nil)
	h.pool = newPoolState([]*Account{
		{ID: "pro", Type: AccountTypeCodex, PlanType: "pro", AccessToken: "fixture-pro", AccountID: "pro-seat"},
		{ID: "max", Type: AccountTypeCodex, PlanType: "promax", AccessToken: "fixture-max", AccountID: "max-seat"},
	}, false)
	r := httptest.NewRequest(http.MethodGet, "/v1/responses", nil).WithContext(context.Background())
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("promax-test-secret", "promax-user"))
	w := httptest.NewRecorder()
	h.proxyRequest(w, r, "promax-ws")
	if dispatched != "max-seat" || w.Code != http.StatusBadRequest {
		t.Fatalf("handshake status=%d seat=%q", w.Code, dispatched)
	}
}

func TestProMaxRoutesFirst(t *testing.T) {
	pro := &Account{ID: "pro", Type: AccountTypeCodex, PlanType: "pro", CyberAccess: true}
	max := &Account{ID: "max", Type: AccountTypeCodex, PlanType: "promax", CyberAccess: true, Usage: UsageSnapshot{SecondaryUsedPercent: 0.7}}
	p := newPoolState([]*Account{pro, max}, false)
	for range 12 {
		if got := p.candidate("", nil, AccountTypeCodex, "pro", ""); got != max {
			t.Fatalf("new request selected %v, want eligible Pro Max", got)
		}
	}
	if got := p.candidateWithCyberAccess(nil, AccountTypeCodex, "pro", ""); got != max {
		t.Fatalf("cyber-access failover selected %v, want Pro Max", got)
	}
}

func TestProMaxKeepsConversationPins(t *testing.T) {
	pro := &Account{ID: "pro", Type: AccountTypeCodex, PlanType: "pro"}
	max := &Account{ID: "max", Type: AccountTypeCodex, PlanType: "promax"}
	p := newPoolState([]*Account{pro, max}, false)
	p.pin("existing-pro", pro.ID)
	p.pin("existing-max", max.ID)
	if got := p.candidate("existing-pro", nil, AccountTypeCodex, "pro", ""); got != pro {
		t.Fatalf("priority broke the existing Pro conversation: %v", got)
	}
	if got := p.candidate("existing-max", nil, AccountTypeCodex, "pro", ""); got != max {
		t.Fatalf("Pro Max conversation lost its account: %v", got)
	}
}

func TestProMaxUnavailableFallsBack(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Account)
	}{
		{"dead", func(a *Account) { a.Dead = true }},
		{"disabled", func(a *Account) { a.Disabled = true }},
		{"cooldown", func(a *Account) { a.RateLimitUntil = time.Now().Add(time.Hour) }},
		{"primary exhausted", func(a *Account) { a.Usage.PrimaryUsedPercent = primaryHardExcludeThreshold }},
		{"weekly exhausted", func(a *Account) { a.Usage.SecondaryUsedPercent = secondaryHardExcludeThreshold }},
		{"IP restricted", func(a *Account) { a.AllowedSourceIPs = []string{"192.0.2.2"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pro := &Account{ID: "pro", Type: AccountTypeCodex, PlanType: "pro", CyberAccess: true}
			max := &Account{ID: "max", Type: AccountTypeCodex, PlanType: "promax", CyberAccess: true}
			tc.mutate(max)
			p := newPoolState([]*Account{max, pro}, false)
			if got := p.candidate("", nil, AccountTypeCodex, "pro", "192.0.2.1"); got != pro {
				t.Fatalf("unavailable Pro Max prevented ordinary fallback: %v", got)
			}
			if got := p.candidateWithCyberAccess(nil, AccountTypeCodex, "pro", "192.0.2.1"); got != pro {
				t.Fatalf("unavailable Pro Max prevented cyber fallback: %v", got)
			}
		})
	}
}

func TestProMaxRespectsModelAndExclusions(t *testing.T) {
	model := "fixture-discovered-model"
	pro := &Account{ID: "pro", Type: AccountTypeCodex, PlanType: "pro", Models: map[string]DiscoveredModel{model: {ID: model}}}
	max := &Account{ID: "max", Type: AccountTypeCodex, PlanType: "promax", Models: map[string]DiscoveredModel{"other": {ID: "other"}}}
	p := newPoolState([]*Account{max, pro}, false)
	if got := p.candidateForModel("", nil, AccountTypeCodex, "pro", "", model); got != pro {
		t.Fatalf("Pro Max bypassed model eligibility: %v", got)
	}
	if got := p.candidate("", map[string]bool{max.ID: true}, AccountTypeCodex, "pro", ""); got != pro {
		t.Fatalf("Pro Max bypassed the retry exclusion: %v", got)
	}
}
