package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type slowHeaderRoundTripper struct {
	delay time.Duration
}

func (s slowHeaderRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	timer := time.NewTimer(s.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
}

func TestRoundTripFirstByteDeadline(t *testing.T) {
	h := &proxyHandler{
		cfg:       &config{upstreamFirstByteTimeout: 30 * time.Millisecond},
		transport: slowHeaderRoundTripper{delay: time.Second},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.test/v1/responses", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	resp, err := h.roundTripWithFirstByteDeadline(req)
	if resp != nil {
		t.Fatalf("resp = %#v, want nil", resp)
	}
	if !errors.Is(err, errUpstreamFirstByteTimeout) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("deadline took %s", time.Since(start))
	}
}

func TestRoundTripFirstByteDeadlineAllowsHeaders(t *testing.T) {
	h := &proxyHandler{
		cfg:       &config{upstreamFirstByteTimeout: time.Second},
		transport: slowHeaderRoundTripper{delay: 20 * time.Millisecond},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test/v1/responses", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.roundTripWithFirstByteDeadline(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
}

func newFirstByteFailoverProxy(t *testing.T, upstream *httptest.Server, accounts []*Account) *httptest.Server {
	t.Helper()
	baseURL, _ := url.Parse(upstream.URL)
	h := &proxyHandler{
		cfg: &config{
			requestTimeout:           5 * time.Second,
			streamTimeout:            5 * time.Second,
			maxInMemoryBodyBytes:     1 << 20,
			maxSpoolBodyBytes:        16 << 20,
			maxAttempts:              1,
			disableRefresh:           true,
			upstreamFirstByteTimeout: 100 * time.Millisecond,
		},
		transport: http.DefaultTransport,
		pool:      newPoolState(accounts, false),
		registry:  NewProviderRegistry(NewCodexProvider(baseURL, baseURL, baseURL), NewClaudeProvider(baseURL), NewGeminiProvider(baseURL, baseURL)),
		metrics:   newMetrics(),
		recent:    newRecentErrors(5),
		aliases:   newModelAliases(nil),
	}
	proxy := httptest.NewServer(h)
	t.Cleanup(proxy.Close)
	return proxy
}

func silentFirstAccountUpstream(stuck, served *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("ChatGPT-Account-ID") == "acct_stuck" {
			stuck.Add(1)
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
			return
		}
		served.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n"))
	}))
}

func TestFirstByteTimeoutFailsOverOnce(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	var stuck, served atomic.Int32
	upstream := silentFirstAccountUpstream(&stuck, &served)
	defer upstream.Close()
	accounts := []*Account{
		{Type: AccountTypeCodex, ID: "a-stuck", AccessToken: "stuck-token", PlanType: "pro", AccountID: "acct_stuck"},
		{Type: AccountTypeCodex, ID: "b-live", AccessToken: "live-token", PlanType: "pro", AccountID: "acct_live"},
	}
	proxy := newFirstByteFailoverProxy(t, upstream, accounts)

	status, body := postPoolResponses(t, proxy, `{"model":"gpt-5.6-sol","stream":true,"input":"hello"}`)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if stuck.Load() != 1 || served.Load() != 1 {
		t.Fatalf("stuck calls=%d served calls=%d, want one each", stuck.Load(), served.Load())
	}
}

func TestFirstByteTimeoutWithoutAlternateReturnsGatewayTimeout(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	var stuck, served atomic.Int32
	upstream := silentFirstAccountUpstream(&stuck, &served)
	defer upstream.Close()
	accounts := []*Account{{Type: AccountTypeCodex, ID: "stuck", AccessToken: "stuck-token", PlanType: "pro", AccountID: "acct_stuck"}}
	proxy := newFirstByteFailoverProxy(t, upstream, accounts)

	status, body := postPoolResponses(t, proxy, `{"model":"gpt-5.6-sol","stream":true,"input":"hello"}`)
	if status != http.StatusGatewayTimeout || stuck.Load() != 1 {
		t.Fatalf("status=%d stuck calls=%d body=%s, want one 504", status, stuck.Load(), body)
	}
}
