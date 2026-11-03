package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
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
