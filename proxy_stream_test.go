package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestProxyStreamedRequestClaude(t *testing.T) {
	receivedCh := make(chan int64, 1)
	keyCh := make(chan string, 1)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedCh <- int64(len(body))
		keyCh <- r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	baseURL, _ := url.Parse(upstream.URL)
	codex := NewCodexProvider(baseURL, baseURL, baseURL)
	claude := NewClaudeProvider(baseURL)
	gemini := NewGeminiProvider(baseURL, baseURL)
	registry := NewProviderRegistry(codex, claude, gemini)

	acc := &Account{Type: AccountTypeClaude, ID: "claude_test", AccessToken: "sk-ant-api-test"}
	pool := newPoolState([]*Account{acc}, false)

	h := &proxyHandler{
		cfg: config{
			requestTimeout:       5 * time.Second,
			streamTimeout:        5 * time.Second,
			maxInMemoryBodyBytes: 1024,
		},
		transport: http.DefaultTransport,
		pool:      pool,
		registry:  registry,
		metrics:   newMetrics(),
		recent:    newRecentErrors(5),
	}

	proxy := httptest.NewServer(h)
	defer proxy.Close()

	body := bytes.Repeat([]byte("a"), 2048)
	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	select {
	case got := <-receivedCh:
		if got != int64(len(body)) {
			t.Fatalf("upstream received %d bytes, want %d", got, len(body))
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for upstream body size")
	}

	select {
	case got := <-keyCh:
		if got == "" {
			t.Fatalf("expected X-Api-Key to be set for Claude API key")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for upstream header")
	}
}
