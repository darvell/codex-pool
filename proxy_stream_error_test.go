package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProxyFailedWriteUsage(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "audit-secret")
	for _, path := range []string{"/v1/responses", "/v1/chat/completions", "/v1/messages"} {
		t.Run(path, func(t *testing.T) {
			store := testUsageStore(t)
			response := "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"audit_response\",\"usage\":{\"input_tokens\":7,\"output_tokens\":3}}}\n\n"
			h := preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(response))}, nil
			}))
			h.store = store
			body := `{"model":"gpt-5.4","stream":true,"input":"hi","max_tokens":32,"messages":[{"role":"user","content":"hi"}]}`
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("audit-secret", "audit-user"))
			h.proxyRequest(&flushTestSink{writeErr: errors.New("client disconnected")}, req, "failed-write-usage")
			usage, err := store.loadAccountUsage("codex")
			if err != nil {
				t.Fatal(err)
			}
			if usage.RequestCount != 1 || usage.TotalInputTokens != 7 || usage.TotalOutputTokens != 3 {
				t.Fatalf("received upstream usage lost on client failure: %+v", usage)
			}
		})
	}
}

func TestProxyStreamWriteFailure(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "latency-test-secret")
	for _, tc := range []struct {
		name, path, body string
	}{
		{"native", "/v1/responses", `{"model":"gpt-5.4","stream":true,"input":"hello"}`},
		{"chat", "/v1/chat/completions", `{"model":"gpt-5.4","stream":true,"messages":[{"role":"user","content":"hello"}]}`},
		{"claude", "/v1/messages", `{"model":"gpt-5.4","stream":true,"max_tokens":100,"messages":[{"role":"user","content":"hello"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			canceled := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
				close(canceled)
			}))
			defer upstream.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h := latencyTestHandler(t, upstream.URL, 1<<20)
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)).WithContext(ctx)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("latency-test-secret", "latency-user"))
			sink := &flushTestSink{writeErr: errors.New("client disconnected")}
			finished := make(chan struct{})
			go func() {
				h.ServeHTTP(sink, req)
				close(finished)
			}()
			select {
			case <-canceled:
			case <-time.After(2 * time.Second):
				t.Fatal("downstream failure did not cancel the open upstream stream")
			}
			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("handler did not return after the write failure")
			}
		})
	}
}
