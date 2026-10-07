package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClaudeHeaderWait(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "prelude-secret")
	for _, status := range []int{http.StatusOK, http.StatusBadRequest} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			h := preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				select {
				case <-release:
				case <-req.Context().Done():
					return nil, req.Context().Err()
				}
				body := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-5-5\",\"usage\":{\"input_tokens\":7}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":3}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
				if status != http.StatusOK {
					body = `{"type":"error","error":{"type":"invalid_request_error","message":"Bad input"}}`
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			}))
			h.pool = newPoolState([]*Account{{ID: "claude", Type: AccountTypeClaude, AccessToken: "sk-ant-api-test", PlanType: "team"}}, false)
			h.store = testUsageStore(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.proxyRequest(w, r, "prelude-test") }))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), heartbeatInterval+5*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/messages", strings.NewReader(`{"model":"claude-opus-5-5","stream":true,"max_tokens":128,"messages":[{"role":"user","content":"hi"}]}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("prelude-secret", "prelude-user"))
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatalf("no response while upstream headers held: %v", err)
			}
			defer resp.Body.Close()
			reader := bufio.NewReader(resp.Body)
			line, err := reader.ReadString('\n')
			if err != nil || line != ": heartbeat\n" || resp.StatusCode != http.StatusOK {
				t.Fatalf("pre-header liveness: status=%d line=%q err=%v", resp.StatusCode, line, err)
			}
			unblock()
			body, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if status == http.StatusOK {
				if !strings.Contains(string(body), "event: message_stop") || strings.Contains(string(body), "event: error") {
					t.Fatalf("native events corrupted: %s", body)
				}
				usage, err := h.store.loadAccountUsage("claude")
				if err != nil || usage.RequestCount != 1 || usage.TotalOutputTokens != 3 {
					t.Fatalf("usage=%+v err=%v", usage, err)
				}
			} else if strings.Count(string(body), "event: error") != 1 || !strings.Contains(string(body), `"message":"Bad input"`) {
				t.Fatalf("late error not delivered as SSE: %s", body)
			}
			if atomic.LoadInt64(&h.inflight) != 0 {
				t.Fatal("inflight request leaked")
			}
		})
	}
}

func TestClaudePreludeErrors(t *testing.T) {
	for _, body := range []string{`{"type":"error","error":{"type":"overloaded_error","message":"Busy"}}`, "<html>524 timeout</html>", "transport failed"} {
		w := httptest.NewRecorder()
		p := newClaudePrelude(w, func() {})
		p.startWait()
		p.ping()
		p.stopWait()
		p.writeError(w, http.StatusBadGateway, []byte(body))
		if w.Code != http.StatusOK || strings.Count(w.Body.String(), "event: error") != 1 || strings.Contains(w.Body.String(), "<html>") {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
	}
}

func TestClaudePreludeFastError(t *testing.T) {
	w := httptest.NewRecorder()
	p := newClaudePrelude(w, func() {})
	p.startWait()
	p.stopWait()
	p.httpError(w, "invalid input", http.StatusBadRequest)
	if w.Code != http.StatusBadRequest || w.Body.String() != "invalid input\n" {
		t.Fatalf("fast error changed: status=%d body=%s", w.Code, w.Body.String())
	}
}

type preludeFailWriter struct {
	header http.Header
}

func (w *preludeFailWriter) Header() http.Header       { return w.header }
func (w *preludeFailWriter) WriteHeader(int)           {}
func (w *preludeFailWriter) Write([]byte) (int, error) { return 0, errors.New("disconnected") }
func (w *preludeFailWriter) Flush()                    {}

func TestClaudePreludeCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := newClaudePrelude(&preludeFailWriter{header: make(http.Header)}, cancel)
	p.startWait()
	p.ping()
	p.stopWait()
	if ctx.Err() != context.Canceled {
		t.Fatal("failed heartbeat did not cancel upstream")
	}
}
