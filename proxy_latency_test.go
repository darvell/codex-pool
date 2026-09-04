package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

// The upstream waits for client acknowledgement of each token. A proxy that
// waits for EOF, batches events, or loses a split event cannot finish this test.
func TestProxySSEIncremental(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "latency-test-secret")
	for _, tc := range []struct {
		name      string
		path      string
		body      string
		bodyLimit int64
	}{
		{"responses", "/v1/responses", `{"model":"gpt-5.4","stream":true,"input":"hello"}`, 1 << 20},
		{"claude_translation", "/v1/messages", `{"model":"gpt-5.4","stream":true,"max_tokens":100,"messages":[{"role":"user","content":"hello"}]}`, 1 << 20},
		{"chat_translation", "/v1/chat/completions", `{"model":"gpt-5.4","stream":true,"messages":[{"role":"user","content":"hello"}]}`, 1 << 20},
		{"spooled_responses", "/v1/responses", `{"model":"gpt-5.4","stream":true,"input":"hello"}`, 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ack := make(chan struct{})
			stop := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_latency\",\"model\":\"gpt-5.4\"}}\n\n")
				w.(http.Flusher).Flush()
				for i := range 32 {
					event := fmt.Sprintf("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"token_%02d\"}\n\n", i)
					// Split JSON and the SSE delimiter across separate upstream writes.
					for _, fragment := range []string{event[:len(event)/2], event[len(event)/2 : len(event)-1], event[len(event)-1:]} {
						if _, err := io.WriteString(w, fragment); err != nil {
							return
						}
						w.(http.Flusher).Flush()
					}
					select {
					case <-ack:
					case <-stop:
						return
					case <-r.Context().Done():
						return
					}
				}
				_, _ = io.WriteString(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_latency\",\"usage\":{\"input_tokens\":1,\"output_tokens\":32}}}\n\n")
			}))
			defer upstream.Close()
			h := latencyTestHandler(t, upstream.URL, tc.bodyLimit)
			proxy := httptest.NewServer(h)
			defer proxy.Close()
			defer close(stop)
			client := &http.Client{Timeout: 5 * time.Second}
			req, err := http.NewRequest(http.MethodPost, proxy.URL+tc.path, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("latency-test-secret", "latency-user"))
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			scanner := bufio.NewScanner(resp.Body)
			tokens := 0
			for scanner.Scan() {
				if !strings.Contains(scanner.Text(), fmt.Sprintf("token_%02d", tokens)) {
					continue
				}
				tokens++
				select {
				case ack <- struct{}{}:
				case <-time.After(5 * time.Second):
					t.Fatal("upstream stopped accepting token acknowledgements")
				}
			}
			if err := scanner.Err(); err != nil {
				t.Fatal(err)
			}
			if tokens != 32 {
				t.Fatalf("received %d tokens, want 32", tokens)
			}
		})
	}
}

func TestProxySSEAccountingLatency(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "latency-test-secret")
	for _, tc := range []struct {
		name, path, body, terminal string
		limit                      int64
	}{
		{"responses", "/v1/responses", `{"model":"gpt-5.4","stream":true,"input":"hi"}`, "response.completed", 1 << 20},
		{"claude_translation", "/v1/messages", `{"model":"gpt-5.4","stream":true,"max_tokens":100,"messages":[{"role":"user","content":"hi"}]}`, "message_stop", 1 << 20},
		{"chat_translation", "/v1/chat/completions", `{"model":"gpt-5.4","stream":true,"messages":[{"role":"user","content":"hi"}]}`, "[DONE]", 1 << 20},
		{"spooled_responses", "/v1/responses", `{"model":"gpt-5.4","stream":true,"input":"hi"}`, "response.completed", 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := testUsageStore(t)
			complete := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_latency\",\"model\":\"gpt-5.4\"}}\n\n")
				w.(http.Flusher).Flush()
				select {
				case <-complete:
				case <-r.Context().Done():
					return
				}
				_, _ = io.WriteString(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_latency\",\"model\":\"gpt-5.4\",\"usage\":{\"input_tokens\":7,\"output_tokens\":3}}}\n\n")
			}))
			defer upstream.Close()
			h := latencyTestHandler(t, upstream.URL, tc.limit)
			h.store = store
			done := make(chan struct{})
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h.ServeHTTP(w, r)
				close(done)
			}))
			defer proxy.Close()
			client := &http.Client{Timeout: 5 * time.Second}
			req, _ := http.NewRequest(http.MethodPost, proxy.URL+tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("latency-test-secret", "latency-user"))
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			tx, err := store.db.Begin(true)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			close(complete)
			terminal := make(chan struct{})
			readDone := make(chan error, 1)
			go func() {
				scanner := bufio.NewScanner(resp.Body)
				seen := false
				for scanner.Scan() {
					if !seen && strings.Contains(scanner.Text(), tc.terminal) {
						seen = true
						close(terminal)
					}
				}
				readDone <- scanner.Err()
			}()
			select {
			case <-terminal:
			case <-time.After(time.Second):
				t.Fatal("terminal SSE event blocked behind the accounting transaction")
			}
			select {
			case <-done:
				t.Fatal("handler returned before accounting committed")
			default:
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("handler failed to finish accounting")
			}
			if err := <-readDone; err != nil {
				t.Fatal(err)
			}
			usage, err := store.loadAccountUsage("latency_account")
			if err != nil {
				t.Fatal(err)
			}
			if usage.RequestCount != 1 || usage.TotalInputTokens != 7 || usage.TotalOutputTokens != 3 {
				t.Fatalf("persisted usage = %+v", usage)
			}
			if err := store.db.View(func(tx *bbolt.Tx) error {
				if n := tx.Bucket([]byte(bucketAnalyticsOutbox)).Stats().KeyN; n != 1 {
					return fmt.Errorf("outbox contains %d facts, want 1", n)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func latencyTestHandler(t testing.TB, upstream string, bodyLimit int64) *proxyHandler {
	t.Helper()
	base, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	account := &Account{Type: AccountTypeCodex, ID: "latency_account", AccessToken: "test-upstream-token", AccountID: "latency_account", PlanType: "pro"}
	return &proxyHandler{
		cfg:       &config{maxInMemoryBodyBytes: bodyLimit, maxSpoolBodyBytes: 1 << 20, maxAttempts: 1, streamTimeout: 5 * time.Second},
		transport: http.DefaultTransport,
		pool:      newPoolState([]*Account{account}, false),
		registry:  NewProviderRegistry(NewCodexProvider(base, base, base), NewClaudeProvider(base), NewGeminiProvider(base, base)),
		metrics:   newMetrics(), recent: newRecentErrors(5),
	}
}
