package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const preflightResponse = "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_preflight\",\"status\":\"completed\",\"output\":[]}}\n\n"

func preflightHandler(transport http.RoundTripper) *proxyHandler {
	base, _ := url.Parse("https://chatgpt.com/backend-api/codex")
	claude, _ := url.Parse("https://api.anthropic.com")
	return &proxyHandler{
		cfg:     &config{maxAttempts: 1, maxInMemoryBodyBytes: 4 << 20, requestTimeout: 37 * time.Second, streamTimeout: 3 * time.Minute},
		pool:    newPoolState([]*Account{{Type: AccountTypeCodex, ID: "codex", AccessToken: "upstream-token", AccountID: "acct", PlanType: "pro"}}, false),
		metrics: newMetrics(), recent: newRecentErrors(5),
		registry:  NewProviderRegistry(NewCodexProvider(base, base, nil), NewClaudeProvider(claude), NewGeminiProvider(base, base)),
		transport: transport,
	}
}

func preflightReply() *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(preflightResponse))}
}

func TestPreflightSpoolAdmission(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "preflight-secret")
	token := generateClaudePoolToken("preflight-secret", "preflight-user")
	for _, mode := range []string{"disk", "memory"} {
		t.Run(mode, func(t *testing.T) {
			var h *proxyHandler
			h = preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				want := 0
				if mode == "memory" {
					want = 1
				}
				if got := len(h.largeReplayBodies); got != want {
					t.Errorf("admission slots held during upstream response = %d, want %d", got, want)
				}
				if _, err := io.Copy(io.Discard, req.Body); err != nil {
					return nil, err
				}
				_ = req.Body.Close()
				return preflightReply(), nil
			}))
			h.largeReplayBodies = make(chan struct{}, 1)
			h.cfg.maxSpoolBodyBytes = 16 << 20
			h.cfg.maxInMemoryBodyBytes = 16 << 20
			body := `{"model":"gpt-5.5","stream":true,"input":"hello"}`
			if mode == "memory" {
				body = `{"model":"gpt-5.5","stream":true,"input":"` + strings.Repeat("x", largeReplayBodyThreshold+1) + `"}`
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
			if mode == "disk" {
				req.ContentLength = -1
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			h.proxyRequest(rr, req, "preflight-admission")
			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			if len(h.largeReplayBodies) != 0 {
				t.Fatal("admission slot leaked")
			}
		})
	}
}

func TestPreflightAdmissionCancellation(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "preflight-secret")
	h := preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, req.Context().Err()
	}))
	h.largeReplayBodies = make(chan struct{}, 1)
	h.largeReplayBodies <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-5.5","stream":true,"input":"hi"}`)).WithContext(ctx)
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("preflight-secret", "preflight-user"))
	done := make(chan struct{})
	go func() { defer close(done); h.proxyRequest(httptest.NewRecorder(), req, "cancel-admission") }()
	defer func() { <-h.largeReplayBodies; <-done }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled request still waits for a large-body slot")
	}
}

func TestPreflightOriginalIntent(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "preflight-secret")
	token := generateClaudePoolToken("preflight-secret", "preflight-user")
	for _, tc := range []struct {
		name, path, body, accept, timeoutHeader, model string
		timeout                                        time.Duration
		compact                                        bool
	}{
		{name: "streaming", body: `{"model":"gpt-5.5","stream":true,"input":"hi"}`, model: "gpt-5.5", timeout: 3 * time.Minute},
		{name: "default nonstream", body: `{"model":"gpt-5.5","input":"hi"}`, model: "gpt-5.5", timeout: 37 * time.Second},
		{name: "SDK timeout survives forced streaming", body: `{"model":"gpt-5.5","stream":false,"input":"hi"}`, timeoutHeader: "11", model: "gpt-5.5", timeout: 11 * time.Second},
		{name: "Accept streaming", body: `{"model":"gpt-5.5","stream":false,"input":"hi"}`, accept: "text/event-stream", timeoutHeader: "11", model: "gpt-5.5", timeout: 3 * time.Minute},
		{name: "image timeout", body: `{"model":"gpt-5.5","stream":false,"tools":[{"type":"image_generation"}],"input":"hi"}`, timeoutHeader: "11", model: "gpt-5.5", timeout: 5 * time.Minute},
		{name: "original image before metadata removal", body: `{"model":"gpt-5.5","metadata":{"type":"image_generation"},"input":"hi"}`, timeoutHeader: "11", model: "gpt-5.5", timeout: 5 * time.Minute},
		{name: "alias", body: `{"model":"fast-model","stream":true,"input":"hi"}`, model: "gpt-5.5", timeout: 3 * time.Minute},
		{name: "thinking suffix", body: `{"model":"gpt-5.5(16384)","stream":true,"input":"hi"}`, model: "gpt-5.5", timeout: 3 * time.Minute},
		{name: "suffix controls", body: `{"model":"gpt-5.5-high-fast","stream":true,"input":"hi"}`, model: "gpt-5.5", timeout: 3 * time.Minute},
		{name: "compact", path: "/v1/responses/compact", body: `{"model":"gpt-5.5","stream":true,"max_output_tokens":128,"input":"hi"}`, model: "gpt-5.5", timeout: 3 * time.Minute, compact: true},
		{name: "chat translation", path: "/v1/chat/completions", body: `{"model":"gpt-5.5","stream":false,"messages":[{"role":"user","content":"hi"}]}`, timeoutHeader: "11", model: "gpt-5.5", timeout: 11 * time.Second},
		{name: "Claude translation", path: "/v1/messages", body: `{"model":"gpt-5.5","stream":false,"max_tokens":128,"messages":[{"role":"user","content":"hi"}]}`, model: "gpt-5.5", timeout: 37 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				called = true
				deadline, ok := req.Context().Deadline()
				if !ok || time.Until(deadline) > tc.timeout || time.Until(deadline) < tc.timeout-time.Second {
					t.Errorf("upstream deadline remaining=%v, want %v", time.Until(deadline), tc.timeout)
				}
				var obj map[string]any
				if err := json.NewDecoder(req.Body).Decode(&obj); err != nil {
					return nil, err
				}
				_ = req.Body.Close()
				if obj["model"] != tc.model {
					t.Errorf("model=%v, want %s", obj["model"], tc.model)
				}
				if tc.compact {
					if _, exists := obj["stream"]; exists {
						t.Error("compact includes stream")
					}
					if _, exists := obj["max_output_tokens"]; exists {
						t.Error("compact includes max_output_tokens")
					}
				} else if obj["stream"] != true {
					t.Errorf("upstream stream=%v", obj["stream"])
				}
				if tc.name == "thinking suffix" || tc.name == "suffix controls" {
					reasoning, _ := obj["reasoning"].(map[string]any)
					if reasoning["effort"] != "high" {
						t.Errorf("reasoning=%v", reasoning)
					}
				}
				if tc.name == "suffix controls" && obj["service_tier"] != "priority" {
					t.Errorf("service_tier=%v", obj["service_tier"])
				}
				return preflightReply(), nil
			}))
			h.aliases = newModelAliases(map[string]string{"fast-model": "gpt-5.5"})
			path := tc.path
			if path == "" {
				path = "/v1/responses"
			}
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", tc.accept)
			req.Header.Set("X-Stainless-Timeout", tc.timeoutHeader)
			rr := httptest.NewRecorder()
			h.proxyRequest(rr, req, "preflight-intent")
			if !called || rr.Code != http.StatusOK {
				t.Fatalf("called=%v status=%d body=%s", called, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestPreflightHostedMCP(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "preflight-secret")
	token := generateClaudePoolToken("preflight-secret", "preflight-user")
	for _, path := range []string{"/v1/responses", "/v1/responses/compact", "/backend-api/codex/responses"} {
		t.Run(path, func(t *testing.T) {
			called := false
			h := preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				called = true
				var obj map[string]any
				if err := json.NewDecoder(req.Body).Decode(&obj); err != nil {
					return nil, err
				}
				_ = req.Body.Close()
				tools, _ := obj["tools"].([]any)
				input, _ := obj["input"].([]any)
				if len(tools) != 2 || len(input) != 1 {
					t.Errorf("hosted MCP filtering: tools=%v input=%v", tools, input)
				}
				if _, exists := obj["tool_choice"]; exists {
					t.Error("hosted MCP tool_choice retained")
				}
				if len(tools) == 2 && tools[0].(map[string]any)["name"] != "mcp__local__read" {
					t.Error("local MCP function removed")
				}
				return preflightReply(), nil
			}))
			body := `{"model":"gpt-5.5","stream":true,"tools":[{"type":"mcp","server_label":"hosted"},{"type":"function","name":"mcp__local__read","parameters":{"type":"object","properties":{"path":{"type":"string"}}}},{"type":"web_search"}],"input":[{"type":"mcp_call","id":"hosted-call"},{"role":"user","content":"hello"}],"tool_choice":{"type":"mcp","server_label":"hosted"}}`
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			h.proxyRequest(rr, req, "preflight-mcp")
			if !called || rr.Code != http.StatusOK {
				t.Fatalf("called=%v status=%d body=%s", called, rr.Code, rr.Body.String())
			}
		})
	}
}

func BenchmarkProxyRequestPreflight(b *testing.B) {
	b.Setenv("POOL_JWT_SECRET", "preflight-secret")
	token := generateClaudePoolToken("preflight-secret", "preflight-user")
	for _, size := range []struct {
		name   string
		bytes  int
		deltas int
	}{{"4KiB", 4 << 10, 0}, {"256KiB", 256 << 10, 0}, {"LongStream", 128, 10000}} {
		b.Run(size.name, func(b *testing.B) {
			body, err := json.Marshal(map[string]any{
				"model": "gpt-5.5", "stream": true, "prompt_cache_key": "preflight-session",
				"input": []any{map[string]any{"role": "user", "content": strings.Repeat("Review this code and explain the change. ", size.bytes/40)}},
				"tools": []any{map[string]any{"type": "function", "name": "read_file", "parameters": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}}}}},
			})
			if err != nil {
				b.Fatal(err)
			}
			response := strings.Repeat("data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n", size.deltas) + preflightResponse
			var captured []byte
			h := preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				var err error
				captured, err = io.ReadAll(req.Body)
				_ = req.Body.Close()
				if err != nil {
					return nil, err
				}
				reply := preflightReply()
				reply.Body = io.NopCloser(strings.NewReader(response))
				return reply, nil
			}))
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()
				h.proxyRequest(rr, req, "preflight-bench")
				if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "response.completed") {
					b.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
				}
			}
			b.StopTimer()
			var upstream map[string]any
			if err := json.Unmarshal(captured, &upstream); err != nil {
				b.Fatal(err)
			}
			if upstream["model"] != "gpt-5.5" || upstream["stream"] != true || upstream["store"] != false {
				b.Fatalf("upstream controls: %v", upstream)
			}
		})
	}
}
