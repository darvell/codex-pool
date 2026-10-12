package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPooledResponsesDiskReplayCompressedAndChunked(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "responses-replay-secret")
	plain := []byte(`{"model":"gpt-5.6-high-fast","stream":true,"input":"` + strings.Repeat("image-data", 4096) + `"}`)
	for _, encoding := range []string{"", "gzip", "zstd"} {
		name := encoding
		if name == "" {
			name = "chunked"
		}
		t.Run(name, func(t *testing.T) {
			wire := compressedResponsesBody(t, encoding, plain)
			var h *proxyHandler
			h = preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if got := len(h.responsesSpoolBodies); got != 1 {
					t.Errorf("spool admission slots held = %d, want 1", got)
				}
				if req.Header.Get("Content-Encoding") != "" {
					t.Errorf("content encoding survived: %q", req.Header.Get("Content-Encoding"))
				}
				body, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}
				var obj map[string]any
				if err := json.Unmarshal(body, &obj); err != nil {
					t.Errorf("upstream JSON: %v", err)
				}
				if obj["model"] != "gpt-5.6" || obj["service_tier"] != "priority" || !bytes.Contains(body, []byte(strings.Repeat("image-data", 128))) {
					t.Errorf("transformed body incomplete: bytes=%d model=%v tier=%v", len(body), obj["model"], obj["service_tier"])
				}
				return preflightReply(), nil
			}))
			h.cfg.maxInMemoryBodyBytes = 64
			h.cfg.maxSpoolBodyBytes = 1 << 20
			h.cfg.maxWireBodyBytes = 1 << 20
			h.responsesSpoolBodies = make(chan struct{}, 1)
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(wire))
			req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("responses-replay-secret", "replay-user"))
			req.Header.Set("Content-Type", "application/json")
			if encoding != "" {
				req.Header.Set("Content-Encoding", encoding)
			}
			if encoding == "" || encoding == "zstd" {
				req.ContentLength = -1
			}
			rr := httptest.NewRecorder()
			h.proxyRequest(rr, req, "responses-replay")
			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			if len(h.responsesSpoolBodies) != 0 {
				t.Fatal("spool admission slot leaked")
			}
		})
	}
}

func TestCompressedSmallNonStreamingResponsesUseBufferedPath(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "responses-buffered-secret")
	plain := []byte(`{"model":"gpt-5.6","stream":false,"input":"hello"}`)
	wire := compressedResponsesBody(t, "gzip", plain)
	var h *proxyHandler
	h = preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := len(h.responsesSpoolBodies); got != 0 {
			t.Errorf("spool slot retained after buffered fallback = %d", got)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil || !bytes.Contains(body, []byte(`"type":"input_text"`)) || !bytes.Contains(body, []byte(`"text":"hello"`)) {
			t.Errorf("buffered Codex transforms missing: body=%s err=%v", body, err)
		}
		return preflightReply(), nil
	}))
	h.cfg.maxInMemoryBodyBytes = 1 << 20
	h.cfg.maxSpoolBodyBytes = 1 << 20
	h.cfg.maxWireBodyBytes = 1 << 20
	h.responsesSpoolBodies = make(chan struct{}, 1)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("responses-buffered-secret", "buffered-user"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	rr := httptest.NewRecorder()
	h.proxyRequest(rr, req, "responses-buffered")
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestResponsesHTTPDiskLimitsAndMalformedRelease(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "responses-limit-secret")
	plain := []byte(`{"model":"gpt-5.6","stream":true,"input":"` + strings.Repeat("x", 8192) + `"}`)
	gzipBody := compressedResponsesBody(t, "gzip", plain)
	cases := []struct {
		name, encoding string
		body           []byte
		wire, decoded  int64
		wantStatus     int
		wantText       string
	}{
		{name: "wire", encoding: "gzip", body: gzipBody, wire: int64(len(gzipBody) - 1), decoded: 1 << 20, wantStatus: http.StatusRequestEntityTooLarge, wantText: "wire byte limit"},
		{name: "decoded", encoding: "gzip", body: gzipBody, wire: 1 << 20, decoded: 1024, wantStatus: http.StatusRequestEntityTooLarge, wantText: "decoded Responses request"},
		{name: "encoding", encoding: "br", body: plain, wire: 1 << 20, decoded: 1 << 20, wantStatus: http.StatusUnsupportedMediaType, wantText: "unsupported Responses request content encoding"},
		{name: "malformed", body: []byte(`{"model":"gpt-5.6","stream":true,"input":"bad\x"}`), wire: 1 << 20, decoded: 1 << 20, wantStatus: http.StatusBadRequest, wantText: "invalid escape"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := preflightHandler(roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("limit violation reached upstream")
				return nil, nil
			}))
			h.cfg.maxInMemoryBodyBytes = 1
			h.cfg.maxSpoolBodyBytes = tc.decoded
			h.cfg.maxWireBodyBytes = tc.wire
			h.responsesSpoolBodies = make(chan struct{}, 1)
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("responses-limit-secret", "limit-user"))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Content-Encoding", tc.encoding)
			if tc.name == "encoding" || tc.name == "malformed" {
				req.ContentLength = -1
			}
			rr := httptest.NewRecorder()
			h.proxyRequest(rr, req, "responses-limit")
			if rr.Code != tc.wantStatus || !strings.Contains(rr.Body.String(), tc.wantText) {
				t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
			}
			if len(h.responsesSpoolBodies) != 0 {
				t.Fatal("spool admission slot leaked")
			}
		})
	}
}

func TestResponsesSpoolAdmissionCancellation(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "responses-cancel-secret")
	h := preflightHandler(roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("cancelled request reached upstream")
		return nil, nil
	}))
	h.cfg.maxSpoolBodyBytes = 1 << 20
	h.cfg.maxWireBodyBytes = 1 << 20
	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "codex-pool-responses-*.json"))
	cancelledCtx, cancelRead := context.WithCancel(context.Background())
	cancelRead()
	cancelledReq := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-5.6","stream":true,"input":[]}`)).WithContext(cancelledCtx)
	if _, err := h.spoolHTTPResponsesRequest(nil, cancelledReq, responsesStreamOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled spool error = %v", err)
	}
	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "codex-pool-responses-*.json"))
	if len(after) != len(before) {
		t.Fatalf("cancelled spool leaked temporary files: before=%d after=%d", len(before), len(after))
	}

	h.responsesSpoolBodies = make(chan struct{}, 1)
	h.responsesSpoolBodies <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-5.6","stream":true,"input":[]}`)).WithContext(ctx)
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("responses-cancel-secret", "cancel-user"))
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.proxyRequest(httptest.NewRecorder(), req, "responses-cancel")
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled request still waits for spool admission")
	}
	if len(h.responsesSpoolBodies) != 1 {
		t.Fatal("cancelled waiter changed spool admission state")
	}
	<-h.responsesSpoolBodies
}

func TestPassthroughResponsesCompressedDiskFiltering(t *testing.T) {
	plain := []byte(`{"model":"gpt-5.6","store":true,"stream":false,"input":"hello","padding":"` + strings.Repeat("x", 1024) + `","tools":[{"type":"mcp","secret":"drop"},{"type":"function","name":"keep","parameters":{"type":"object","required":null}}]}`)
	wire := compressedResponsesBody(t, "zstd", plain)
	received := make(chan []byte, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer sk-proj-responses-replay" {
			t.Errorf("authorization changed: %q", r.Header.Get("Authorization"))
		}
		received <- body
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp","output":[{"type":"mcp_call","output":"TOP-SECRET"},{"type":"message","content":[{"type":"output_text","text":"safe"}]}]}`)
	}))
	defer upstream.Close()
	base, _ := url.Parse(upstream.URL)
	codex := NewCodexProvider(base, base, base)
	h := &proxyHandler{
		cfg:       &config{maxInMemoryBodyBytes: 256, maxSpoolBodyBytes: 1 << 20, maxWireBodyBytes: 1 << 20, requestTimeout: 5 * time.Second, streamTimeout: 5 * time.Second},
		registry:  NewProviderRegistry(codex, NewClaudeProvider(base), NewGeminiProvider(base, base)),
		transport: http.DefaultTransport,
		pool:      newPoolState(nil, false),
		metrics:   newMetrics(), recent: newRecentErrors(5), responsesSpoolBodies: make(chan struct{}, 1),
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer sk-proj-responses-replay")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "zstd")
	req.ContentLength = -1
	rr := httptest.NewRecorder()
	h.proxyRequest(rr, req, "passthrough-responses-replay")
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "TOP-SECRET") || !strings.Contains(rr.Body.String(), "safe") {
		t.Fatalf("non-SSE hosted MCP response was not filtered: %s", rr.Body.String())
	}
	got := <-received
	var obj map[string]any
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["store"] != true || obj["stream"] != false || obj["input"] != "hello" || bytes.Contains(got, []byte("secret")) {
		t.Fatalf("passthrough body semantics/filtering: %s", got)
	}
	tools := obj["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["parameters"].(map[string]any)["required"] != nil {
		t.Fatalf("passthrough tool changed: %s", got)
	}
	if len(h.responsesSpoolBodies) != 0 {
		t.Fatal("passthrough spool slot leaked")
	}
}
