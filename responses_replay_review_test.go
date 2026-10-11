package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func TestResponsesLexicalTextSchemaAndPassthroughInteger(t *testing.T) {
	pooled, err := streamResponsesRequest(strings.NewReader(`{"model":"gpt-5.6","stream":true,"text":{"format":{"type":"json_schema","schema":{"type":"object","required":null,"properties":{"n":{"type":"integer"}}}}}}`), 1<<20, responsesStreamOptions{})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(pooled.File)
	pooled.Close()
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatal(err)
	}
	schema := obj["text"].(map[string]any)["format"].(map[string]any)["schema"].(map[string]any)
	if schema["additionalProperties"] != false {
		t.Fatalf("text format schema not normalized: %s", body)
	}
	if required, ok := schema["required"].([]any); !ok || len(required) != 0 {
		t.Fatalf("text format required not normalized: %s", body)
	}

	const largeInteger = "9007199254740993"
	passthrough, err := streamResponsesRequest(strings.NewReader(`{"model":"gpt-5.6","stream":true,"tools":[{"type":"function","name":"exact","parameters":{"type":"object","maximum":`+largeInteger+`}}]}`), 1<<20, responsesStreamOptions{passthrough: true})
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(passthrough.File)
	passthrough.Close()
	if !bytes.Contains(body, []byte(`"maximum":`+largeInteger)) {
		t.Fatalf("passthrough tool integer changed: %s", body)
	}
}

func TestResponsesLexicalCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	spooled, err := streamResponsesRequest(strings.NewReader(`{"model":"gpt-5.6","stream":true,"input":[]}`), 1<<20, responsesStreamOptions{ctx: ctx})
	if spooled != nil {
		spooled.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lexical cancellation error = %v", err)
	}
}

func TestDiskResponsesSparkRejectsNonProAccount(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "spark-plan-secret")
	base, _ := url.Parse("https://chatgpt.example")
	called := false
	h := &proxyHandler{
		cfg:      &config{maxInMemoryBodyBytes: 32, maxSpoolBodyBytes: 1 << 20, maxWireBodyBytes: 1 << 20, maxAttempts: 1, disableRefresh: true},
		pool:     newPoolState([]*Account{{Type: AccountTypeCodex, ID: "free", AccessToken: "free-token", AccountID: "free", PlanType: "free"}}, false),
		registry: NewProviderRegistry(NewCodexProvider(base, base, base), NewClaudeProvider(base), NewGeminiProvider(base, base)),
		transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return preflightReply(), nil
		}),
		metrics: newMetrics(), recent: newRecentErrors(5), aliases: newModelAliases(nil), responsesSpoolBodies: make(chan struct{}, 1),
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-5.3-codex-spark","stream":true,"input":"`+strings.Repeat("x", 1024)+`"}`))
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("spark-plan-secret", "spark-user"))
	rr := httptest.NewRecorder()
	h.proxyRequest(rr, req, "spark-plan")
	if rr.Code != http.StatusServiceUnavailable || called {
		t.Fatalf("status=%d called=%v body=%s", rr.Code, called, rr.Body.String())
	}
}

func TestCompressedSmallStreamingResponsesReturnToBufferedPath(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "small-stream-secret")
	plain := []byte(`{"model":"gpt-5.6","stream":true,"input":"hello"}`)
	wire := compressedResponsesBody(t, "gzip", plain)
	var h *proxyHandler
	h = preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if len(h.responsesSpoolBodies) != 0 {
			t.Error("small decoded request retained disk admission during upstream response")
		}
		deadline, ok := req.Context().Deadline()
		if !ok || time.Until(deadline) > 3*time.Minute || time.Until(deadline) < 3*time.Minute-time.Second {
			t.Errorf("stream timeout not preserved: %v", time.Until(deadline))
		}
		return preflightReply(), nil
	}))
	h.cfg.maxInMemoryBodyBytes = 1 << 20
	h.cfg.maxSpoolBodyBytes = 1 << 20
	h.cfg.maxWireBodyBytes = 1 << 20
	h.responsesSpoolBodies = make(chan struct{}, 1)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("small-stream-secret", "small-user"))
	req.Header.Set("Content-Encoding", "gzip")
	rr := httptest.NewRecorder()
	h.proxyRequest(rr, req, "small-stream")
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestLargeDiskStreamingResponsesPreserveStreamTimeout(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "large-timeout-secret")
	for _, mode := range []string{"pooled", "passthrough"} {
		t.Run(mode, func(t *testing.T) {
			base, _ := url.Parse("https://chatgpt.example")
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				deadline, ok := req.Context().Deadline()
				if !ok || time.Until(deadline) > 2*time.Second || time.Until(deadline) < time.Second {
					t.Errorf("large disk stream timeout not preserved: %v", time.Until(deadline))
				}
				return preflightReply(), nil
			})
			h := &proxyHandler{
				cfg:       &config{maxInMemoryBodyBytes: 32, maxSpoolBodyBytes: 1 << 20, maxWireBodyBytes: 1 << 20, streamTimeout: 2 * time.Second, disableRefresh: true},
				pool:      newPoolState([]*Account{{Type: AccountTypeCodex, ID: "codex", AccessToken: "token", AccountID: "account", PlanType: "pro"}}, false),
				registry:  NewProviderRegistry(NewCodexProvider(base, base, base), NewClaudeProvider(base), NewGeminiProvider(base, base)),
				transport: transport, metrics: newMetrics(), recent: newRecentErrors(5), aliases: newModelAliases(nil), responsesSpoolBodies: make(chan struct{}, 1),
			}
			body := `{"model":"gpt-5.6","stream":true,"input":"` + strings.Repeat("x", 2048) + `"}`
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
			if mode == "pooled" {
				req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("large-timeout-secret", "large-user"))
			} else {
				req.Header.Set("Authorization", "Bearer sk-proj-large-timeout")
			}
			rr := httptest.NewRecorder()
			h.proxyRequest(rr, req, "large-timeout")
			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestDiskResponsesUploadTimeoutReleasesFilesAndAdmission(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "upload-timeout-secret")
	for _, mode := range []string{"pooled", "passthrough"} {
		t.Run(mode, func(t *testing.T) {
			h := preflightHandler(roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("timed-out upload reached upstream")
				return nil, nil
			}))
			h.cfg.maxSpoolBodyBytes = 1 << 20
			h.cfg.maxWireBodyBytes = 1 << 20
			h.cfg.responsesBodyTimeout = 50 * time.Millisecond
			h.responsesSpoolBodies = make(chan struct{}, 1)
			beforeDecoded, _ := filepath.Glob(filepath.Join(os.TempDir(), "codex-pool-responses-decoded-*.json"))
			beforeOutput, _ := filepath.Glob(filepath.Join(os.TempDir(), "codex-pool-responses-*.json"))
			reader, writer := io.Pipe()
			defer writer.Close()
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", reader)
			req.ContentLength = -1
			if mode == "pooled" {
				req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("upload-timeout-secret", "timeout-user"))
			} else {
				req.Header.Set("Authorization", "Bearer sk-proj-timeout")
			}
			rr := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { defer close(done); h.proxyRequest(rr, req, "upload-timeout") }()
			_, _ = io.WriteString(writer, `{"model":"gpt-5.6","stream":true,"input":"`)
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("blocked upload did not time out")
			}
			if rr.Code != http.StatusRequestTimeout || !strings.Contains(rr.Body.String(), "upload timed out") {
				t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
			}
			if len(h.responsesSpoolBodies) != 0 {
				t.Fatal("spool admission slot leaked")
			}
			afterDecoded, _ := filepath.Glob(filepath.Join(os.TempDir(), "codex-pool-responses-decoded-*.json"))
			afterOutput, _ := filepath.Glob(filepath.Join(os.TempDir(), "codex-pool-responses-*.json"))
			if len(afterDecoded) != len(beforeDecoded) || len(afterOutput) != len(beforeOutput) {
				t.Fatalf("temporary files leaked decoded %d->%d output %d->%d", len(beforeDecoded), len(afterDecoded), len(beforeOutput), len(afterOutput))
			}
		})
	}
}

func TestConnectedResponsesCancellationInterruptsStalledUpload(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "connected-cancel-secret")
	h := preflightHandler(roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("cancelled connected upload reached upstream")
		return nil, nil
	}))
	h.cfg.maxSpoolBodyBytes = 1 << 20
	h.cfg.maxWireBodyBytes = 1 << 20
	h.cfg.responsesBodyTimeout = 5 * time.Second
	h.responsesSpoolBodies = make(chan struct{}, 1)
	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "codex-pool-responses-*.json"))
	handlerDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		h.proxyRequest(w, r, "connected-cancel")
	}))
	defer server.Close()
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/responses", reader)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("connected-cancel-secret", "cancel-user"))
	clientDone := make(chan error, 1)
	go func() {
		resp, err := server.Client().Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		clientDone <- err
	}()
	if _, err := io.WriteString(writer, `{"model":"gpt-5.6","stream":true,"input":"`); err != nil {
		t.Fatal(err)
	}
	admittedBy := time.Now().Add(time.Second)
	for len(h.responsesSpoolBodies) == 0 && time.Now().Before(admittedBy) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(h.responsesSpoolBodies) != 1 {
		t.Fatal("connected upload never acquired spool admission")
	}
	started := time.Now()
	cancel()
	select {
	case <-handlerDone:
		if time.Since(started) > time.Second {
			t.Fatalf("cancellation release took %s", time.Since(started))
		}
	case <-time.After(time.Second):
		t.Fatal("connected cancellation waited for upload deadline")
	}
	_ = writer.Close()
	select {
	case <-clientDone:
	case <-time.After(time.Second):
		t.Fatal("cancelled client did not return")
	}
	if len(h.responsesSpoolBodies) != 0 {
		t.Fatal("connected cancellation leaked spool admission")
	}
	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "codex-pool-responses-*.json"))
	if len(after) != len(before) {
		t.Fatalf("connected cancellation leaked temporary files: %d -> %d", len(before), len(after))
	}
}

func TestPassthroughDiskResponseFilterLimitFailsClosed(t *testing.T) {
	upstreamBody := `{"output":[{"type":"mcp_call","output":"PRIVATE-` + strings.Repeat("x", 1024) + `"}]}`
	base, _ := url.Parse("https://chatgpt.example")
	codex := NewCodexProvider(base, base, base)
	h := &proxyHandler{
		cfg:      &config{maxInMemoryBodyBytes: 128, maxSpoolBodyBytes: 1 << 20, maxWireBodyBytes: 1 << 20},
		registry: NewProviderRegistry(codex, NewClaudeProvider(base), NewGeminiProvider(base, base)),
		transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(upstreamBody))}, nil
		}),
		pool: newPoolState(nil, false), metrics: newMetrics(), recent: newRecentErrors(5), responsesSpoolBodies: make(chan struct{}, 1),
	}
	requestBody := `{"model":"gpt-5.6","stream":false,"padding":"` + strings.Repeat("q", 1024) + `","input":"hello"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(requestBody))
	req.Header.Set("Authorization", "Bearer sk-proj-filter-limit")
	rr := httptest.NewRecorder()
	h.proxyRequest(rr, req, "filter-limit")
	if rr.Code != http.StatusBadGateway || strings.Contains(rr.Body.String(), "PRIVATE-") || !strings.Contains(rr.Body.String(), "hosted-MCP filter limit") {
		t.Fatalf("response did not fail closed: status=%d body=%q", rr.Code, rr.Body.String())
	}
}

// The disk model router deliberately supports fewer providers than the buffered
// pipeline. Wire compression must not turn a small buffered request into a
// disk-router rejection, or subject it to Codex-specific control-value limits.
func TestCompressedSmallResponsesPreserveBufferedProviderAdmission(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "small-provider-secret")
	plain := []byte(`{"model":"antigravity/gemini-3.5-flash","stream":true,"input":"hello"}`)
	for _, encoding := range []string{"", "gzip", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			h := preflightHandler(roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("unconfigured provider reached upstream")
				return nil, nil
			}))
			h.cfg.maxInMemoryBodyBytes = 1 << 20
			h.cfg.maxSpoolBodyBytes = 1 << 20
			h.responsesSpoolBodies = make(chan struct{}, 1)
			wire := compressedResponsesBody(t, encoding, plain)
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(wire))
			req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("small-provider-secret", "small-user"))
			req.Header.Set("Content-Encoding", encoding)
			rr := httptest.NewRecorder()
			h.proxyRequest(rr, req, "small-provider")
			if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "Antigravity provider is not configured") {
				t.Fatalf("compressed buffered routing changed: status=%d body=%s", rr.Code, rr.Body.String())
			}
			if len(h.responsesSpoolBodies) != 0 {
				t.Error("fallback spool slot leaked")
			}
		})
	}
}

func TestCompressedSmallPassthroughAvoidsDiskOnlyControlLimits(t *testing.T) {
	var body strings.Builder
	body.WriteString(`{"model":"gpt-5.6","stream":true,"input":[]`)
	for i := 0; i < maxResponsesTopLevelFields+1; i++ {
		fmt.Fprintf(&body, `,"extra_%d":%d`, i, i)
	}
	body.WriteString(`}`)
	plain := []byte(body.String())
	for _, encoding := range []string{"", "gzip", "zstd"} {
		for _, chunked := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/chunked=%v", encoding, chunked), func(t *testing.T) {
				h := preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
					got, err := io.ReadAll(req.Body)
					if err != nil || !bytes.Equal(got, plain) {
						t.Errorf("small BYOK control fields changed: gotBytes=%d err=%v", len(got), err)
					}
					if req.Header.Get("Authorization") != "Bearer sk-proj-small-controls" {
						t.Error("BYOK auth changed")
					}
					return preflightReply(), nil
				}))
				h.cfg.maxInMemoryBodyBytes = 1 << 20
				h.cfg.maxSpoolBodyBytes = 1 << 20
				h.responsesSpoolBodies = make(chan struct{}, 1)
				req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(compressedResponsesBody(t, encoding, plain)))
				req.Header.Set("Authorization", "Bearer sk-proj-small-controls")
				req.Header.Set("Content-Encoding", encoding)
				if chunked {
					req.ContentLength = -1
				}
				rr := httptest.NewRecorder()
				h.proxyRequest(rr, req, "small-controls")
				if rr.Code != http.StatusOK {
					t.Fatalf("valid small BYOK request rejected: status=%d error=%s", rr.Code, rr.Body.String())
				}
				if len(h.responsesSpoolBodies) != 0 {
					t.Error("BYOK admission leaked")
				}
			})
		}
	}
}
