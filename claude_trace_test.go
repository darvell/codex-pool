package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func traceHeaderLookup(headers map[string][]string, key string) []string {
	for k, values := range headers {
		if http.CanonicalHeaderKey(k) == http.CanonicalHeaderKey(key) {
			return values
		}
	}
	return nil
}

func TestTraceHeaderValueRedactsSecrets(t *testing.T) {
	if got := traceHeaderValue("Authorization", "Bearer secret", false); got != "<redacted>" {
		t.Fatalf("authorization redaction = %q", got)
	}
	if got := traceHeaderValue("X-Api-Key", "sk-ant-api-secret", false); got != "<redacted>" {
		t.Fatalf("x-api-key redaction = %q", got)
	}
	if got := traceHeaderValue("Anthropic-Version", "2023-06-01", false); got != "2023-06-01" {
		t.Fatalf("unexpected public header redaction = %q", got)
	}
	if got := traceHeaderValue("Authorization", "Bearer secret", true); got != "Bearer secret" {
		t.Fatalf("authorization should remain when includeSecrets=true, got %q", got)
	}
}

func waitForTraceFile(t *testing.T, traceDir string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		files, err := os.ReadDir(traceDir)
		if err != nil {
			t.Fatalf("read trace dir: %v", err)
		}
		if len(files) > 0 {
			return filepath.Join(traceDir, files[0].Name())
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("expected trace file to be written")
	return ""
}

func TestClaudeTraceWritesFileForPooledRequest(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	traceDir := t.TempDir()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	baseURL, _ := url.Parse(upstream.URL)
	codex := NewCodexProvider(baseURL, baseURL, baseURL)
	claude := NewClaudeProvider(baseURL)
	gemini := NewGeminiProvider(baseURL, baseURL)
	registry := NewProviderRegistry(codex, claude, gemini)

	acc := &Account{Type: AccountTypeClaude, ID: "claude_test", AccessToken: "sk-ant-api-test", PlanType: "pro"}
	pool := newPoolState([]*Account{acc}, false)

	h := &proxyHandler{
		cfg: &config{
			requestTimeout:       5 * time.Second,
			streamTimeout:        5 * time.Second,
			maxInMemoryBodyBytes: 16 * 1024,
			claudeTraceDir:       traceDir,
			claudeTraceBodyLimit: 16 * 1024,
		},
		transport: http.DefaultTransport,
		pool:      pool,
		registry:  registry,
		metrics:   newMetrics(),
		recent:    newRecentErrors(5),
	}

	proxy := httptest.NewServer(h)
	defer proxy.Close()

	body := []byte(`{"model":"claude-sonnet-4-6","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`)
	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("test-secret", "trace-user"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	tracePath := waitForTraceFile(t, traceDir)
	traceBytes, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatalf("read trace file: %v", err)
	}

	var record struct {
		Mode      string `json:"mode"`
		AccountID string `json:"account_id"`
		Incoming  struct {
			Headers map[string][]string `json:"headers"`
			Body    string              `json:"body"`
		} `json:"incoming"`
		Upstream struct {
			Headers map[string][]string `json:"headers"`
		} `json:"upstream"`
		Response struct {
			Headers map[string][]string `json:"headers"`
			Body    string              `json:"body"`
		} `json:"response"`
	}
	if err := json.Unmarshal(traceBytes, &record); err != nil {
		t.Fatalf("unmarshal trace: %v\n%s", err, string(traceBytes))
	}

	if record.Mode != "pool" {
		t.Fatalf("mode = %q", record.Mode)
	}
	if record.AccountID != "claude_test" {
		t.Fatalf("account_id = %q", record.AccountID)
	}
	if got := traceHeaderLookup(record.Incoming.Headers, "Authorization"); len(got) != 1 || got[0] != "<redacted>" {
		t.Fatalf("incoming authorization = %v", got)
	}
	if got := traceHeaderLookup(record.Upstream.Headers, "X-Api-Key"); len(got) != 1 || got[0] != "<redacted>" {
		t.Fatalf("upstream x-api-key = %v", got)
	}
	if record.Incoming.Body == "" || !bytes.Contains([]byte(record.Incoming.Body), []byte("claude-sonnet-4-6")) {
		t.Fatalf("incoming body missing model: %q", record.Incoming.Body)
	}
	if got := record.Response.Headers[":status_code"]; len(got) != 1 || got[0] != "200" {
		t.Fatalf("response status = %v", got)
	}
	if record.Response.Body == "" || !bytes.Contains([]byte(record.Response.Body), []byte(`"ok":true`)) {
		t.Fatalf("response body = %q", record.Response.Body)
	}
}

func TestClaudeTraceWritesFileForPooledRoundTripError(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	traceDir := t.TempDir()
	baseURL, _ := url.Parse("https://anthropic.invalid")
	codex := NewCodexProvider(baseURL, baseURL, baseURL)
	claude := NewClaudeProvider(baseURL)
	gemini := NewGeminiProvider(baseURL, baseURL)
	registry := NewProviderRegistry(codex, claude, gemini)

	acc := &Account{Type: AccountTypeClaude, ID: "claude_test", AccessToken: "sk-ant-api-test", PlanType: "pro"}
	pool := newPoolState([]*Account{acc}, false)
	transportErr := errors.New("synthetic upstream failure")

	h := &proxyHandler{
		cfg: &config{
			requestTimeout:       5 * time.Second,
			streamTimeout:        5 * time.Second,
			maxInMemoryBodyBytes: 16 * 1024,
			claudeTraceDir:       traceDir,
			claudeTraceBodyLimit: 16 * 1024,
		},
		transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, transportErr
		}),
		pool:     pool,
		registry: registry,
		metrics:  newMetrics(),
		recent:   newRecentErrors(5),
	}

	proxy := httptest.NewServer(h)
	defer proxy.Close()

	body := []byte(`{"model":"claude-sonnet-4-6","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`)
	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("test-secret", "trace-user"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	traceBytes, err := os.ReadFile(waitForTraceFile(t, traceDir))
	if err != nil {
		t.Fatalf("read trace file: %v", err)
	}

	var record struct {
		Mode      string `json:"mode"`
		AccountID string `json:"account_id"`
		Error     string `json:"error"`
		Incoming  struct {
			Body string `json:"body"`
		} `json:"incoming"`
		Upstream struct {
			Body string `json:"body"`
		} `json:"upstream"`
		Response *struct{} `json:"response"`
	}
	if err := json.Unmarshal(traceBytes, &record); err != nil {
		t.Fatalf("unmarshal trace: %v\n%s", err, string(traceBytes))
	}
	if record.Mode != "pool" {
		t.Fatalf("mode = %q", record.Mode)
	}
	if record.AccountID != "claude_test" {
		t.Fatalf("account_id = %q", record.AccountID)
	}
	if !bytes.Contains([]byte(record.Error), []byte(transportErr.Error())) {
		t.Fatalf("error = %q", record.Error)
	}
	if record.Response != nil {
		t.Fatalf("response should be absent on round trip failure")
	}
	if !bytes.Contains([]byte(record.Incoming.Body), []byte("claude-sonnet-4-6")) {
		t.Fatalf("incoming body missing model: %q", record.Incoming.Body)
	}
	if !bytes.Contains([]byte(record.Upstream.Body), []byte("claude-sonnet-4-6")) {
		t.Fatalf("upstream body missing model: %q", record.Upstream.Body)
	}
}
