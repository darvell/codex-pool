package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestShouldRetryBufferedSSEForCyberPolicy locks down the gating
// logic that decides whether a buffered SSE-translation response
// should be discarded and retried on a cyber_access account when
// cyber_policy fired mid-stream.
func TestShouldRetryBufferedSSEForCyberPolicy(t *testing.T) {
	h := &proxyHandler{}
	nonCyberAcc := &Account{ID: "shiv_1", Type: AccountTypeCodex}
	cyberAcc := &Account{ID: "darv", Type: AccountTypeCodex, CyberAccess: true}

	cases := []struct {
		name        string
		cyberPinned bool
		attempt     int
		attempts    int
		acc         *Account
		want        bool
	}{
		{"hit on non-cyber with retries left", true, 1, 3, nonCyberAcc, true},
		{"hit on non-cyber but no retries left", true, 3, 3, nonCyberAcc, false},
		{"hit on non-cyber attempts==1 means no retry", true, 1, 1, nonCyberAcc, false},
		{"no cyber_policy hit -> no retry", false, 1, 3, nonCyberAcc, false},
		{"cyber_policy on cyber account itself -> no further swap", true, 1, 3, cyberAcc, false},
		{"nil account -> safe no-op", true, 1, 3, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := h.shouldRetryBufferedSSEForCyberPolicy(tc.cyberPinned, tc.attempt, tc.attempts, tc.acc, "test", "label")
			if got != tc.want {
				t.Fatalf("shouldRetryBufferedSSEForCyberPolicy(%+v) = %v, want %v", tc, got, tc.want)
			}
		})
	}
}

// TestResponsesNonStreamingBufferedRetriesOnCyberPolicy covers the
// `/v1/responses` non-streaming buffered path: an OpenAI SDK client
// (or any direct caller) hits POST /v1/responses with stream:false,
// the proxy buffers the upstream SSE and assembles a single JSON
// response. Before the fix, a cyber_policy event mid-stream produced a
// partial/empty buffered response; after the fix, the proxy detects it,
// retries on a cyber account, and writes the real assembled answer.
func TestResponsesNonStreamingBufferedRetriesOnCyberPolicy(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	base, _ := url.Parse("https://chatgpt.com/backend-api")
	ordinary := &Account{Type: AccountTypeCodex, ID: "ordinary", AccessToken: "ordinary-token", AccountID: "acct_ordinary", PlanType: "pro"}
	cyber := &Account{Type: AccountTypeCodex, ID: "cyber", AccessToken: "cyber-token", AccountID: "acct_cyber", PlanType: "pro", CyberAccess: true}

	var accounts []string
	cleanSSE := strings.Join([]string{
		`event: response.created`,
		`data: {"type":"response.created","response":{"id":"resp_clean","status":"in_progress"}}`,
		``,
		`event: response.output_item.added`,
		`data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant","content":[]}}`,
		``,
		`event: response.output_text.delta`,
		`data: {"type":"response.output_text.delta","output_index":0,"item_id":"msg_1","content_index":0,"delta":"reply from cyber"}`,
		``,
		`event: response.output_item.done`,
		`data: {"type":"response.output_item.done","output_index":0,"item":{"id":"msg_1","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"reply from cyber"}]}}`,
		``,
		`event: response.completed`,
		`data: {"type":"response.completed","response":{"id":"resp_clean","status":"completed","usage":{"input_tokens":3,"output_tokens":5,"total_tokens":8}}}`,
		``,
		``,
	}, "\n")

	flaggedSSE := strings.Join([]string{
		`event: response.created`,
		`data: {"type":"response.created","response":{"id":"resp_flagged"}}`,
		``,
		`event: error`,
		`data: {"type":"error","error":{"type":"invalid_request","code":"cyber_policy","message":"This content was flagged for possible cybersecurity risk."}}`,
		``,
		``,
	}, "\n")

	h := &proxyHandler{
		cfg: &config{maxAttempts: 3, maxInMemoryBodyBytes: 4096},
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			accountID := req.Header.Get("ChatGPT-Account-ID")
			accounts = append(accounts, accountID)
			body := flaggedSSE
			if accountID == "acct_cyber" {
				body = cleanSSE
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(bytes.NewBufferString(body)),
			}, nil
		}),
		refreshTransport: http.DefaultTransport,
		pool:             newPoolState([]*Account{ordinary, cyber}, false),
		registry:         NewProviderRegistry(NewCodexProvider(base, base, base), NewClaudeProvider(base), NewGeminiProvider(base, base)),
		metrics:          newMetrics(),
		recent:           newRecentErrors(5),
	}
	h.cfg.debug.Store(true)

	reqBody := []byte(`{"model":"gpt-5.5","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}],"stream":false}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("test-secret", "user-buffered-responses"))
	req.Header.Set("session_id", "buffered-responses-cyber-test")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	bodyStr := rr.Body.String()
	if strings.Contains(bodyStr, "cyber_policy") || strings.Contains(bodyStr, "cybersecurity") {
		t.Fatalf("client received policy text: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "reply from cyber") {
		t.Fatalf("client did not receive cyber-account text; got: %s", bodyStr)
	}
	var assembled map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &assembled); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody=%s", err, bodyStr)
	}
	if assembled["status"] != "completed" {
		t.Errorf("expected status=completed, got %v", assembled["status"])
	}

	if len(accounts) < 2 || accounts[0] != "acct_ordinary" {
		t.Fatalf("first attempt account = %#v, want acct_ordinary first", accounts)
	}
	foundCyber := false
	for _, a := range accounts {
		if a == "acct_cyber" {
			foundCyber = true
			break
		}
	}
	if !foundCyber {
		t.Fatalf("cyber account never dialed; accounts = %#v", accounts)
	}
}

// behavioral regression for the "Claude SDK calling a Codex model"
// pipeline: the proxy buffers the upstream SSE, translates to Claude
// JSON, and writes once. Before the fix, a cyber_policy event mid-stream
// produced an empty translated response. After the fix, the proxy
// detects the policy event, discards the buffer, retries on a cyber
// account, and writes the real translated answer.
func TestClaudeSDKBufferedTranslationRetriesOnCyberPolicy(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	base, _ := url.Parse("https://chatgpt.com/backend-api")
	ordinary := &Account{Type: AccountTypeCodex, ID: "ordinary", AccessToken: "ordinary-token", AccountID: "acct_ordinary", PlanType: "pro"}
	cyber := &Account{Type: AccountTypeCodex, ID: "cyber", AccessToken: "cyber-token", AccountID: "acct_cyber", PlanType: "pro", CyberAccess: true}

	var accounts []string
	cleanSSE := strings.Join([]string{
		`event: response.created`,
		`data: {"type":"response.created","response":{"id":"resp_clean"}}`,
		``,
		`event: response.output_item.added`,
		`data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant","content":[]}}`,
		``,
		`event: response.content_part.added`,
		`data: {"type":"response.content_part.added","output_index":0,"item_id":"msg_1","content_index":0,"part":{"type":"output_text","text":""}}`,
		``,
		`event: response.output_text.delta`,
		`data: {"type":"response.output_text.delta","output_index":0,"item_id":"msg_1","content_index":0,"delta":"hello from cyber"}`,
		``,
		`event: response.output_text.done`,
		`data: {"type":"response.output_text.done","output_index":0,"item_id":"msg_1","content_index":0,"text":"hello from cyber"}`,
		``,
		`event: response.content_part.done`,
		`data: {"type":"response.content_part.done","output_index":0,"item_id":"msg_1","content_index":0,"part":{"type":"output_text","text":"hello from cyber"}}`,
		``,
		`event: response.output_item.done`,
		`data: {"type":"response.output_item.done","output_index":0,"item":{"id":"msg_1","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"hello from cyber"}]}}`,
		``,
		`event: response.completed`,
		`data: {"type":"response.completed","response":{"id":"resp_clean","status":"completed","usage":{"input_tokens":3,"output_tokens":4,"total_tokens":7}}}`,
		``,
		``,
	}, "\n")

	flaggedSSE := strings.Join([]string{
		`event: response.created`,
		`data: {"type":"response.created","response":{"id":"resp_flagged"}}`,
		``,
		`event: error`,
		`data: {"type":"error","error":{"type":"invalid_request","code":"cyber_policy","message":"This content was flagged for possible cybersecurity risk."}}`,
		``,
		``,
	}, "\n")

	h := &proxyHandler{
		cfg: &config{
			maxAttempts:          3,
			maxInMemoryBodyBytes: 4096,
		},
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			accountID := req.Header.Get("ChatGPT-Account-ID")
			accounts = append(accounts, accountID)
			body := flaggedSSE
			if accountID == "acct_cyber" {
				body = cleanSSE
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(bytes.NewBufferString(body)),
			}, nil
		}),
		refreshTransport: http.DefaultTransport,
		pool:             newPoolState([]*Account{ordinary, cyber}, false),
		registry:         NewProviderRegistry(NewCodexProvider(base, base, base), NewClaudeProvider(base), NewGeminiProvider(base, base)),
		metrics:          newMetrics(),
		recent:           newRecentErrors(5),
	}
	h.cfg.debug.Store(true)

	// Non-streaming Claude SDK request hitting a Codex model — this is
	// the buffered-translation path (TranslateClaudeToResponses).
	reqBody := []byte(`{"model":"gpt-5.5","max_tokens":128,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],"stream":false}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("test-secret", "user-buffered"))
	req.Header.Set("session_id", "buffered-cyber-test")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	bodyStr := rr.Body.String()
	if strings.Contains(bodyStr, "cyber_policy") || strings.Contains(bodyStr, "cybersecurity") {
		t.Fatalf("client received policy text: %s", bodyStr)
	}

	// The translated Claude response must contain the cyber account's
	// assistant text — proving the retry actually happened and the
	// flagged buffer was discarded.
	if !strings.Contains(bodyStr, "hello from cyber") {
		t.Fatalf("client did not receive cyber-account text; got: %s", bodyStr)
	}

	// Validate it parses as Claude-format JSON.
	var claude map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &claude); err != nil {
		t.Fatalf("response is not valid JSON: %v\nbody=%s", err, bodyStr)
	}
	if claude["type"] != "message" {
		t.Errorf("expected type=message, got %v", claude["type"])
	}

	// Both accounts were dialed: ordinary first (flagged), cyber second
	// (succeeded).
	if len(accounts) < 2 {
		t.Fatalf("accounts = %#v, expected at least ordinary then cyber", accounts)
	}
	if accounts[0] != "acct_ordinary" {
		t.Fatalf("first attempt account = %q, want acct_ordinary", accounts[0])
	}
	foundCyber := false
	for _, a := range accounts {
		if a == "acct_cyber" {
			foundCyber = true
			break
		}
	}
	if !foundCyber {
		t.Fatalf("cyber account never dialed; accounts = %#v", accounts)
	}
}
