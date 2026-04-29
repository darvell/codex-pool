package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testWebSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func TestIsWebSocketUpgradeRequest(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://localhost/ws", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Connection", "keep-alive, Upgrade")
	req.Header.Set("Upgrade", "websocket")
	if !isWebSocketUpgradeRequest(req) {
		t.Fatalf("expected websocket upgrade request")
	}

	req.Header.Set("Upgrade", "h2c")
	if isWebSocketUpgradeRequest(req) {
		t.Fatalf("unexpected websocket upgrade detection for non-websocket upgrade")
	}
}

func TestProxyWebSocketPoolRewritesAuthAndPinsSession(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	type upstreamReq struct {
		path            string
		auth            string
		accountID       string
		sessionID       string
		clientRequestID string
		connection      string
		upgrade         string
	}

	upstreamReqCh := make(chan upstreamReq, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReqCh <- upstreamReq{
			path:            r.URL.Path,
			auth:            r.Header.Get("Authorization"),
			accountID:       r.Header.Get("ChatGPT-Account-ID"),
			sessionID:       r.Header.Get("session_id"),
			clientRequestID: r.Header.Get("x-client-request-id"),
			connection:      r.Header.Get("Connection"),
			upgrade:         r.Header.Get("Upgrade"),
		}
		writeWebSocketSwitchingProtocolsResponseWithHeaders(w, r, http.Header{"x-codex-turn-state": []string{"turn-from-ws-upgrade"}})
	}))
	defer upstream.Close()

	baseURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	codex := NewCodexProvider(baseURL, baseURL, baseURL)
	claude := NewClaudeProvider(baseURL)
	gemini := NewGeminiProvider(baseURL, baseURL)
	registry := NewProviderRegistry(codex, claude, gemini)

	acc := &Account{
		Type:        AccountTypeCodex,
		ID:          "codex_pool_1",
		AccessToken: "pool-access-token",
		AccountID:   "acct_pool_1",
		PlanType:    "pro",
	}
	pool := newPoolState([]*Account{acc}, false)

	h := &proxyHandler{
		cfg: &config{
			requestTimeout:       5 * time.Second,
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

	statusLine := performRawWebSocketHandshake(t, proxy.URL, "/responses", map[string]string{
		"Authorization":       "Bearer " + generateClaudePoolToken("test-secret", "ws-user"),
		"session_id":          "thread-ws-1",
		"x-client-request-id": "thread-ws-1",
	})
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("expected 101 response, got %q", statusLine)
	}

	select {
	case got := <-upstreamReqCh:
		if got.path != "/responses" {
			t.Fatalf("upstream path = %q, want %q", got.path, "/responses")
		}
		if got.auth != "Bearer pool-access-token" {
			t.Fatalf("upstream auth = %q, want pooled auth", got.auth)
		}
		if got.accountID != "acct_pool_1" {
			t.Fatalf("upstream ChatGPT-Account-ID = %q, want %q", got.accountID, "acct_pool_1")
		}
		if got.sessionID != "thread-ws-1" {
			t.Fatalf("upstream session_id = %q, want %q", got.sessionID, "thread-ws-1")
		}
		if got.clientRequestID != "thread-ws-1" {
			t.Fatalf("upstream x-client-request-id = %q, want %q", got.clientRequestID, "thread-ws-1")
		}
		if !strings.EqualFold(got.upgrade, "websocket") {
			t.Fatalf("upstream Upgrade = %q, want websocket", got.upgrade)
		}
		if !headerContainsToken(http.Header{"Connection": []string{got.connection}}, "Connection", "Upgrade") {
			t.Fatalf("upstream Connection header missing Upgrade token: %q", got.connection)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for upstream websocket request")
	}

	if acc.CodexTurnState != "turn-from-ws-upgrade" {
		t.Fatalf("CodexTurnState = %q, want turn-from-ws-upgrade", acc.CodexTurnState)
	}
	if got := extractConversationIDFromHeaders(http.Header{"Session_id": []string{"thread-ws-1"}}); got != "thread-ws-1" {
		t.Fatalf("extractConversationIDFromHeaders = %q, want %q", got, "thread-ws-1")
	}
}

func TestProxyWebSocketUsesPinnedAccountBeforeCyberPolicy(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	upstreamAccountID := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAccountID <- r.Header.Get("ChatGPT-Account-ID")
		writeWebSocketSwitchingProtocolsResponse(w, r)
	}))
	defer upstream.Close()

	baseURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	codex := NewCodexProvider(baseURL, baseURL, baseURL)
	claude := NewClaudeProvider(baseURL)
	gemini := NewGeminiProvider(baseURL, baseURL)
	registry := NewProviderRegistry(codex, claude, gemini)

	ordinary := &Account{Type: AccountTypeCodex, ID: "ordinary", AccessToken: "ordinary-token", AccountID: "acct_ordinary", PlanType: "pro"}
	cyber := &Account{Type: AccountTypeCodex, ID: "cyber", AccessToken: "cyber-token", AccountID: "acct_cyber", PlanType: "pro", CyberAccess: true}
	pool := newPoolState([]*Account{ordinary, cyber}, false)
	pool.pin("thread-ws-cyber", "ordinary")

	h := &proxyHandler{
		cfg:       &config{requestTimeout: 5 * time.Second, maxInMemoryBodyBytes: 1024},
		transport: http.DefaultTransport,
		pool:      pool,
		registry:  registry,
		metrics:   newMetrics(),
		recent:    newRecentErrors(5),
	}

	proxy := httptest.NewServer(h)
	defer proxy.Close()

	statusLine := performRawWebSocketHandshake(t, proxy.URL, "/responses", map[string]string{
		"Authorization": "Bearer " + generateClaudePoolToken("test-secret", "ws-user"),
		"session_id":    "thread-ws-cyber",
	})
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("expected 101 response, got %q", statusLine)
	}

	select {
	case got := <-upstreamAccountID:
		if got != "acct_ordinary" {
			t.Fatalf("upstream ChatGPT-Account-ID = %q, want pinned ordinary account", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for upstream websocket request")
	}
}

func TestProxyWebSocketPassthroughPreservesAuthorization(t *testing.T) {
	upstreamAuth := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth <- r.Header.Get("Authorization")
		writeWebSocketSwitchingProtocolsResponse(w, r)
	}))
	defer upstream.Close()

	baseURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	codex := NewCodexProvider(baseURL, baseURL, baseURL)
	claude := NewClaudeProvider(baseURL)
	gemini := NewGeminiProvider(baseURL, baseURL)
	registry := NewProviderRegistry(codex, claude, gemini)

	h := &proxyHandler{
		cfg: &config{
			requestTimeout:       5 * time.Second,
			maxInMemoryBodyBytes: 1024,
		},
		transport: http.DefaultTransport,
		pool:      newPoolState(nil, false),
		registry:  registry,
		metrics:   newMetrics(),
		recent:    newRecentErrors(5),
	}

	proxy := httptest.NewServer(h)
	defer proxy.Close()

	statusLine := performRawWebSocketHandshake(t, proxy.URL, "/responses", map[string]string{
		"Authorization": "Bearer sk-proj-test-passthrough",
	})
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("expected 101 response, got %q", statusLine)
	}

	select {
	case got := <-upstreamAuth:
		if got != "Bearer sk-proj-test-passthrough" {
			t.Fatalf("upstream auth = %q, want passthrough auth", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for upstream websocket auth header")
	}
}

func TestProxyWebSocketPinsMaxPlanWhen1MHeaderPresent(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	type upstreamReq struct {
		authorization string
		apiKey        string
	}
	upstreamReqCh := make(chan upstreamReq, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReqCh <- upstreamReq{
			authorization: r.Header.Get("Authorization"),
			apiKey:        r.Header.Get("X-Api-Key"),
		}
		writeWebSocketSwitchingProtocolsResponse(w, r)
	}))
	defer upstream.Close()

	baseURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	codex := NewCodexProvider(baseURL, baseURL, baseURL)
	claude := NewClaudeProvider(baseURL)
	gemini := NewGeminiProvider(baseURL, baseURL)
	registry := NewProviderRegistry(codex, claude, gemini)

	pro := &Account{Type: AccountTypeClaude, ID: "claude_pro", AccessToken: "pro-token", PlanType: "pro"}
	max := &Account{Type: AccountTypeClaude, ID: "claude_max", AccessToken: "max-token", PlanType: "max"}
	pool := newPoolState([]*Account{pro, max}, false)

	h := &proxyHandler{
		cfg:       &config{requestTimeout: 5 * time.Second, maxInMemoryBodyBytes: 1024},
		transport: http.DefaultTransport,
		pool:      pool,
		registry:  registry,
		metrics:   newMetrics(),
		recent:    newRecentErrors(5),
	}

	proxy := httptest.NewServer(h)
	defer proxy.Close()

	statusLine := performRawWebSocketHandshake(t, proxy.URL, "/v1/messages", map[string]string{
		"Authorization":  "Bearer " + generateClaudePoolToken("test-secret", "ws-user"),
		"anthropic-beta": "context-1m-2025-08-07",
	})
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("expected 101 response, got %q", statusLine)
	}

	select {
	case got := <-upstreamReqCh:
		if got.authorization != "" {
			t.Fatalf("upstream authorization = %q, want empty for API-key auth", got.authorization)
		}
		if got.apiKey != "max-token" {
			t.Fatalf("upstream X-Api-Key = %q, want max plan token", got.apiKey)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for upstream websocket request")
	}
}

func performRawWebSocketHandshake(
	t *testing.T,
	serverURL string,
	path string,
	headers map[string]string,
) string {
	t.Helper()

	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial websocket endpoint: %v", err)
	}
	defer conn.Close()

	key := "dGhlIHNhbXBsZSBub25jZQ=="
	request := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n",
		path,
		u.Host,
		key,
	)
	for k, v := range headers {
		request += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	request += "\r\n"

	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write websocket handshake: %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read websocket status line: %v", err)
	}
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatalf("read websocket response header: %v", readErr)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	return strings.TrimSpace(statusLine)
}

func writeWebSocketSwitchingProtocolsResponse(w http.ResponseWriter, r *http.Request) {
	writeWebSocketSwitchingProtocolsResponseWithHeaders(w, r, nil)
}

func writeWebSocketSwitchingProtocolsResponseWithHeaders(w http.ResponseWriter, r *http.Request, headers http.Header) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	sum := sha1.Sum([]byte(key + testWebSocketGUID))
	accept := base64.StdEncoding.EncodeToString(sum[:])

	_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	_, _ = rw.WriteString("Upgrade: websocket\r\n")
	_, _ = rw.WriteString("Connection: Upgrade\r\n")
	_, _ = rw.WriteString("Sec-WebSocket-Accept: " + accept + "\r\n")
	for key, values := range headers {
		for _, value := range values {
			_, _ = rw.WriteString(key + ": " + value + "\r\n")
		}
	}
	_, _ = rw.WriteString("\r\n")
	_ = rw.Flush()
}
