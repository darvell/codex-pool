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

	"github.com/coder/websocket"
)

func TestCodexProxyStripsHostedMCPFromResponsesRequest(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	received := make(chan map[string]any, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream request: %v", err)
		}
		var request map[string]any
		if err := json.Unmarshal(body, &request); err != nil {
			t.Errorf("decode upstream request: %v; body=%s", err, body)
		}
		received <- request

		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_test\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n")
	}))
	defer upstream.Close()

	baseURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	codex := NewCodexProvider(baseURL, baseURL, baseURL)
	registry := NewProviderRegistry(
		codex,
		NewClaudeProvider(baseURL),
		NewGeminiProvider(baseURL, baseURL),
	)
	account := &Account{
		Type:        AccountTypeCodex,
		ID:          "codex_test",
		AccessToken: "upstream-token",
		AccountID:   "acct_test",
		PlanType:    "pro",
	}
	handler := &proxyHandler{
		cfg: &config{
			requestTimeout:       5 * time.Second,
			streamTimeout:        5 * time.Second,
			maxInMemoryBodyBytes: 1024 * 1024,
			maxAttempts:          1,
		},
		transport: http.DefaultTransport,
		pool:      newPoolState([]*Account{account}, false),
		registry:  registry,
		metrics:   newMetrics(),
		recent:    newRecentErrors(5),
	}
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	body := []byte(`{
		"model":"gpt-5.4",
		"stream":true,
		"input":[
			{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]},
			{"type":"mcp_approval_response","approval_request_id":"approval-secret","approve":true}
		],
		"tools":[
			{"type":"mcp","server_label":"private-drive","server_url":"https://private.example/mcp"},
			{"type":"web_search","search_context_size":"low"},
			{"type":"tool_search","description":"deferred tools"},
			{"type":"function","name":"local_mcp_tool","description":"local tool","parameters":{"type":"object"}}
		],
		"tool_choice":{"type":"mcp","server_label":"private-drive","name":"read_secret"}
	}`)
	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/v1/responses", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("test-secret", "mcp-filter-user"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		responseBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, responseBody)
	}

	select {
	case got := <-received:
		tools, _ := got["tools"].([]any)
		if len(tools) != 3 {
			t.Fatalf("upstream tools=%#v, want three non-MCP tools", tools)
		}
		wantTypes := []string{"web_search", "tool_search", "function"}
		for i, wantType := range wantTypes {
			tool, _ := tools[i].(map[string]any)
			if tool["type"] != wantType {
				t.Fatalf("tool[%d].type=%#v, want %q; tools=%#v", i, tool["type"], wantType, tools)
			}
		}
		input, _ := got["input"].([]any)
		if len(input) != 1 {
			t.Fatalf("upstream input=%#v, want only the user message", input)
		}
		if _, ok := got["tool_choice"]; ok {
			t.Fatalf("upstream retained hosted MCP tool_choice: %#v", got["tool_choice"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream request")
	}
}

func TestCodexProxyStripsHostedMCPFromResponsesStream(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, strings.Join([]string{
			`event: response.output_item.added`,
			`data: {"type":"response.output_item.added","output_index":0,"item":{"id":"mcp_1","type":"mcp_list_tools","server_label":"private-drive","tools":[{"name":"secret_tool"}]}}`,
			``,
			`event: response.output_item.done`,
			`data: {"type":"response.output_item.done","output_index":0,"item":{"id":"mcp_1","type":"mcp_list_tools","server_label":"private-drive","tools":[{"name":"secret_tool"}]}}`,
			``,
			`event: response.output_item.done`,
			`data: {"type":"response.output_item.done","output_index":1,"item":{"id":"ws_1","type":"web_search_call","status":"completed","action":{"type":"search","query":"public query"}}}`,
			``,
			`event: response.output_item.done`,
			`data: {"type":"response.output_item.done","output_index":2,"item":{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"safe answer"}]}}`,
			``,
			`event: response.completed`,
			`data: {"type":"response.completed","response":{"id":"resp_test","output":[{"id":"mcp_2","type":"mcp_call","server_label":"private-drive","name":"read_secret","arguments":"{\"path\":\"private\"}","output":"TOP-SECRET-MCP-RESULT"},{"id":"ws_1","type":"web_search_call","status":"completed"},{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"safe answer"}]}],"usage":{"input_tokens":1,"output_tokens":1}}}`,
			``,
			``,
		}, "\n"))
		w.(http.Flusher).Flush()
	}))
	defer upstream.Close()

	baseURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	codex := NewCodexProvider(baseURL, baseURL, baseURL)
	handler := &proxyHandler{
		cfg: &config{
			requestTimeout:       5 * time.Second,
			streamTimeout:        5 * time.Second,
			maxInMemoryBodyBytes: 1024 * 1024,
			maxAttempts:          1,
		},
		transport: http.DefaultTransport,
		pool: newPoolState([]*Account{{
			Type:        AccountTypeCodex,
			ID:          "codex_test",
			AccessToken: "upstream-token",
			AccountID:   "acct_test",
			PlanType:    "pro",
		}}, false),
		registry: NewProviderRegistry(
			codex,
			NewClaudeProvider(baseURL),
			NewGeminiProvider(baseURL, baseURL),
		),
		metrics: newMetrics(),
		recent:  newRecentErrors(5),
	}
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/v1/responses", strings.NewReader(`{"model":"gpt-5.4","stream":true,"input":"hello"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("test-secret", "mcp-filter-user"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, responseBody)
	}

	for _, forbidden := range []string{"mcp_list_tools", "mcp_call", "private-drive", "secret_tool", "TOP-SECRET-MCP-RESULT"} {
		if bytes.Contains(responseBody, []byte(forbidden)) {
			t.Fatalf("response exposed %q:\n%s", forbidden, responseBody)
		}
	}
	for _, required := range []string{"web_search_call", "public query", "safe answer", "response.completed"} {
		if !bytes.Contains(responseBody, []byte(required)) {
			t.Fatalf("response lost %q:\n%s", required, responseBody)
		}
	}
}

func TestCodexWebSocketStripsHostedMCPFrames(t *testing.T) {
	state := &codexRelayState{}

	request := []byte(`{
		"type":"response.create",
		"model":"gpt-5.4",
		"input":[
			{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]},
			{"type":"mcp_approval_response","approval_request_id":"approval-secret","approve":true}
		],
		"tools":[
			{"type":"mcp","server_label":"private-drive","server_url":"https://private.example/mcp"},
			{"type":"web_search","search_context_size":"low"},
			{"type":"tool_search","description":"deferred tools"},
			{"type":"function","name":"local_mcp_tool","parameters":{"type":"object"}}
		],
		"tool_choice":{"type":"mcp","server_label":"private-drive","name":"read_secret"}
	}`)
	filteredRequest, err := state.inspectClient(request)
	if err != nil {
		t.Fatalf("filter client frame: %v", err)
	}
	for _, forbidden := range []string{`"type":"mcp"`, "private-drive", "private.example", "approval-secret"} {
		if bytes.Contains(filteredRequest, []byte(forbidden)) {
			t.Fatalf("request exposed %q: %s", forbidden, filteredRequest)
		}
	}
	for _, required := range []string{"web_search", "tool_search", "local_mcp_tool"} {
		if !bytes.Contains(filteredRequest, []byte(required)) {
			t.Fatalf("request lost %q: %s", required, filteredRequest)
		}
	}

	mcpEvent := []byte(`{"type":"response.output_item.done","item":{"id":"mcp_1","type":"mcp_call","server_label":"private-drive","output":"TOP-SECRET-MCP-RESULT"}}`)
	filteredEvent, err := state.inspectUpstream(mcpEvent)
	if err != nil {
		t.Fatalf("filter upstream MCP frame: %v", err)
	}
	if len(filteredEvent) != 0 {
		t.Fatalf("MCP-only upstream frame was not dropped: %s", filteredEvent)
	}

	completed := []byte(`{"type":"response.completed","response":{"id":"resp_test","output":[{"id":"mcp_2","type":"mcp_call","output":"TOP-SECRET-MCP-RESULT"},{"id":"ws_1","type":"web_search_call","status":"completed"},{"id":"msg_1","type":"message","content":[{"type":"output_text","text":"safe answer"}]}]}}`)
	filteredCompleted, err := state.inspectUpstream(completed)
	if err != nil {
		t.Fatalf("filter upstream completion frame: %v", err)
	}
	for _, forbidden := range []string{"mcp_call", "TOP-SECRET-MCP-RESULT"} {
		if bytes.Contains(filteredCompleted, []byte(forbidden)) {
			t.Fatalf("completion exposed %q: %s", forbidden, filteredCompleted)
		}
	}
	for _, required := range []string{"response.completed", "web_search_call", "safe answer"} {
		if !bytes.Contains(filteredCompleted, []byte(required)) {
			t.Fatalf("completion lost %q: %s", required, filteredCompleted)
		}
	}
}

func TestCodexPassthroughStripsHostedMCPFromLargeRequestAndJSONResponse(t *testing.T) {
	received := make(chan []byte, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream request: %v", err)
		}
		received <- body
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_test","output":[{"id":"mcp_1","type":"mcp_call","server_label":"private-drive","output":"TOP-SECRET-MCP-RESULT"},{"id":"ws_1","type":"web_search_call","status":"completed"},{"id":"msg_1","type":"message","content":[{"type":"output_text","text":"safe answer"}]}]}`)
	}))
	defer upstream.Close()

	baseURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	handler := &proxyHandler{
		cfg: &config{
			requestTimeout:       5 * time.Second,
			streamTimeout:        5 * time.Second,
			maxInMemoryBodyBytes: 64,
		},
		transport: http.DefaultTransport,
		pool:      newPoolState(nil, false),
		registry: NewProviderRegistry(
			NewCodexProvider(baseURL, baseURL, baseURL),
			NewClaudeProvider(baseURL),
			NewGeminiProvider(baseURL, baseURL),
		),
		metrics: newMetrics(),
		recent:  newRecentErrors(5),
	}
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	requestBody := []byte(`{
		"model":"gpt-5.4",
		"stream":false,
		"instructions":"padding-padding-padding-padding-padding-padding-padding-padding",
		"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]},{"type":"mcp_approval_response","approval_request_id":"approval-secret","approve":true}],
		"tools":[{"type":"mcp","server_label":"private-drive","server_url":"https://private.example/mcp"},{"type":"web_search"},{"type":"function","name":"local_mcp_tool","parameters":{"type":"object"}}]
	}`)
	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/v1/responses", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-proj-passthrough-test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}

	select {
	case upstreamBody := <-received:
		for _, forbidden := range []string{`"type":"mcp"`, "private.example", "approval-secret"} {
			if bytes.Contains(upstreamBody, []byte(forbidden)) {
				t.Fatalf("passthrough request exposed %q: %s", forbidden, upstreamBody)
			}
		}
		for _, required := range []string{"web_search", "local_mcp_tool"} {
			if !bytes.Contains(upstreamBody, []byte(required)) {
				t.Fatalf("passthrough request lost %q: %s", required, upstreamBody)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for passthrough upstream request")
	}

	for _, forbidden := range []string{"mcp_call", "private-drive", "TOP-SECRET-MCP-RESULT"} {
		if bytes.Contains(responseBody, []byte(forbidden)) {
			t.Fatalf("passthrough response exposed %q: %s", forbidden, responseBody)
		}
	}
	for _, required := range []string{"web_search_call", "safe answer"} {
		if !bytes.Contains(responseBody, []byte(required)) {
			t.Fatalf("passthrough response lost %q: %s", required, responseBody)
		}
	}
}

func TestCodexPassthroughWebSocketStripsHostedMCPFrames(t *testing.T) {
	upstream := newFakeCodexUpstream(t)
	received := make(chan []byte, 1)
	upstream.on("acct_pass", func(ctx context.Context, conn *websocket.Conn) {
		_, request, err := conn.Read(ctx)
		if err != nil {
			return
		}
		received <- request
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.output_item.done","item":{"id":"mcp_1","type":"mcp_call","server_label":"private-drive","output":"TOP-SECRET-MCP-RESULT"}}`))
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.output_item.done","item":{"id":"ws_1","type":"web_search_call","status":"completed"}}`))
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.completed","response":{"id":"resp_pass","output":[{"id":"mcp_1","type":"mcp_call","output":"TOP-SECRET-MCP-RESULT"},{"id":"msg_1","type":"message","content":[{"type":"output_text","text":"safe answer"}]}]}}`))
	})

	upURL, err := url.Parse(upstream.server.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	fx := newCodexProxyFixture(t, upURL, nil)
	conn := dialClientWS(t, fx, http.Header{
		"Authorization":      []string{"Bearer sk-proj-passthrough-test"},
		"ChatGPT-Account-ID": []string{"acct_pass"},
	})
	request := []byte(`{"type":"response.create","model":"gpt-5.4","input":[{"type":"message","role":"user"},{"type":"mcp_approval_response","approval_request_id":"approval-secret","approve":true}],"tools":[{"type":"mcp","server_label":"private-drive","server_url":"https://private.example/mcp"},{"type":"web_search"},{"type":"function","name":"local_mcp_tool","parameters":{"type":"object"}}]}`)
	if err := conn.Write(context.Background(), websocket.MessageText, request); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case upstreamRequest := <-received:
		for _, forbidden := range []string{`"type":"mcp"`, "private.example", "approval-secret"} {
			if bytes.Contains(upstreamRequest, []byte(forbidden)) {
				t.Fatalf("passthrough websocket request exposed %q: %s", forbidden, upstreamRequest)
			}
		}
		for _, required := range []string{"web_search", "local_mcp_tool"} {
			if !bytes.Contains(upstreamRequest, []byte(required)) {
				t.Fatalf("passthrough websocket request lost %q: %s", required, upstreamRequest)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for passthrough websocket request")
	}

	frames := mustReadUntil(t, conn, `"response.completed"`, 4*time.Second)
	joined := []byte(strings.Join(frames, "\n"))
	for _, forbidden := range []string{"mcp_call", "private-drive", "TOP-SECRET-MCP-RESULT"} {
		if bytes.Contains(joined, []byte(forbidden)) {
			t.Fatalf("passthrough websocket response exposed %q: %s", forbidden, joined)
		}
	}
	for _, required := range []string{"web_search_call", "safe answer", "response.completed"} {
		if !bytes.Contains(joined, []byte(required)) {
			t.Fatalf("passthrough websocket response lost %q: %s", required, joined)
		}
	}
}
