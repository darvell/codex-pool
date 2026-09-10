package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCompactionFailures(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "compact-failure-secret")
	token := generateClaudePoolToken("compact-failure-secret", "compact-user")
	for _, tc := range []struct {
		name, contentType, body, want string
		status, wantStatus            int
	}{
		{"rejection", "application/json", `{"error":{"message":"invalid context"}}`, "invalid context", http.StatusBadRequest, http.StatusBadRequest},
		{"failed terminal", "text/event-stream", "data: {\"type\":\"response.failed\",\"response\":{\"status\":\"failed\",\"error\":{\"code\":\"context_error\"}}}\n\n", `"status":"failed"`, http.StatusOK, http.StatusOK},
		{"incomplete terminal", "text/event-stream", "data: {\"type\":\"response.incomplete\",\"response\":{\"status\":\"incomplete\"}}\n\n", `"status":"incomplete"`, http.StatusOK, http.StatusOK},
		{"missing terminal", "text/event-stream", "data: {\"type\":\"response.created\",\"response\":{}}\n\n", "without a terminal", http.StatusOK, http.StatusBadGateway},
		{"malformed event", "text/event-stream", "data: {invalid}\n\n", "decode compact event", http.StatusOK, http.StatusBadGateway},
		{"unexpected JSON", "application/json", `{}`, "did not return an event stream", http.StatusOK, http.StatusBadGateway},
		{"timeout", "text/event-stream", ": waiting\n\n", "compaction response", http.StatusOK, http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
				if tc.name == "timeout" {
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				}
			}))
			defer upstream.Close()
			h := preflightHandler(upstream.Client().Transport)
			h.cfg.streamTimeout = time.Second
			base, _ := url.Parse(upstream.URL)
			h.registry = NewProviderRegistry(NewCodexProvider(base, base, nil), NewClaudeProvider(base), NewGeminiProvider(base, base))
			req := httptest.NewRequest(http.MethodPost, "/v1/responses/compact", strings.NewReader(`{"model":"gpt-5.5","input":[]}`))
			req.Header.Set("Authorization", "Bearer "+token)
			rr := httptest.NewRecorder()
			h.proxyRequest(rr, req, "compact-failure")
			if rr.Code != tc.wantStatus || !strings.Contains(rr.Body.String(), tc.want) {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestCompactionRoundTrip(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "compact-test-secret")
	token := generateClaudePoolToken("compact-test-secret", "compact-user")
	const compactOutput = `{"id":"resp_compact","object":"response.compact","status":"completed","output":[{"type":"compaction","encrypted_content":"opaque-state"}],"usage":{"input_tokens":100,"output_tokens":10}}`
	const compactSSE = "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"compaction\",\"encrypted_content\":\"opaque-state\"}}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_compact\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":100,\"output_tokens\":10}}}\n\n"

	for _, tc := range []struct{ path, auth string }{
		{"/v1/responses/compact", token},
		{"/responses/compact", token},
		{"/backend-api/codex/responses/compact", token},
		{"/v1/responses/compact", "sk-test-passthrough"},
		{"/backend-api/codex/responses/compact", "sk-test-passthrough"},
	} {
		path := tc.path
		t.Run(path, func(t *testing.T) {
			calls := 0
			upstreamToken := "upstream-token"
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/backend-api/codex/responses" || r.URL.RawQuery != "trace=compact" {
					t.Errorf("upstream path = %q", r.URL.Path)
				}
				wantAuth := "Bearer " + upstreamToken
				if tc.auth != token {
					wantAuth = "Bearer " + tc.auth
				}
				if r.Header.Get("Authorization") != wantAuth || r.Header.Get("ChatGPT-Account-ID") != "acct" {
					t.Error("incorrect upstream credentials")
				}
				var obj map[string]any
				if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
					t.Error(err)
				}
				if calls == 2 {
					input, _ := obj["input"].([]any)
					if len(input) != 2 || input[0].(map[string]any)["encrypted_content"] != "opaque-state" {
						t.Errorf("compaction replay changed: %#v", obj)
					}
					if r.Header.Get("X-Codex-Turn-State") != "state-after" {
						t.Error("replayed turn state lost")
					}
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, preflightResponse)
					return
				}
				if obj["model"] != "gpt-5.5" || obj["instructions"] != "Keep the project state." {
					t.Errorf("compact request = %#v", obj)
				}
				if obj["stream"] != true || obj["store"] != false {
					t.Errorf("stream/store = %v/%v", obj["stream"], obj["store"])
				}
				for _, key := range []string{"text", "tools", "tool_choice", "max_output_tokens"} {
					if _, ok := obj[key]; ok {
						t.Errorf("compact forwarded %s", key)
					}
				}
				input, _ := obj["input"].([]any)
				if len(input) != 2 || input[1].(map[string]any)["type"] != "compaction_trigger" {
					t.Errorf("compact input = %#v", input)
				}
				metadata, _ := obj["client_metadata"].(map[string]any)
				reasoning, _ := obj["reasoning"].(map[string]any)
				if metadata["session_id"] != "123e4567-e89b-12d3-a456-426614174000" || reasoning["context"] != "all_turns" {
					t.Errorf("context state lost: %#v", obj)
				}
				var turn map[string]any
				_ = json.Unmarshal([]byte(r.Header.Get("X-Codex-Turn-Metadata")), &turn)
				if turn["request_kind"] != "compaction" || turn["turn_id"] != "turn-test" || r.Header.Get("X-Codex-Turn-State") != "state-before" {
					t.Errorf("turn headers = %v", r.Header)
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("X-Codex-Turn-State", "state-after")
				_, _ = io.WriteString(w, compactSSE)
			}))
			defer upstream.Close()

			h := preflightHandler(upstream.Client().Transport)
			base, _ := url.Parse(upstream.URL + "/backend-api/codex")
			wham, _ := url.Parse(upstream.URL + "/backend-api")
			h.registry = NewProviderRegistry(NewCodexProvider(base, wham, nil), NewClaudeProvider(base), NewGeminiProvider(base, base))
			if tc.auth == token {
				account := contextTestAccount("codex", "compact-owner")
				account.AccountID = "acct"
				upstreamToken = account.AccessToken
				h.nativeContext = contextTestService(t, base.String(), account)
				h.pool = h.nativeContext.pool
			}
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h.proxyRequest(w, r, "compact-round-trip")
			}))
			defer proxy.Close()

			body := `{"model":"gpt-5.5","instructions":"Keep the project state.","input":[{"role":"user","content":"Remember the project state."}],"stream":false,"store":true,"max_output_tokens":100,"tools":[],"tool_choice":"auto","text":{"format":{"type":"text"}},"client_metadata":{"session_id":"123e4567-e89b-12d3-a456-426614174000"},"reasoning":{"context":"all_turns"}}`
			req, err := http.NewRequest(http.MethodPost, proxy.URL+path+"?trace=compact", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+tc.auth)
			req.Header.Set("ChatGPT-Account-ID", "acct")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Codex-Turn-Metadata", `{"turn_id":"turn-test","request_kind":"inference"}`)
			req.Header.Set("X-Codex-Turn-State", "state-before")
			resp, err := proxy.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			var actual, expected any
			if err := json.Unmarshal(got, &actual); err != nil {
				t.Fatalf("response is not JSON: %s", got)
			}
			_ = json.Unmarshal([]byte(compactOutput), &expected)
			if calls != 1 || resp.StatusCode != http.StatusOK || !reflect.DeepEqual(actual, expected) {
				t.Fatalf("calls=%d status=%d body=%s", calls, resp.StatusCode, got)
			}
			if resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("X-Codex-Turn-State") != "state-after" {
				t.Errorf("response headers = %v", resp.Header)
			}

			input := actual.(map[string]any)["output"].([]any)
			input = append(input, map[string]any{"role": "user", "content": "Continue."})
			replayBody, err := json.Marshal(map[string]any{"model": "gpt-5.5", "stream": true, "input": input})
			if err != nil {
				t.Fatal(err)
			}
			replay, err := http.NewRequest(http.MethodPost, proxy.URL+strings.TrimSuffix(path, "/compact")+"?trace=compact", bytes.NewReader(replayBody))
			if err != nil {
				t.Fatal(err)
			}
			replay.Header.Set("Authorization", "Bearer "+tc.auth)
			replay.Header.Set("ChatGPT-Account-ID", "acct")
			replay.Header.Set("Content-Type", "application/json")
			replay.Header.Set("X-Codex-Turn-State", resp.Header.Get("X-Codex-Turn-State"))
			replayed, err := proxy.Client().Do(replay)
			if err != nil {
				t.Fatal(err)
			}
			defer replayed.Body.Close()
			replayedBody, err := io.ReadAll(replayed.Body)
			if err != nil || calls != 2 || replayed.StatusCode != http.StatusOK || string(replayedBody) != preflightResponse {
				t.Fatalf("replay: calls=%d status=%d body=%s err=%v", calls, replayed.StatusCode, replayedBody, err)
			}
		})
	}
}
