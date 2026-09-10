package main

import (
	"bytes"
	"compress/gzip"
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
	"sync"
	"testing"
	"time"
)

const contextProxySession = "123e4567-e89b-12d3-a456-426614174000"

func contextProxyFixture(t *testing.T, upstream string, accounts ...*Account) (*proxyHandler, *httptest.Server) {
	t.Helper()
	h := preflightHandler(http.DefaultTransport)
	h.cfg.disableRefresh = true
	h.nativeContext = contextTestService(t, upstream+"/backend-api/codex", accounts...)
	h.pool = h.nativeContext.pool
	base, _ := url.Parse(upstream + "/backend-api/codex")
	wham, _ := url.Parse(upstream + "/backend-api")
	h.registry = NewProviderRegistry(NewCodexProvider(base, wham, nil), NewClaudeProvider(base), NewGeminiProvider(base, base))
	proxy := httptest.NewServer(h)
	t.Cleanup(proxy.Close)
	return h, proxy
}

func contextProxyCall(t *testing.T, proxy *httptest.Server, method, path, principal string, body []byte, headers http.Header) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, proxy.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header = headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	if principal != "" {
		req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("context-proxy-secret", principal))
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func assertContextParticipant(t *testing.T, h *proxyHandler, alias string) {
	t.Helper()
	stored, err := h.nativeContext.store.lookup("context-user", contextProxySession)
	if err != nil || stored == nil {
		t.Errorf("dispatch preceded durable context session: %v", err)
		return
	}
	for _, participant := range stored.Participants {
		if participant.Alias == alias {
			return
		}
	}
	t.Errorf("dispatch preceded participant registration: %s", alias)
}

func contextProxyInference(token string) []byte {
	obj := contextInference(contextProxySession)
	obj["model"] = "gpt-5.5"
	obj["stream"] = true
	obj["input"] = []any{map[string]any{"role": "user", "content": "continue"}}
	if token != "" {
		obj["input"] = []any{map[string]any{"type": "function_call_output", "call_id": "context-call", "output": []any{map[string]any{"type": "encrypted_content", "encrypted_content": token}}}}
	}
	body, _ := json.Marshal(obj)
	return body
}

func TestNativeContextHTTPRoundTrip(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "context-proxy-secret")
	a, b := contextTestAccount("a", "user-a"), contextTestAccount("b", "user-b")
	var mu sync.Mutex
	var calls []string
	var inferenceBodies [][]byte
	var h *proxyHandler
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alias := "a"
		if r.Header.Get("Authorization") == "Bearer "+b.AccessToken {
			alias = "b"
		} else if r.Header.Get("Authorization") != "Bearer "+a.AccessToken {
			t.Error("wrong upstream credential")
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, alias+":"+r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/responses") {
			inferenceBodies = append(inferenceBodies, body)
		}
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/responses") {
			assertContextParticipant(t, h, alias)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, preflightResponse)
			return
		}
		if r.Header.Get("X-Codex-Truncation-Mode") != "disabled" || r.Header.Get("X-Codex-Encrypted-Tool-Args") != "true" {
			t.Error("native request headers lost")
		}
		if !bytes.Contains(body, []byte(`"encrypted_args":"opaque"`)) {
			t.Error("native args changed")
		}
		_, _ = io.WriteString(w, `{"encrypted_output":"native-`+alias+`"}`)
	}))
	defer upstream.Close()
	h, proxy := contextProxyFixture(t, upstream.URL, a, b)
	// Stick only inference to A, then B; native notes must remain owned by A.
	h.pool.pin(contextProxySession, a.ID)
	inferenceHeaders := http.Header{"Conversation_id": {"context-conversation"}}
	status, body := contextProxyCall(t, proxy, http.MethodPost, "/v1/responses", "context-user", contextProxyInference(""), inferenceHeaders)
	if status != http.StatusOK {
		t.Fatalf("first inference %d %s", status, body)
	}
	a.mu.Lock()
	a.RateLimitUntil = time.Now().Add(time.Hour)
	a.mu.Unlock()
	h.pool.pin(contextProxySession, b.ID)
	status, body = contextProxyCall(t, proxy, http.MethodPost, "/backend-api/codex/responses", "context-user", contextProxyInference(""), inferenceHeaders)
	if status != http.StatusOK {
		t.Fatalf("second inference %d %s", status, body)
	}
	nativeBody := []byte(`{"context":{"session_id":"` + contextProxySession + `","current_agent_name":"/root"},"encrypted_args":"opaque"}`)
	headers := http.Header{"X-Codex-Truncation-Mode": {"disabled"}, "X-Codex-Encrypted-Tool-Args": {"true"}}
	for _, path := range []string{"/alpha/notes/v2/read_file", "/v1/alpha/history/v2/list_items"} {
		status, body = contextProxyCall(t, proxy, http.MethodPost, path, "context-user", nativeBody, headers)
		if status != http.StatusOK {
			t.Fatalf("native request %d %s", status, body)
		}
		var envelope map[string]string
		if json.Unmarshal(body, &envelope) != nil || !strings.HasPrefix(envelope["encrypted_output"], contextEnvelopePrefix) {
			t.Fatalf("missing envelope %s", body)
		}
		status, body = contextProxyCall(t, proxy, http.MethodPost, "/v1/responses", "context-user", contextProxyInference(envelope["encrypted_output"]), inferenceHeaders)
		if status != http.StatusOK {
			t.Fatalf("replay %d %s", status, body)
		}
		mu.Lock()
		got := string(inferenceBodies[len(inferenceBodies)-1])
		mu.Unlock()
		if strings.Contains(got, contextEnvelopePrefix) || !strings.Contains(got, "native-a") || !strings.Contains(got, contextProxySession) {
			t.Fatalf("replay or metadata lost: %s", got)
		}
		if strings.Contains(path, "/history/") && !strings.Contains(got, "native-b") {
			t.Fatalf("second participant missing: %s", got)
		}
		status, body = contextProxyCall(t, proxy, http.MethodPost, "/v1/responses", "foreign-user", contextProxyInference(envelope["encrypted_output"]), inferenceHeaders)
		if status != http.StatusBadRequest || bytes.Contains(body, []byte("native-a")) {
			t.Fatalf("foreign replay %d %s", status, body)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	var notes, history []string
	for _, call := range calls {
		if strings.Contains(call, "/notes/") {
			notes = append(notes, call)
		}
		if strings.Contains(call, "/history/") {
			history = append(history, call)
		}
	}
	if len(inferenceBodies) != 4 || len(notes) != 1 || !strings.HasPrefix(notes[0], "a:") || len(history) != 2 {
		t.Fatalf("dispatches=%v inference=%d", calls, len(inferenceBodies))
	}
}

func TestNativeContextPassthrough(t *testing.T) {
	const credential = "sk-proj-context-passthrough-test"
	body := []byte(`{"context":{"session_id":"` + contextProxySession + `","current_agent_name":"/root"},"query":"opaque"}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/backend-api/codex/alpha/history/v2/search_contents" {
			t.Errorf("native passthrough path=%s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+credential || r.Header.Get("ChatGPT-Account-ID") != "supplied-workspace" {
			t.Error("supplied credentials replaced")
		}
		got, _ := io.ReadAll(r.Body)
		if !bytes.Equal(got, body) || r.Header.Get("X-Openai-Encrypted-Tool-Arguments") != "true" {
			t.Error("native arguments or headers changed")
		}
		_, _ = io.WriteString(w, `{"encrypted_output":"native-result"}`)
	}))
	defer upstream.Close()
	h, proxy := contextProxyFixture(t, upstream.URL, contextTestAccount("pool", "pool-user"))
	for _, prefix := range []string{"", "/v1", "/backend-api/codex", "/api/codex"} {
		headers := http.Header{"Authorization": {"Bearer " + credential}, "Chatgpt-Account-Id": {"supplied-workspace"}, "X-Openai-Encrypted-Tool-Arguments": {"true"}}
		status, got := contextProxyCall(t, proxy, http.MethodPost, prefix+"/alpha/history/v2/search_contents", "", body, headers)
		if status != http.StatusOK || string(got) != `{"encrypted_output":"native-result"}` {
			t.Fatalf("passthrough status=%d body=%s", status, got)
		}
	}
	stored, err := h.nativeContext.store.lookup("supplied-user", contextProxySession)
	if err != nil || stored != nil {
		t.Fatalf("passthrough acquired pooled ownership: %v %v", stored, err)
	}
}

func TestNativeContextHTTPGuards(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "context-proxy-secret")
	var mu sync.Mutex
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		http.Error(w, "private upstream body", http.StatusBadGateway)
	}))
	defer upstream.Close()
	_, proxy := contextProxyFixture(t, upstream.URL, contextTestAccount("a", "user-a"))
	body := []byte(`{"context":{"session_id":"` + contextProxySession + `","current_agent_name":"/root"}}`)
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, _ = zw.Write(bytes.Repeat([]byte("x"), contextRequestLimit+1))
	_ = zw.Close()
	for _, tc := range []struct {
		name, method, path, principal string
		body                          []byte
		headers                       http.Header
		status                        int
	}{
		{"unauthenticated", http.MethodPost, "/alpha/notes/v2/read_file", "", body, nil, http.StatusUnauthorized},
		{"method", http.MethodGet, "/alpha/notes/v2/read_file", "context-user", body, nil, http.StatusMethodNotAllowed},
		{"unknown", http.MethodPost, "/alpha/history/v2/not-real", "context-user", body, nil, http.StatusNotFound},
		{"namespace root", http.MethodPost, "/alpha/history", "context-user", body, nil, http.StatusNotFound},
		{"trailing slash", http.MethodPost, "/alpha/notes/v2/read_file/", "context-user", body, nil, http.StatusNotFound},
		{"invalid session", http.MethodPost, "/alpha/notes/v2/read_file", "context-user", []byte(`{}`), nil, http.StatusBadRequest},
		{"wire limit", http.MethodPost, "/alpha/notes/v2/read_file", "context-user", bytes.Repeat([]byte("x"), contextRequestLimit+1), nil, http.StatusBadRequest},
		{"decoded limit", http.MethodPost, "/alpha/notes/v2/read_file", "context-user", compressed.Bytes(), http.Header{"Content-Encoding": {"gzip"}}, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, data := contextProxyCall(t, proxy, tc.method, tc.path, tc.principal, tc.body, tc.headers)
			if status != tc.status {
				t.Fatalf("status=%d body=%s", status, data)
			}
			if !json.Valid(data) {
				t.Fatalf("non-JSON error: %s", data)
			}
		})
	}
	mu.Lock()
	before := calls
	mu.Unlock()
	if before != 0 {
		t.Fatalf("guard sent %d upstream requests", before)
	}
	status, data := contextProxyCall(t, proxy, http.MethodPost, "/alpha/notes/v2/read_file", "context-user", body, nil)
	if status != http.StatusServiceUnavailable || bytes.Contains(data, []byte("private upstream")) {
		t.Fatalf("unsafe failure %d %s", status, data)
	}
}

func TestNativeContextHTTPRefresh(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "context-proxy-secret")
	for _, changedIdentity := range []bool{false, true} {
		name := "same identity"
		if changedIdentity {
			name = "changed identity"
		}
		t.Run(name, func(t *testing.T) {
			a, b := contextTestAccount("a", "user-a"), contextTestAccount("b", "user-b")
			a.RefreshToken = "refresh-test"
			a.File = filepath.Join(t.TempDir(), "account.json")
			if err := os.WriteFile(a.File, []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}
			originalToken := a.AccessToken
			refreshedToken := originalToken + "-refreshed"
			if changedIdentity {
				refreshedToken = contextTestAccount("a", "new-user").AccessToken
			}
			var mu sync.Mutex
			inferenceCalls, refreshCalls := 0, 0
			var h *proxyHandler
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth/token" {
					mu.Lock()
					refreshCalls++
					mu.Unlock()
					_ = json.NewEncoder(w).Encode(map[string]string{"access_token": refreshedToken})
					return
				}
				if !strings.HasSuffix(r.URL.Path, "/responses") {
					_, _ = io.WriteString(w, `{"encrypted_output":"native-a"}`)
					return
				}
				mu.Lock()
				inferenceCalls++
				count := inferenceCalls
				mu.Unlock()
				assertContextParticipant(t, h, "a")
				data, _ := io.ReadAll(r.Body)
				if !bytes.Contains(data, []byte("native-a")) || bytes.Contains(data, []byte(contextEnvelopePrefix)) {
					t.Errorf("invalid retry body %s", data)
				}
				if count == 1 {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = io.WriteString(w, `{"error":{"message":"expired"}}`)
					return
				}
				if r.Header.Get("Authorization") != "Bearer "+refreshedToken {
					t.Error("retry did not use refreshed snapshot")
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, preflightResponse)
			}))
			defer upstream.Close()
			h, proxy := contextProxyFixture(t, upstream.URL, a, b)
			h.cfg.disableRefresh = false
			h.cfg.maxAttempts = 2
			h.refreshTransport = http.DefaultTransport
			base, _ := url.Parse(upstream.URL + "/backend-api/codex")
			wham, _ := url.Parse(upstream.URL + "/backend-api")
			refresh, _ := url.Parse(upstream.URL)
			h.registry = NewProviderRegistry(NewCodexProvider(base, wham, refresh), NewClaudeProvider(base), NewGeminiProvider(base, base))
			h.pool.pin(contextProxySession, a.ID)
			nativeBody := []byte(`{"context":{"session_id":"` + contextProxySession + `","current_agent_name":"/root"}}`)
			status, data := contextProxyCall(t, proxy, http.MethodPost, "/alpha/notes/v2/read_file", "context-user", nativeBody, nil)
			if status != http.StatusOK {
				t.Fatalf("notes %d %s", status, data)
			}
			var envelope map[string]string
			_ = json.Unmarshal(data, &envelope)
			status, data = contextProxyCall(t, proxy, http.MethodPost, "/v1/responses", "context-user", contextProxyInference(envelope["encrypted_output"]), nil)
			wantStatus, wantCalls := http.StatusOK, 2
			if changedIdentity {
				wantStatus, wantCalls = http.StatusServiceUnavailable, 1
			}
			mu.Lock()
			defer mu.Unlock()
			if status != wantStatus || inferenceCalls != wantCalls || refreshCalls != 1 {
				t.Fatalf("status=%d inference=%d refresh=%d body=%s", status, inferenceCalls, refreshCalls, data)
			}
		})
	}
}

func TestNativeContextRefreshWait(t *testing.T) {
	a := contextTestAccount("a", "user-a")
	pending := &refreshCall{done: make(chan struct{})}
	h := &proxyHandler{refreshCalls: map[string]*refreshCall{string(a.Type) + ":" + a.ID: pending}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := make(chan error, 1)
	go func() { result <- h.refreshAccount(ctx, a) }()
	select {
	case err := <-result:
		close(pending.done)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("refresh wait returned %v", err)
		}
	case <-time.After(time.Second):
		close(pending.done)
		<-result
		t.Fatal("cancelled context remained blocked behind shared refresh")
	}
}

func TestNativeContextHTTPInvalidSession(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "context-proxy-secret")
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, preflightResponse)
	}))
	defer upstream.Close()
	h := preflightHandler(upstream.Client().Transport)
	base, _ := url.Parse(upstream.URL)
	h.registry = NewProviderRegistry(NewCodexProvider(base, base, nil), NewClaudeProvider(base), NewGeminiProvider(base, base))
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-5.5","input":[],"reasoning":{"context":"all_turns"}}`))
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("context-proxy-secret", "context-user"))
	rr := httptest.NewRecorder()
	h.proxyRequest(rr, req, "context-invalid")
	if rr.Code != http.StatusBadRequest || calls != 0 {
		t.Fatalf("status=%d calls=%d body=%s", rr.Code, calls, rr.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(contextProxyInference("")))
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("context-proxy-secret", "context-user"))
	rr = httptest.NewRecorder()
	h.proxyRequest(rr, req, "context-missing-store")
	if rr.Code != http.StatusServiceUnavailable || calls != 0 {
		t.Fatalf("missing store fell back: status=%d calls=%d body=%s", rr.Code, calls, rr.Body.String())
	}
}
