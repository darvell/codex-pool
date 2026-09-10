package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestContextStreamedReplay(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "stream-context-secret")
	const session = "123e4567-e89b-12d3-a456-426614174000"
	for _, mode := range []string{"oversized", "chunked"} {
		t.Run(mode, func(t *testing.T) {
			a, b := contextTestAccount("a", "user-a"), contextTestAccount("b", "user-b")
			var s *nativeContext
			calls := 0
			prompt := strings.Repeat("context ", (5<<20)/8)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get("Authorization") != "Bearer "+b.AccessToken {
					t.Error("streamed replay did not use inference account B")
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				input := body["input"].([]any)
				if input[0].(map[string]any)["content"] != prompt {
					t.Error("large prompt changed")
				}
				parts := input[1].(map[string]any)["output"].([]any)
				if parts[0].(map[string]any)["encrypted_content"] != "native-history" {
					t.Errorf("context envelope was not expanded: %v", parts)
				}
				stored, err := s.store.lookup("stream-user", session)
				if err != nil || stored == nil || len(stored.Participants) != 2 {
					t.Errorf("streamed dispatch not durably recorded before send: %v %v", stored, err)
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, preflightResponse)
			}))
			defer upstream.Close()
			s = contextTestService(t, upstream.URL, a, b)
			if err := s.recordDispatch("stream-user", contextInference(session), a, ""); err != nil {
				t.Fatal(err)
			}
			a.Usage.PrimaryUsedPercent = 100
			identity, _, err := contextIdentity(a)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := s.store.pack("stream-user", session, []contextResult{{Account: identity, Value: json.RawMessage(`{"encrypted_output":"native-history"}`)}})
			if err != nil {
				t.Fatal(err)
			}
			h := preflightHandler(upstream.Client().Transport)
			h.pool, h.nativeContext = s.pool, s
			h.cfg.maxSpoolBodyBytes = 16 << 20
			base, _ := url.Parse(upstream.URL)
			h.registry = NewProviderRegistry(NewCodexProvider(base, base, nil), NewClaudeProvider(base), NewGeminiProvider(base, base))
			body := `{"input":[{"role":"user","content":"` + prompt + `"},{"type":"function_call_output","call_id":"context-call","output":[{"type":"encrypted_content","encrypted_content":"` + envelope + `"}]}],"client_metadata":{"session_id":"` + session + `"},"reasoning":{"context":"all_turns"},"model":"gpt-5.5","stream":true}`
			proxy := httptest.NewServer(h)
			defer proxy.Close()
			send := func(body string, wantStatus, wantCalls int) {
				t.Helper()
				req, err := http.NewRequest(http.MethodPost, proxy.URL+"/backend-api/codex/responses", strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				if mode == "chunked" {
					req.ContentLength = -1
				}
				req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("stream-context-secret", "stream-user"))
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
				if calls != wantCalls || resp.StatusCode != wantStatus {
					t.Fatalf("calls=%d status=%d body=%s", calls, resp.StatusCode, data)
				}
				if wantStatus == http.StatusOK && string(data) != preflightResponse {
					t.Fatalf("streamed response changed: %s", data)
				}
				if wantStatus != http.StatusOK && (!json.Valid(data) || strings.Contains(string(data), "native-history")) {
					t.Fatalf("unsafe context error: %s", data)
				}
			}
			send(body, http.StatusOK, 1)
			a.mu.Lock()
			a.Disabled = true
			a.mu.Unlock()
			send(body, http.StatusServiceUnavailable, 1)
			a.mu.Lock()
			a.Disabled = false
			a.mu.Unlock()
			send(strings.Replace(body, envelope, contextEnvelopePrefix+"invalid", 1), http.StatusBadRequest, 1)
			send(body, http.StatusOK, 2)
		})
	}
}
