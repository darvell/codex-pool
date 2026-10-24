package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func proTestHandler(t *testing.T, upstream http.HandlerFunc) *chatGPTFixture {
	t.Helper()
	f := chatGPTTest(t, upstream)
	base, _ := url.Parse(f.upstream.URL + "/backend-api")
	provider := NewCodexProvider(base, base, base)
	f.h.registry = &ProviderRegistry{byType: map[AccountType]Provider{AccountTypeCodex: provider}}
	f.h.transport = f.upstream.Client().Transport
	f.h.store = testUsageStore(t)
	return f
}

func TestProFixedAccountAndOwnership(t *testing.T) {
	calls := 0
	f := proTestHandler(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer provider-secret" || r.Header.Get("ChatGPT-Account-ID") != "real-account" {
			t.Error("account changed")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	})
	client, err := f.h.proAccount("desktop", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.json(context.Background(), "f/conversation/prepare", map[string]any{"model": "gpt-6-pro"})
	if err != nil || result["ok"] != true {
		t.Fatalf("fixed request failed: %v", err)
	}
	f.account.mu.Lock()
	f.account.Dead = true
	f.account.mu.Unlock()
	if _, err := client.json(context.Background(), "f/conversation/resume", map[string]any{}); err == nil || calls != 1 {
		t.Fatal("unavailable account did not fail closed")
	}
	record := chatGPTProRecord{Principal: "desktop", Alias: "cont", Identity: client.identity, Input: []any{map[string]any{"role": "user", "content": "test"}}, Created: time.Now()}
	if err := f.h.saveProRecord("desktop", "resp_test", record); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.readProRecord("other", "resp_test"); err == nil {
		t.Fatal("another principal read response history")
	}
	if got, err := f.h.readProRecord("desktop", "resp_test"); err != nil || got.Alias != "cont" {
		t.Fatalf("owner lost response: %v", err)
	}
}

func TestProSessionCookies(t *testing.T) {
	var calls atomic.Int64
	f := proTestHandler(t, func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("__cf_bm")
		switch calls.Add(1) {
		case 1:
			if err != nil || cookie.Value != "saved-cookie" {
				t.Error("saved cookie missing")
			}
			w.Header().Add("Set-Cookie", "__cf_bm=test-session-cookie; Path=/; Secure; HttpOnly")
			io.WriteString(w, `{"prepare_token":"test-prepare"}`)
		case 2:
			if err != nil || cookie.Value != "test-session-cookie" || len(r.Cookies()) != 1 {
				t.Error("updated cookie missing or duplicated")
			}
			w.Header().Add("Set-Cookie", "__cf_bm=; Path=/; Max-Age=0; Secure; HttpOnly")
			io.WriteString(w, `{"token":"test-final"}`)
		case 3:
			if err == nil {
				t.Error("deleted cookie resurrected from saved account")
			}
			io.WriteString(w, `{"ok":true}`)
		case 4:
			if err != nil || cookie.Value != "saved-cookie" {
				t.Error("session cookies leaked to another principal")
			}
			io.WriteString(w, `{"ok":true}`)
		default:
			t.Error("unexpected session request")
		}
	})
	f.account.CodexCookies = map[string]string{"__cf_bm": "saved-cookie"}
	client, err := f.h.proAccount("desktop", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.json(context.Background(), "sentinel/chat-requirements/prepare", map[string]any{"p": "test-key"}); err != nil {
		t.Fatal(err)
	}
	result, err := client.json(context.Background(), "sentinel/chat-requirements/finalize", map[string]any{"prepare_token": "test-prepare"})
	if err != nil || result["token"] != "test-final" {
		t.Fatalf("upstream session state lost: %v", err)
	}
	if _, err := client.json(context.Background(), "f/conversation", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	other, err := f.h.proAccount("other", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.json(context.Background(), "models", nil); err != nil {
		t.Fatal(err)
	}
	if f.account.CodexCookies["__cf_bm"] != "saved-cookie" {
		t.Fatal("per-request cookie state persisted to shared account")
	}
}

func TestProActivityRestriction(t *testing.T) {
	var calls atomic.Int64
	f := proTestHandler(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"detail":"Unusual activity has been detected from your device. Try again later. (test-request-id)","private":"provider-secret"}`)
	})
	client, err := f.h.proAccount("desktop", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.json(context.Background(), "f/conversation", map[string]any{})
	if !errors.Is(err, errProActivityRestricted) {
		t.Fatalf("activity restriction was masked: %v", err)
	}
	if calls.Load() != 1 || strings.Contains(err.Error(), "provider-secret") || strings.Contains(err.Error(), "test-request-id") {
		t.Fatal("restriction retried or raw response leaked")
	}
	r := httptest.NewRequest(http.MethodPost, "/backend-api/codex/responses", nil)
	r.Header.Set("Authorization", "Bearer "+f.ownerToken)
	w := httptest.NewRecorder()
	f.h.handleChatGPTPro(w, r, mustJSON(map[string]any{"model": "gpt-6-pro", "input": "test"}), "gpt-6-pro")
	if w.Code != http.StatusForbidden || calls.Load() != 2 || !strings.Contains(w.Body.String(), "ChatGPT restricted this session") {
		t.Fatalf("restriction not surfaced as HTTP 403: %d %s", w.Code, w.Body.String())
	}
}

func TestProChunkedRouting(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		f := proTestHandler(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/backend-api/accounts/check/v4-2023-04-27" {
				t.Errorf("Pro request reached the wrong endpoint %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"detail":"Unusual activity has been detected from your device. Try again later."}`)
		})
		f.h.cfg.maxInMemoryBodyBytes = 1 << 20
		f.h.cfg.maxSpoolBodyBytes = 2 << 20
		body := mustJSON(map[string]any{"model": "gpt-6-pro", "input": "test", "stream": streaming})
		r := httptest.NewRequest(http.MethodPost, "/backend-api/codex/responses", strings.NewReader(string(body)))
		r.ContentLength = -1
		r.Header.Set("Authorization", "Bearer "+f.ownerToken)
		w := httptest.NewRecorder()
		f.h.proxyRequest(w, r, "chunked-pro")
		if w.Code != http.StatusForbidden || f.calls.Load() != 1 || !strings.Contains(w.Body.String(), "ChatGPT restricted this session") {
			t.Fatalf("chunked Pro request bypassed adapter (stream=%v): %d %s", streaming, w.Code, w.Body.String())
		}
	}
}

func TestProSpooledSizeLimit(t *testing.T) {
	f := proTestHandler(t, func(w http.ResponseWriter, r *http.Request) { t.Error("oversized Pro request reached upstream") })
	f.h.cfg.maxInMemoryBodyBytes = 32
	f.h.cfg.maxSpoolBodyBytes = 1 << 20
	body := `{"model":"gpt-6-pro","input":"test","stream":true}`
	r := httptest.NewRequest(http.MethodPost, "/backend-api/codex/responses", strings.NewReader(body))
	r.ContentLength = -1
	r.Header.Set("Authorization", "Bearer "+f.ownerToken)
	w := httptest.NewRecorder()
	f.h.proxyRequest(w, r, "oversized-pro")
	if w.Code != http.StatusRequestEntityTooLarge || f.calls.Load() != 0 {
		t.Fatalf("size limit bypassed: %d %s", w.Code, w.Body.String())
	}
}

func TestProSelectionConstraints(t *testing.T) {
	cases := []struct {
		name     string
		change   func(*chatGPTFixture)
		eligible bool
	}{
		{"pro", func(f *chatGPTFixture) { f.account.PlanType = "pro" }, true},
		{"promax", func(f *chatGPTFixture) {}, true},
		{"prolite", func(f *chatGPTFixture) { f.account.PlanType = "prolite" }, false},
		{"plus", func(f *chatGPTFixture) { f.account.PlanType = "plus" }, false},
		{"disabled", func(f *chatGPTFixture) { f.account.Disabled = true }, false},
		{"dead", func(f *chatGPTFixture) { f.account.Dead = true }, false},
		{"cooldown", func(f *chatGPTFixture) { f.account.RateLimitUntil = time.Now().Add(time.Minute) }, false},
		{"source IP", func(f *chatGPTFixture) { f.account.AllowedSourceIPs = []string{"192.0.2.1"} }, false},
		{"reserved", func(f *chatGPTFixture) { f.reserve(t) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := proTestHandler(t, chatGPTMembership)
			tc.change(f)
			if got := f.h.pool.proCandidate("198.51.100.1"); (got != nil) != tc.eligible {
				t.Fatalf("selection eligibility = %v, want %v", got != nil, tc.eligible)
			}
		})
	}
}

func TestProResponsesRestriction(t *testing.T) {
	if os.Getenv("CHATGPT_BROWSER_PATH") == "" {
		t.Skip("set CHATGPT_BROWSER_PATH to exercise the real integrity browser")
	}
	cases := []struct {
		name, rejectedPath string
		stream             bool
	}{
		{"start", "/backend-api/f/conversation", false},
		{"resume", "/backend-api/f/conversation/resume", false},
		{"streamed resume", "/backend-api/f/conversation/resume", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rejected atomic.Int64
			f := proTestHandler(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tc.rejectedPath {
					rejected.Add(1)
					cookie, err := r.Cookie("oai-sc")
					if err != nil || cookie.Value != "test-scope" {
						t.Error("integrity session cookie missing")
					}
					w.WriteHeader(http.StatusForbidden)
					io.WriteString(w, `{"detail":"Unusual activity has been detected from your device. Try again later."}`)
					return
				}
				switch r.URL.Path {
				case "/backend-api/accounts/check/v4-2023-04-27":
					chatGPTMembership(w, r)
				case "/backend-api/models":
					io.WriteString(w, `{"models":[{"slug":"gpt-6-pro"}]}`)
				case "/backend-api/sentinel/chat-requirements/prepare":
					w.Header().Add("Set-Cookie", "oai-sc=test-scope; Path=/backend-api; Secure; HttpOnly")
					io.WriteString(w, `{"token":"test-integrity"}`)
				case "/backend-api/f/conversation":
					io.WriteString(w, proFrame(proSnapshot("partial", "all", "final", "Partial", "in_progress", false))+proFrame(map[string]any{"type": "stream_handoff", "resume_conversation_token": "test-conduit"})+"data: [DONE]\n\n")
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			r := httptest.NewRequest(http.MethodPost, "/backend-api/codex/responses", nil)
			r.Header.Set("Authorization", "Bearer "+f.ownerToken)
			w := httptest.NewRecorder()
			f.h.handleChatGPTPro(w, r, mustJSON(map[string]any{"model": "gpt-6-pro", "input": "test", "stream": tc.stream}), "gpt-6-pro")
			if rejected.Load() != 1 || strings.Contains(w.Body.String(), "response.completed") {
				t.Fatal("restricted request retried or falsely completed")
			}
			if tc.stream {
				if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"code":"pro_activity_restricted"`) || !strings.Contains(w.Body.String(), "event: response.failed\n") {
					t.Fatalf("streamed restriction missing: %d %s", w.Code, w.Body.String())
				}
				return
			}
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "ChatGPT restricted this session") {
				t.Fatalf("restriction was presented as retryable: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestProResponsesRoundTrip(t *testing.T) {
	if os.Getenv("CHATGPT_BROWSER_PATH") == "" {
		t.Skip("set CHATGPT_BROWSER_PATH to exercise Responses with the real integrity browser")
	}
	var starts, resumes atomic.Int64
	f := proTestHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer provider-secret" || r.Header.Get("ChatGPT-Account-ID") != "real-account" {
			t.Error("fixed provider identity lost")
		}
		switch r.URL.Path {
		case "/backend-api/accounts/check/v4-2023-04-27":
			chatGPTMembership(w, r)
		case "/backend-api/models":
			io.WriteString(w, `{"models":[{"slug":"gpt-6-pro"}]}`)
		case "/backend-api/sentinel/chat-requirements/prepare":
			io.WriteString(w, `{"token":"test-integrity"}`)
		case "/backend-api/f/conversation":
			if r.Header.Get("OpenAI-Sentinel-Chat-Requirements-Token") != "test-integrity" {
				t.Error("integrity header lost")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			if starts.Add(1) == 1 {
				io.WriteString(w, proFrame(map[string]any{"conversation_id": "conv-1", "resume_conversation_token": "test-conduit"})+proFrame(map[string]any{"type": "stream_handoff"})+"data: [DONE]\n\n")
				return
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			messages, _ := body["messages"].([]any)
			found := false
			for _, raw := range messages {
				message, _ := raw.(map[string]any)
				author, _ := message["author"].(map[string]any)
				if author["role"] != "tool" {
					continue
				}
				content, _ := message["content"].(map[string]any)
				text, _ := content["text"].(string)
				var result map[string]any
				if json.Unmarshal([]byte(text), &result) == nil && result["call_id"] == "test-call" && result["result"] == "verified" && result["tool"] == "handoff" {
					found = true
				}
			}
			if !found {
				t.Error("tool result lost from persisted continuation")
			}
			io.WriteString(w, proFrame(proSnapshot("answer", "all", "final", "verified", "finished_successfully", true))+"data: [DONE]\n\n")
		case "/backend-api/f/conversation/resume":
			resumes.Add(1)
			if r.Header.Get("X-Conduit-Token") != "test-conduit" {
				t.Error("resume token lost")
			}
			io.WriteString(w, proFrame(proSnapshot("test-call", "local.handoff", "commentary", `{"prompt":"test","reason":"verify"}`, "finished_successfully", false))+"data: [DONE]\n\n")
		default:
			t.Errorf("unexpected upstream path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	invoke := func(token string, body map[string]any) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/backend-api/codex/responses", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		if !f.h.handleChatGPTPro(w, r, mustJSON(body), "gpt-6-pro") {
			t.Fatal("Pro request not routed")
		}
		return w
	}
	body := map[string]any{"model": "gpt-6-pro", "input": "test", "tools": proTools(), "stream": false}
	first := invoke(f.ownerToken, body)
	var response map[string]any
	if first.Code != http.StatusOK || json.Unmarshal(first.Body.Bytes(), &response) != nil {
		t.Fatalf("first response: %d %s", first.Code, first.Body.String())
	}
	output, _ := response["output"].([]any)
	if len(output) != 1 || output[0].(map[string]any)["call_id"] != "test-call" || response["status"] != "completed" {
		t.Fatal("function call did not complete")
	}
	body["previous_response_id"] = response["id"]
	body["input"] = []any{map[string]any{"type": "function_call_output", "call_id": "test-call", "output": "verified"}}
	if other := invoke(f.otherToken, body); other.Code != http.StatusNotFound {
		t.Fatal("cross-principal history accepted")
	}
	body["stream"] = true
	second := invoke(f.ownerToken, body)
	if second.Code != http.StatusOK || second.Header().Get("Content-Type") != "text/event-stream" || !strings.Contains(second.Body.String(), "event: response.completed\n") || !strings.Contains(second.Body.String(), `"text":"verified"`) {
		t.Fatalf("streamed continuation failed: %d %s", second.Code, second.Body.String())
	}
	if starts.Load() != 2 || resumes.Load() != 1 {
		t.Fatal("handoff or principal isolation changed request count")
	}
}

func TestProIntegrityBrowser(t *testing.T) {
	if os.Getenv("CHATGPT_BROWSER_PATH") == "" {
		t.Skip("set CHATGPT_BROWSER_PATH to exercise the real integrity browser")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	browser, err := newChatGPTIntegrity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer browser.close()
	key, err := browser.prepare()
	if err != nil || !strings.HasPrefix(key, "gAAAAAC") {
		t.Fatalf("browser preparation failed: %v", err)
	}
	proofs, err := browser.complete(map[string]any{"proofofwork": map[string]any{"required": true, "seed": "test-seed", "difficulty": "f"}})
	if err != nil || !strings.HasPrefix(proofs["proofofwork"], "gAAAAAB") || !strings.HasSuffix(proofs["proofofwork"], "~S") {
		t.Fatalf("browser proof failed: %v", err)
	}
	if _, err := browser.complete(map[string]any{"force_login": true}); err == nil {
		t.Fatal("renewed account authentication ignored")
	}
}

func TestProLiveRoundTrip(t *testing.T) {
	auth := os.Getenv("CHATGPT_PRO_PROBE_AUTH")
	if auth == "" {
		t.Skip("explicit live Pro credential required")
	}
	f := proTestHandler(t, chatGPTMembership)
	base, _ := url.Parse("https://chatgpt.com/backend-api")
	provider := NewCodexProvider(base, base, base)
	account, err := provider.LoadAccount("cont.json", "", []byte(auth))
	if err != nil || account == nil {
		t.Fatal("invalid live account")
	}
	f.h.pool = newPoolState([]*Account{account}, false)
	f.h.chatGPT = nil
	f.h.registry = &ProviderRegistry{byType: map[AccountType]Provider{AccountTypeCodex: provider}}
	transport := &http.Transport{ResponseHeaderTimeout: 30 * time.Second}
	defer transport.CloseIdleConnections()
	liveTransport := newRustlsHybridTransport(transport)
	f.h.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := liveTransport.RoundTrip(r)
		if err != nil {
			return resp, err
		}
		var requestCookies, responseCookies []string
		for _, cookie := range r.Cookies() {
			requestCookies = append(requestCookies, cookie.Name)
		}
		for _, cookie := range resp.Cookies() {
			responseCookies = append(responseCookies, cookie.Name)
		}
		t.Logf("upstream %s: HTTP %d, request cookie names=%v, response cookie names=%v", r.URL.Path, resp.StatusCode, requestCookies, responseCookies)
		return resp, nil
	})
	request := map[string]any{"model": "gpt-6-pro", "instructions": "For this protocol test use pool_probe, then report its result.", "input": "Call pool_probe with value ready.", "tools": []any{map[string]any{"type": "function", "name": "pool_probe", "description": "A harmless protocol verification tool", "parameters": map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "string"}}, "required": []string{"value"}, "additionalProperties": false}}}, "stream": false}
	invoke := func(body map[string]any) map[string]any {
		r := httptest.NewRequest(http.MethodPost, "/backend-api/codex/responses", strings.NewReader(string(mustJSON(body))))
		r.Header.Set("Authorization", "Bearer "+f.ownerToken)
		w := httptest.NewRecorder()
		if !f.h.handleChatGPTPro(w, r, mustJSON(body), "gpt-6-pro") {
			t.Fatal("Pro request not routed")
		}
		if w.Code != http.StatusOK {
			t.Fatalf("live Pro request failed (%d): %s", w.Code, w.Body.String())
		}
		var result map[string]any
		if json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatal("invalid Responses result")
		}
		return result
	}
	first := invoke(request)
	var call map[string]any
	for _, raw := range first["output"].([]any) {
		item := raw.(map[string]any)
		if item["type"] == "function_call" {
			call = item
		}
	}
	if call == nil || call["name"] != "pool_probe" {
		t.Fatal("Pro did not emit a genuine function call")
	}
	request["previous_response_id"] = first["id"]
	request["input"] = []any{map[string]any{"type": "function_call_output", "call_id": call["call_id"], "output": "probe-result-verified"}}
	second := invoke(request)
	if second["status"] != "completed" || !strings.Contains(string(mustJSON(second["output"])), "probe-result-verified") {
		t.Fatal("Pro tool result did not round-trip")
	}
}
