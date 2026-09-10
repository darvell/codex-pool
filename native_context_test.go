package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

func contextTestAccount(alias, user string) *Account {
	claims, _ := json.Marshal(map[string]any{"sub": user, "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "workspace", "chatgpt_user_id": user}})
	token := "header." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
	return &Account{Type: AccountTypeCodex, ID: alias, AccessToken: token, AccountID: "workspace", PlanType: "pro"}
}

func contextTestService(t *testing.T, baseURL string, accounts ...*Account) *nativeContext {
	t.Helper()
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "context.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := newNativeContextStore(db)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse(baseURL)
	return &nativeContext{store: store, pool: newPoolState(accounts, false), provider: NewCodexProvider(base, base, nil), transport: http.DefaultTransport}
}

func contextInference(session string) map[string]any {
	return map[string]any{"client_metadata": map[string]any{"session_id": session}, "reasoning": map[string]any{"context": "all_turns"}}
}

func TestContextIngestMetadata(t *testing.T) {
	const session = "123e4567-e89b-12d3-a456-426614174000"
	a := contextTestAccount("a", "user-a")
	s := contextTestService(t, "http://localhost", a)
	obj := map[string]any{"client_metadata": map[string]any{"session_id": session, "x-codex-turn-metadata": `{"session_id":"` + session + `","history_ingest_requested":true,"agent_name":"/root/child"}`}}
	if err := s.recordDispatch("principal", obj, a, ""); err != nil {
		t.Fatal(err)
	}
	stored, err := s.store.lookup("principal", session)
	if err != nil || stored == nil {
		t.Fatalf("non-Lite history dispatch was not recorded: %v", err)
	}
	obj["client_metadata"].(map[string]any)["session_id"] = "223e4567-e89b-12d3-a456-426614174000"
	if err := s.recordDispatch("principal", obj, a, ""); err == nil {
		t.Fatal("conflicting session projections accepted")
	}
}

func TestNativeContextOwnership(t *testing.T) {
	const session = "123e4567-e89b-12d3-a456-426614174000"
	a, b := contextTestAccount("a", "user-a"), contextTestAccount("b", "user-b")
	var mu sync.Mutex
	var called []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		called = append(called, r.Header.Get("Authorization"))
		mu.Unlock()
		if r.URL.Path != "/alpha/notes/v2/read_file" && r.URL.Path != "/alpha/history/v2/list_items" {
			t.Errorf("path=%s", r.URL.Path)
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request["encrypted_args"] != "opaque-args" || r.Header.Get("X-Codex-Turn-State") != "turn-state" {
			t.Error("native arguments/headers lost")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"encrypted_output": "native-" + r.Header.Get("Authorization")})
	}))
	defer upstream.Close()
	s := contextTestService(t, upstream.URL, a, b)
	for _, acc := range []*Account{a, b} {
		if err := s.recordDispatch("principal", contextInference(session), acc, ""); err != nil {
			t.Fatal(err)
		}
	}
	a.RateLimitUntil = time.Now().Add(time.Hour)
	a.Usage.PrimaryUsedPercent = 100
	headers := http.Header{"X-Codex-Turn-State": {"turn-state"}}
	request := []byte(`{"context":{"session_id":"` + session + `","current_agent_name":"/root"},"encrypted_args":"opaque-args"}`)
	for _, path := range []string{"/alpha/notes/v2/read_file", "/alpha/history/v2/list_items"} {
		called = nil
		result, err := s.relay(context.Background(), "principal", "", path, headers, request)
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]any
		_ = json.Unmarshal(result, &obj)
		envelope, _ := obj["encrypted_output"].(string)
		body := contextInference(session)
		body["input"] = []any{map[string]any{"type": "function_call_output", "call_id": "call-context", "output": []any{map[string]any{"type": "encrypted_content", "encrypted_content": envelope}}}}
		changed, err := s.expand("principal", "", body)
		if err != nil || !changed {
			t.Fatalf("expand=%v err=%v", changed, err)
		}
		wantCalls := 1
		if strings.Contains(path, "/history/") {
			wantCalls = 2
		}
		if len(called) != wantCalls || (wantCalls == 1 && called[0] != "Bearer "+a.AccessToken) {
			t.Fatalf("context called wrong accounts: %v", called)
		}
		output, _ := json.Marshal(body["input"])
		if !strings.Contains(string(output), "native-Bearer "+a.AccessToken) || strings.Contains(string(output), "codex-pool-context-v1:") {
			t.Fatalf("native context not restored: %s", output)
		}
		if wantCalls == 2 && !strings.Contains(string(output), "native-Bearer "+b.AccessToken) {
			t.Fatalf("second history partition missing: %s", output)
		}
		if a.Penalty != 0 || a.Usage.PrimaryUsedPercent != 100 {
			t.Fatal("context changed inference health")
		}
	}
}

func TestContextPrincipalIsolation(t *testing.T) {
	const session = "123e4567-e89b-12d3-a456-426614174000"
	a := contextTestAccount("shared", "shared-user")
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = io.WriteString(w, `{"encrypted_output":"private-notes"}`)
	}))
	defer upstream.Close()
	s := contextTestService(t, upstream.URL, a)
	if err := s.recordDispatch("owner", contextInference(session), a, ""); err != nil {
		t.Fatal(err)
	}
	request := []byte(`{"context":{"session_id":"` + session + `","current_agent_name":"/root"},"path":"notes"}`)
	if _, err := s.relay(context.Background(), "other-principal", "", "/alpha/notes/v2/read_file", nil, request); err == nil || calls != 0 {
		t.Fatalf("shared-account notes crossed principal boundary: calls=%d err=%v", calls, err)
	}
}

func TestNativeContextRefresh(t *testing.T) {
	const session = "123e4567-e89b-12d3-a456-426614174000"
	for _, mode := range []string{"same identity", "changed identity", "ambiguous write"} {
		t.Run(mode, func(t *testing.T) {
			a := contextTestAccount("a", "user-a")
			calls, refreshes := 0, 0
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if mode == "ambiguous write" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				if calls == 1 {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				_, _ = io.WriteString(w, `{"encrypted_output":"written"}`)
			}))
			defer upstream.Close()
			s := contextTestService(t, upstream.URL, a)
			s.refresh = func(ctx context.Context, acc *Account) error {
				refreshes++
				acc.mu.Lock()
				defer acc.mu.Unlock()
				if mode == "changed identity" {
					acc.AccessToken = contextTestAccount("a", "new-user").AccessToken
				}
				return nil
			}
			request := []byte(`{"context":{"session_id":"` + session + `","current_agent_name":"/root"},"text":"opaque","path":"notes"}`)
			_, err := s.relay(context.Background(), "principal", "", "/alpha/notes/v2/append_to_file", nil, request)
			if mode == "same identity" {
				if err != nil || calls != 2 || refreshes != 1 {
					t.Fatalf("same owner refresh: calls=%d refreshes=%d err=%v", calls, refreshes, err)
				}
				return
			}
			if err == nil || calls != 1 {
				t.Fatalf("unsafe write retry: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestContextMalformedImages(t *testing.T) {
	const session = "123e4567-e89b-12d3-a456-426614174000"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"encrypted_output":"opaque","images":[{"data":"aW1hZ2U=","mime_type":"image/png","detail":"invalid"}]}`)
	}))
	defer upstream.Close()
	s := contextTestService(t, upstream.URL, contextTestAccount("a", "user-a"))
	request := []byte(`{"context":{"session_id":"` + session + `","current_agent_name":"/root"},"path":"notes"}`)
	if value, err := s.relay(context.Background(), "principal", "", "/alpha/notes/v2/read_file", nil, request); err == nil || value != nil {
		t.Fatalf("malformed images returned as successful tool output: %s %v", value, err)
	}
}

func TestContextResultShapes(t *testing.T) {
	for _, data := range []string{`[1,2]`, `null`, `{"count":9007199254740993}`, `{"encrypted_output":"opaque","images":[{"data":"aW1hZ2U=","mime_type":"image/png","detail":"original"}]}`} {
		parts, err := contextResultParts(json.RawMessage(data))
		if err != nil || len(parts) == 0 {
			t.Fatalf("result %s: %v", data, err)
		}
		encoded, _ := json.Marshal(parts)
		if strings.Contains(data, "9007199254740993") && !strings.Contains(string(encoded), "9007199254740993") {
			t.Fatal("backend integer precision lost")
		}
		if strings.Contains(data, "images") && (len(parts) != 2 || parts[1].(map[string]any)["image_url"] != "data:image/png;base64,aW1hZ2U=") {
			t.Fatalf("image attachment lost: %s", encoded)
		}
	}
}

func TestNativeContextFailure(t *testing.T) {
	const session = "123e4567-e89b-12d3-a456-426614174000"
	a, b := contextTestAccount("a", "user-a"), contextTestAccount("b", "user-b")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+b.AccessToken {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, "private upstream failure")
			return
		}
		_, _ = io.WriteString(w, `{"encrypted_output":"native"}`)
	}))
	defer upstream.Close()
	s := contextTestService(t, upstream.URL, a, b)
	for _, acc := range []*Account{a, b} {
		if err := s.recordDispatch("principal", contextInference(session), acc, ""); err != nil {
			t.Fatal(err)
		}
	}
	request := []byte(`{"context":{"session_id":"` + session + `","current_agent_name":"/root/child"},"encrypted_args":"opaque"}`)
	result, err := s.relay(context.Background(), "principal", "", "/alpha/history/v2/list_items", nil, request)
	if err == nil || result != nil || strings.Contains(err.Error(), "private") {
		t.Fatalf("partial history leaked: %s %v", result, err)
	}
	if b.Penalty != 0 || !b.RateLimitUntil.IsZero() {
		t.Fatal("history failure changed inference health")
	}
	result, err = s.relay(context.Background(), "principal", "", "/alpha/notes/v2/read_file", nil, request)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	_ = json.Unmarshal(result, &envelope)
	body := contextInference(session)
	body["input"] = []any{map[string]any{"type": "function_call_output", "output": []any{map[string]any{"type": "encrypted_content", "encrypted_content": envelope["encrypted_output"]}}}}
	original, _ := json.Marshal(body)
	a.AccessToken = contextTestAccount("a", "another-user").AccessToken
	if _, err := s.expand("principal", "", body); err == nil {
		t.Fatal("re-login accepted old context")
	}
	after, _ := json.Marshal(body)
	if !reflect.DeepEqual(original, after) {
		t.Fatal("failed expansion mutated request")
	}
	if _, err := s.relay(context.Background(), "principal", "", "/alpha/notes/v2/read_file", nil, request); err == nil {
		t.Fatal("notes silently moved to new identity")
	}
}
