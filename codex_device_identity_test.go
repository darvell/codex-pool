package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestScopeCodexDeviceBodyRewritesIDsPerAccount(t *testing.T) {
	const installation = "5f0c3a52-9d2e-4b8f-a1c7-3e6d9b2f4a10"
	const window = "0193a5e2-7c41-7d2a-9b3e-5f6a7b8c9d0e"
	body := `{"model":"gpt-5.5","client_metadata":{"x-codex-installation-id":"` + installation + `","x-codex-window-id":"` + window + `","x-codex-turn-metadata":"{\"installation_id\":\"` + installation + `\",\"session_id\":\"sess-0001-0002-0003\"}"},"prompt_cache_key":"sess-0001-0002-0003"}`
	a := &Account{Type: AccountTypeCodex, ID: "a", AccountID: "acct_a"}
	b := &Account{Type: AccountTypeCodex, ID: "b", AccountID: "acct_b"}

	outA := string(scopeCodexDeviceBody([]byte(body), a, "alice"))
	outB := string(scopeCodexDeviceBody([]byte(body), b, "alice"))
	if strings.Contains(outA, installation) || strings.Contains(outA, window) {
		t.Fatalf("device ids leaked: %s", outA)
	}
	if outA == outB {
		t.Fatal("two accounts received the same device ids")
	}
	if again := string(scopeCodexDeviceBody([]byte(body), a, "alice")); again != outA {
		t.Fatal("device ids are not stable for one user and account")
	}
	if strings.Count(outA, scopedCodexDeviceID(a, "alice", "installation", installation)) != 2 {
		t.Fatalf("installation id was not rewritten in both places: %s", outA)
	}
	if !strings.Contains(outA, "sess-0001-0002-0003") {
		t.Fatalf("session-bound ids must pass through: %s", outA)
	}
	if !strings.Contains(outA, `"model":"gpt-5.5"`) || len(outA) != len(body) {
		t.Fatalf("body changed beyond the ids: %s", outA)
	}
}

func TestScopedCodexDeviceIDKeepsUUIDShape(t *testing.T) {
	acc := &Account{Type: AccountTypeCodex, ID: "a", AccountID: "acct_a"}
	for _, raw := range []string{"5f0c3a52-9d2e-4b8f-a1c7-3e6d9b2f4a10", "0193a5e2-7c41-7d2a-9b3e-5f6a7b8c9d0e"} {
		original := uuid.MustParse(raw)
		scoped, err := uuid.Parse(scopedCodexDeviceID(acc, "alice", "window", raw))
		if err != nil {
			t.Fatal(err)
		}
		if scoped.Version() != original.Version() || scoped.Variant() != original.Variant() {
			t.Fatalf("%s -> %s changed version or variant", raw, scoped)
		}
		if original.Version() == 7 && string(scoped[:6]) != string(original[:6]) {
			t.Fatalf("v7 timestamp not kept: %s -> %s", raw, scoped)
		}
	}
}

func TestScopeCodexDeviceHeaders(t *testing.T) {
	const installation = "5f0c3a52-9d2e-4b8f-a1c7-3e6d9b2f4a10"
	h := http.Header{}
	h.Set("x-codex-installation-id", installation)
	h.Set("session_id", "5f0c3a52-0000-4b8f-a1c7-3e6d9b2f4a10")
	scopeCodexDeviceHeaders(h, &Account{Type: AccountTypeCodex, ID: "a"}, "alice")
	if h.Get("x-codex-installation-id") == installation {
		t.Fatal("installation header was not scoped")
	}
	if h.Get("session_id") != "5f0c3a52-0000-4b8f-a1c7-3e6d9b2f4a10" {
		t.Fatal("session header must pass through")
	}
}

func TestHTTPResponsesScopeCodexDeviceIdentity(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")
	const installation = "5f0c3a52-9d2e-4b8f-a1c7-3e6d9b2f4a10"

	var gotHeader, gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Codex-Installation-Id")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n"))
	}))
	defer upstream.Close()
	account := &Account{Type: AccountTypeCodex, ID: "codex", AccessToken: "token", PlanType: "pro", AccountID: "acct"}
	proxy := newOverloadFailoverHandler(t, upstream, []*Account{account})

	req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/v1/responses", strings.NewReader(`{"model":"gpt-5.6-sol","stream":true,"input":"hi","client_metadata":{"x-codex-installation-id":"`+installation+`"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("test-secret", "device-user"))
	req.Header.Set("X-Codex-Installation-Id", installation)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if gotHeader == "" || gotHeader == installation {
		t.Fatalf("upstream installation header = %q, want a scoped replacement", gotHeader)
	}
	if strings.Contains(gotBody, installation) || !strings.Contains(gotBody, gotHeader) {
		t.Fatalf("upstream body = %s, want installation id %s", gotBody, gotHeader)
	}
}
