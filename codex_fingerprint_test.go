package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestCodexProviderAddsDesktopFingerprintHeadersAndCookies(t *testing.T) {
	acc := &Account{
		Type:         AccountTypeCodex,
		AccessToken:  "tok",
		AccountID:    "acct_123",
		CodexCookies: map[string]string{"cf_clearance": "clear", "__cf_bm": "bm"},
	}
	req, err := http.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	NewCodexProvider(nil, nil, nil).SetAuthHeaders(req, acc)

	checks := map[string]string{
		"Authorization":                     "Bearer tok",
		"ChatGPT-Account-ID":                "acct_123",
		"originator":                        "Codex Desktop",
		"x-openai-internal-codex-residency": "us",
		"OpenAI-Beta":                       "responses_websockets=2026-02-06",
		"sec-fetch-site":                    "same-origin",
		"sec-fetch-mode":                    "cors",
		"sec-fetch-dest":                    "empty",
		"sec-ch-ua-mobile":                  "?0",
	}
	for key, want := range checks {
		if got := req.Header.Get(key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	if got := req.Header.Get("x-client-request-id"); got == "" {
		t.Fatalf("x-client-request-id was not set")
	}
	if got := req.Header.Get("User-Agent"); !strings.HasPrefix(got, "Codex Desktop/") {
		t.Fatalf("User-Agent = %q, want Codex Desktop prefix", got)
	}
	cookie := req.Header.Get("Cookie")
	if !strings.Contains(cookie, "cf_clearance=clear") || !strings.Contains(cookie, "__cf_bm=bm") {
		t.Fatalf("Cookie = %q, want persisted Cloudflare cookies", cookie)
	}
}

func TestCodexProviderPreservesClientRequestID(t *testing.T) {
	acc := &Account{Type: AccountTypeCodex, AccessToken: "tok"}
	req, err := http.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("x-client-request-id", "client-thread-1")

	NewCodexProvider(nil, nil, nil).SetAuthHeaders(req, acc)

	if got := req.Header.Get("x-client-request-id"); got != "client-thread-1" {
		t.Fatalf("x-client-request-id = %q, want client-thread-1", got)
	}
}

func TestCaptureCodexResponseStatePersistsCloudflareCookiesAndTurnState(t *testing.T) {
	acc := &Account{Type: AccountTypeCodex, ID: "test", CodexCookies: map[string]string{}}
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("x-codex-turn-state", "turn-1")
	resp.Header.Add("Set-Cookie", "cf_clearance=abc; Path=/; HttpOnly")
	resp.Header.Add("Set-Cookie", "session=skip; Path=/")

	captureCodexResponseState(acc, resp, "test")
	if acc.CodexTurnState != "turn-1" {
		t.Fatalf("CodexTurnState = %q, want turn-1", acc.CodexTurnState)
	}
	if got := acc.CodexCookies["cf_clearance"]; got != "abc" {
		t.Fatalf("cf_clearance = %q, want abc", got)
	}
	if _, ok := acc.CodexCookies["session"]; ok {
		t.Fatalf("non-Cloudflare session cookie should not be persisted")
	}
}

func TestParseCodexAppcastVersion(t *testing.T) {
	xml := `<rss><channel><item><sparkle:shortVersionString>26.400.1</sparkle:shortVersionString><sparkle:version>1200</sparkle:version></item></channel></rss>`
	version, build := parseCodexAppcastVersion(xml)
	if version != "26.400.1" || build != "1200" {
		t.Fatalf("version=%q build=%q", version, build)
	}
}
