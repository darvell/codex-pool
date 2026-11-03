package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestCodexProviderAddsCLIFingerprintHeadersAndCookies(t *testing.T) {
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
	req.Header.Set("sec-fetch-site", "cross-site")
	req.Header.Set("sec-ch-ua", `"Chromium";v="144"`)
	req.Header.Set("Accept-Language", "fr")
	NewCodexProvider(nil, nil, nil).SetAuthHeaders(req, acc)

	checks := map[string]string{
		"Authorization":                     "Bearer tok",
		"ChatGPT-Account-ID":                "acct_123",
		"originator":                        "codex_cli_rs",
		"x-openai-internal-codex-residency": "us",
		"OpenAI-Beta":                       "responses_websockets=2026-02-06",
	}
	for key, want := range checks {
		if got := req.Header.Get(key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	for _, browserOnly := range []string{"sec-fetch-site", "sec-ch-ua", "Accept-Language"} {
		if got := req.Header.Get(browserOnly); got != "" {
			t.Fatalf("%s = %q, want removed for a CLI identity", browserOnly, got)
		}
	}
	if got := req.Header.Get("x-client-request-id"); got == "" {
		t.Fatalf("x-client-request-id was not set")
	}
	want := "codex_cli_rs/" + currentCodexFingerprint().Version + " ("
	if got := req.Header.Get("User-Agent"); !strings.HasPrefix(got, want) {
		t.Fatalf("User-Agent = %q, want prefix %q", got, want)
	}
	cookie := req.Header.Get("Cookie")
	if !strings.Contains(cookie, "cf_clearance=clear") || !strings.Contains(cookie, "__cf_bm=bm") {
		t.Fatalf("Cookie = %q, want persisted Cloudflare cookies", cookie)
	}
}

func TestCodexCLIUserAgentDefaultShape(t *testing.T) {
	t.Setenv("CODEX_USER_AGENT", "")
	got := codexCLIUserAgent(codexFingerprintState{Version: "0.166.0", Platform: "Ubuntu 24.4.0", Arch: "x86_64", Terminal: "xterm-256color"})
	want := "codex_cli_rs/0.166.0 (Ubuntu 24.4.0; x86_64) xterm-256color"
	if got != want {
		t.Fatalf("User-Agent = %q, want %q", got, want)
	}
}

func TestCodexIdentityNormalizesTUIToCLI(t *testing.T) {
	t.Setenv("CODEX_USER_AGENT", "codex-tui/0.140.2 (Mac OS X 14.0; arm64) iTerm (codex-tui; 0.140.2)")
	got := codexCLIUserAgent(codexFingerprintState{Version: "0.166.0"})
	want := "codex_cli_rs/0.166.0 (Mac OS X 14.0; arm64) iTerm"
	if got != want {
		t.Fatalf("normalized User-Agent = %q, want %q", got, want)
	}
}

func TestCodexIdentityRewritesStaleVersion(t *testing.T) {
	t.Setenv("CODEX_USER_AGENT", "Codex Desktop/26.318.11754 (darwin; arm64)")
	got := codexCLIUserAgent(codexFingerprintState{Version: "0.166.0"})
	want := "codex_cli_rs/0.166.0 (darwin; arm64)"
	if got != want {
		t.Fatalf("canonical User-Agent = %q, want %q", got, want)
	}
}

func TestParseCodexCLIRelease(t *testing.T) {
	cases := map[string]string{
		`{"name":"@openai/codex","version":"0.167.0"}`:         "0.167.0",
		`{"name":"@openai/codex","version":"0.167.0-alpha.3"}`: "",
		`{"version":"26.1027.61615 bad"}`:                      "",
		`not json`:                                             "",
	}
	for body, want := range cases {
		if got := parseCodexCLIRelease([]byte(body)); got != want {
			t.Fatalf("parseCodexCLIRelease(%s) = %q, want %q", body, got, want)
		}
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

func TestCaptureCodexResponseStatePersistsCloudflareCookies(t *testing.T) {
	acc := &Account{Type: AccountTypeCodex, ID: "test", CodexCookies: map[string]string{}}
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("x-codex-turn-state", "turn-1")
	resp.Header.Add("Set-Cookie", "cf_clearance=abc; Path=/; HttpOnly")
	resp.Header.Add("Set-Cookie", "session=skip; Path=/")

	captureCodexResponseState(acc, resp, "test")
	if got := acc.CodexCookies["cf_clearance"]; got != "abc" {
		t.Fatalf("cf_clearance = %q, want abc", got)
	}
	if _, ok := acc.CodexCookies["session"]; ok {
		t.Fatalf("non-Cloudflare session cookie should not be persisted")
	}
}
