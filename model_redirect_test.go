package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestModelRedirectHTTP(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "redirect-secret")
	token := generateClaudePoolToken("redirect-secret", "redirect-user")
	for _, tc := range []struct {
		name, ip, model, want string
		chunked, large        bool
	}{
		{"matching", "192.0.2.42", "gpt-5.4", "gpt-5.5", false, false},
		{"other origin", "192.0.2.43", "gpt-5.4", "gpt-5.4", false, false},
		{"chunked", "192.0.2.42", "gpt-5.4", "gpt-5.5", true, false},
		{"large", "192.0.2.42", "gpt-5.4", "gpt-5.5", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, gotTier := "", ""
			h := preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}
				var obj map[string]any
				if err := json.Unmarshal(body, &obj); err != nil {
					t.Fatal(err)
				}
				got, _ = obj["model"].(string)
				gotTier, _ = obj["service_tier"].(string)
				return preflightReply(), nil
			}))
			h.cfg.maxSpoolBodyBytes = 1 << 20
			h.modelRedirects = newModelRedirects(map[string]string{"192.0.2.42": "gpt-5.5"})
			h.serviceTierOverride = newModelRedirects(map[string]string{"192.0.2.42": "default"})
			input := "hi"
			if tc.large {
				h.cfg.maxInMemoryBodyBytes = 1024
				input = strings.Repeat("a", 2048)
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"`+tc.model+`","stream":true,"service_tier":"priority","input":"`+input+`"}`))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("CF-Connecting-IP", tc.ip)
			if tc.chunked {
				req.ContentLength = -1
			}
			rec := httptest.NewRecorder()
			h.proxyRequest(rec, req, "redirect-test")
			if got != tc.want {
				t.Fatalf("upstream model = %q, want %q; status=%d body=%s", got, tc.want, rec.Code, rec.Body.String())
			}
			wantTier := "priority"
			if tc.ip == "192.0.2.42" {
				wantTier = "default"
			}
			if gotTier != wantTier {
				t.Fatalf("upstream tier = %q, want %q", gotTier, wantTier)
			}
		})
	}
}

func TestModelRedirectWebSocket(t *testing.T) {
	for _, input := range []string{
		`{"type":"response.create","model":"gpt-6-astra","service_tier":"priority","input":"hi"}`,
		`{"type":"response.create","response":{"model":"gpt-6-astra","service_tier":"ultrafast","input":"hi"}}`,
	} {
		state := &codexRelayState{h: &proxyHandler{modelRedirects: newModelRedirects(map[string]string{"192.0.2.42": "gpt-6.1-sol"}), serviceTierOverride: newModelRedirects(map[string]string{"192.0.2.42": "default"})}, opts: codexCyberSwapOptions{ClientIP: "192.0.2.42"}}
		data, err := state.inspectClient([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		if got := extractCodexWebSocketRequestedModel(data); got != "gpt-6.1-sol" {
			t.Fatalf("model = %q, frame = %s", got, data)
		}
		if got := serviceTierFromJSON(data); got != "default" {
			t.Fatalf("tier = %q, frame = %s", got, data)
		}
	}
}

func TestModelRedirectReload(t *testing.T) {
	r := newModelRedirects(map[string]string{"192.0.2.42": "gpt-5.5"})
	if got := r.modelFor("192.0.2.42"); got != "gpt-5.5" {
		t.Fatal(got)
	}
	r.reload(nil)
	if got := r.modelFor("192.0.2.42"); got != "" {
		t.Fatal(got)
	}
}
