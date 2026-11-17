package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAntigravityReplayRetryCooldown(t *testing.T) {
	for _, mode := range []string{"initial failure", "replay retry"} {
		t.Run(mode, func(t *testing.T) {
			oldCache := antigravityNativeReplay
			antigravityNativeReplay = newAntigravityReplayCache(time.Hour, 10)
			t.Cleanup(func() { antigravityNativeReplay = oldCache })
			account := &Account{Type: AccountTypeAntigravity, ID: "a", AccessToken: "a", ProjectID: "project", File: filepath.Join(t.TempDir(), "antigravity.json")}
			var hosts []string
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				hosts = append(hosts, req.URL.Host)
				if mode == "replay retry" && len(hosts) == 1 {
					return antigravityHTTPResponse(http.StatusBadRequest, `{"error":{"message":"invalid thoughtSignature"}}`), nil
				}
				return antigravityHTTPResponse(http.StatusInternalServerError, `{"error":{"message":"failed"}}`), nil
			})
			h, model := testAntigravityHandler(t, transport, account)
			req, body := antigravityProxyRequest(model)
			if mode == "replay retry" {
				prepared, err := prepareAntigravityRequest(req.URL.Path, body, "antigravity/"+model, "project", "conversation", &h.pool.antigravityModels)
				if err != nil {
					t.Fatal(err)
				}
				scope := antigravityReplayScopeFromBodyForTenant(prepared.Body, "user\x00origin")
				response := []byte(`{"response":{"candidates":[{"content":{"parts":[{"functionCall":{"name":"tool","args":{}},"thoughtSignature":"signed"}]}}]}}`)
				if !antigravityNativeReplay.capture(scope, prepared.Body, response) {
					t.Fatal("failed to seed replay cache")
				}
			}
			recorder := httptest.NewRecorder()
			h.handleAntigravityProxy(recorder, req, body, "antigravity/"+model, "conversation", "user", "origin", "", "request")
			if recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if mode == "initial failure" {
				if strings.Join(hosts, ",") != "daily.test,production.test" || !account.RateLimitUntil.After(time.Now()) || account.BackoffLevel != 1 {
					t.Fatalf("hosts=%v cooldown=%v backoff=%d", hosts, account.RateLimitUntil, account.BackoffLevel)
				}
			} else if strings.Join(hosts, ",") != "daily.test,daily.test,production.test" || !account.RateLimitUntil.IsZero() || account.BackoffLevel != 0 {
				t.Fatalf("hosts=%v cooldown=%v backoff=%d", hosts, account.RateLimitUntil, account.BackoffLevel)
			}
		})
	}
}
