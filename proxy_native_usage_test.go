package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuditNativeUsage(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "audit-secret")
	for _, kind := range []AccountType{AccountTypeClaude, AccountTypeCodex} {
		t.Run(string(kind), func(t *testing.T) {
			store := testUsageStore(t)
			body := `{"model":"gpt-5.4","stream":true,"prompt_cache_key":"audit-session","input":"hi"}`
			path := "/v1/responses"
			response := "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"audit_response\",\"usage\":{\"input_tokens\":7,\"output_tokens\":3}}}\n\n"
			if kind == AccountTypeClaude {
				path = "/v1/messages"
				body = `{"model":"claude-sonnet-4-6","stream":true,"max_tokens":32,"messages":[{"role":"user","content":"hi"}]}`
				response = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":7}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":3}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
			}
			h := preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				_, _ = io.Copy(io.Discard, req.Body)
				_ = req.Body.Close()
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(response))}, nil
			}))
			h.store = store
			h.pool = newPoolState([]*Account{{ID: "audit_account", Type: kind, AccessToken: "sk-ant-api-test", AccountID: "audit_account", CyberAccess: true}}, false)
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("audit-secret", "audit-user"))
			rr := httptest.NewRecorder()
			h.proxyRequest(rr, req, "audit-native-usage")
			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			usage, err := store.loadAccountUsage("audit_account")
			if err != nil {
				t.Fatal(err)
			}
			if usage.RequestCount != 1 || usage.TotalInputTokens != 7 || usage.TotalOutputTokens != 3 {
				t.Fatalf("native stream accounting lost: %+v", usage)
			}
		})
	}
}
