package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Verifies the cap survives the full proxy path and reaches the upstream
// request body, not just the unit-level helper. Uses gpt-5.5 because the test
// pool account is not entitled to discovery-gated models; the cap itself is
// model-independent.
func TestProxyRequestAppliesEffortCap(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "effort-secret")
	const principal = "1f85c8154331cf17"
	token := generateClaudePoolToken("effort-secret", principal)

	for _, tc := range []struct {
		name       string
		capUsers   map[string]string
		model      string
		effort     string
		wantEffort string
	}{
		{
			name:       "capped user xhigh lowered to medium",
			capUsers:   map[string]string{principal: "medium"},
			model:      "gpt-5.5",
			effort:     "xhigh",
			wantEffort: "medium",
		},
		{
			name:       "capped user low left alone",
			capUsers:   map[string]string{principal: "medium"},
			model:      "gpt-5.5",
			effort:     "low",
			wantEffort: "low",
		},
		{
			name:       "uncapped user keeps xhigh",
			capUsers:   map[string]string{"someone-else": "medium"},
			model:      "gpt-5.5",
			effort:     "xhigh",
			wantEffort: "xhigh",
		},
		{
			name:       "model suffix cannot escape the cap",
			capUsers:   map[string]string{principal: "medium"},
			model:      "gpt-5.5-xhigh",
			effort:     "low",
			wantEffort: "medium",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotEffort, gotModel string
			called := false

			h := preflightHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				called = true
				body, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}
				var obj map[string]any
				if err := json.Unmarshal(body, &obj); err != nil {
					t.Fatalf("upstream body not JSON: %v (%s)", err, body)
				}
				gotModel, _ = obj["model"].(string)
				if reasoning, ok := obj["reasoning"].(map[string]any); ok {
					gotEffort, _ = reasoning["effort"].(string)
				}
				return preflightReply(), nil
			}))
			h.effortCap = newEffortCap(tc.capUsers, nil)

			body := `{"model":"` + tc.model + `","stream":true,"reasoning":{"effort":"` + tc.effort + `","summary":"detailed"},"input":"hi"}`
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			h.proxyRequest(httptest.NewRecorder(), req, "effort-cap-test")

			if !called {
				t.Fatal("upstream was never called")
			}
			if gotEffort != tc.wantEffort {
				t.Errorf("upstream effort = %q, want %q", gotEffort, tc.wantEffort)
			}
			if gotModel != "gpt-5.5" {
				t.Errorf("upstream model = %q, want gpt-5.5", gotModel)
			}
		})
	}
}
