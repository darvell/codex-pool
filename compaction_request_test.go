package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrepareCompactRequest(t *testing.T) {
	for _, tc := range []struct {
		name, input, metadata string
		count                 int
	}{
		{"append", `[]`, `{"turn_id":"keep"}`, 1},
		{"existing trigger", `[{"type":"compaction_trigger"}]`, `not json`, 1},
		{"nonfinal trigger", `[{"type":"compaction_trigger"},{"role":"user","content":"more"}]`, `[]`, 3},
		{"string input", `"summarize"`, `null`, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var obj map[string]any
			if err := json.Unmarshal([]byte(`{"input":`+tc.input+`}`), &obj); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/responses/compact", nil)
			req.Header.Set("X-Codex-Turn-Metadata", tc.metadata)
			if err := prepareCompactRequest(req, obj); err != nil {
				t.Fatal(err)
			}
			input := obj["input"].([]any)
			if len(input) != tc.count || input[len(input)-1].(map[string]any)["type"] != "compaction_trigger" {
				t.Fatalf("input = %#v", input)
			}
			var metadata map[string]any
			if err := json.Unmarshal([]byte(req.Header.Get("X-Codex-Turn-Metadata")), &metadata); err != nil {
				t.Fatal(err)
			}
			if metadata["request_kind"] != "compaction" || (tc.name == "append" && metadata["turn_id"] != "keep") {
				t.Fatalf("metadata = %#v", metadata)
			}
		})
	}
}

func TestCompactCanonicalMetadata(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/responses/compact", nil)
	req.Header.Set("X-Codex-Turn-Metadata", `{"request_kind":"turn","turn_id":"turn-test"}`)
	obj := map[string]any{"input": []any{}, "client_metadata": map[string]any{"x-codex-turn-metadata": `{"request_kind":"turn","turn_id":"turn-test","history_ingest_requested":true,"tool_namespaces_info":{"notes":{}}}`}}
	if err := prepareCompactRequest(req, obj); err != nil {
		t.Fatal(err)
	}
	metadata := obj["client_metadata"].(map[string]any)
	var turn map[string]any
	if err := json.Unmarshal([]byte(metadata["x-codex-turn-metadata"].(string)), &turn); err != nil {
		t.Fatal(err)
	}
	if turn["request_kind"] != "compaction" || turn["history_ingest_requested"] != true || turn["tool_namespaces_info"] == nil {
		t.Fatalf("canonical compact metadata = %#v", turn)
	}
	if strings.Contains(req.Header.Get("X-Codex-Turn-Metadata"), "tool_namespaces_info") {
		t.Fatal("unbounded namespace inventory copied into compatibility header")
	}
}

func TestCompactInvalidRequest(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "compact-invalid-secret")
	token := generateClaudePoolToken("compact-invalid-secret", "compact-user")
	for _, body := range []string{`null`, `[]`, `{`, `{}`, `{"input":null}`, `{"input":42}`} {
		t.Run(body, func(t *testing.T) {
			h := preflightHandler(roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("invalid compact request reached upstream")
				return nil, nil
			}))
			req := httptest.NewRequest(http.MethodPost, "/v1/responses/compact", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			rr := httptest.NewRecorder()
			h.proxyRequest(rr, req, "invalid-compact")
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestCompactSessionAffinity(t *testing.T) {
	const session = "123e4567-e89b-12d3-a456-426614174000"
	body := []byte(`{"client_metadata":{"session_id":"` + session + `"},"reasoning":{"context":"all_turns"}}`)
	if got := extractConversationIDFromJSON(body); got != session {
		t.Fatalf("conversation ID = %q, want client_metadata.session_id", got)
	}
}
