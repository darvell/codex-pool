package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestPoolStatsUsesEmptyAccountArrayForFirstAccountSignIn(t *testing.T) {
	handler := &proxyHandler{pool: newPoolState(nil, false)}
	recorder := httptest.NewRecorder()
	handler.handlePoolStats(recorder, httptest.NewRequest("GET", "/api/pool/stats", nil))
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil { t.Fatal(err) }
	if string(payload["accounts"]) != "[]" { t.Fatalf("accounts must be [], got %s", payload["accounts"]) }
}
