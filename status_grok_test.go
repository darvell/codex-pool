package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStatusJSONCountsGrokAccounts(t *testing.T) {
	h := &proxyHandler{
		pool:      newPoolState([]*Account{{ID: "grok", Type: AccountTypeGrok, AccessToken: "token"}}, false),
		startTime: time.Now(),
	}
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()

	h.serveStatusPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var data struct {
		TotalCount int `json:"TotalCount"`
		GrokCount  int `json:"GrokCount"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if data.TotalCount != 1 || data.GrokCount != 1 {
		t.Fatalf("counts = %+v", data)
	}
}
