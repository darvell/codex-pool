package main

import (
	"net/http/httptest"
	"testing"
)

func TestMetricsServe(t *testing.T) {
	m := newMetrics()
	m.inc("200", "acct1")
	m.inc("429", "acct1")
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.serve(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if len(body) == 0 {
		t.Fatalf("expected metrics output")
	}
}
