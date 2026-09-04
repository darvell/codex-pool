package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRelayWebSocketRejection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "17")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer upstream.Close()
	base, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/responses", nil)
	w := httptest.NewRecorder()
	result := relayWebSocket(w, r, base, nil, webSocketRelayOptions{ReadLimit: 1024})
	if result.err != nil || result.statusCode != http.StatusTooManyRequests || w.Code != http.StatusTooManyRequests {
		t.Fatalf("relay result=%+v HTTP=%d", result, w.Code)
	}
	if w.Header().Get("Retry-After") != "17" {
		t.Fatalf("Retry-After=%q", w.Header().Get("Retry-After"))
	}
}
