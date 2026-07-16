package main

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAntigravityRequestFallsBackToProductionAfterDailyRateLimit(t *testing.T) {
	daily, _ := url.Parse("https://daily.example")
	production, _ := url.Parse("https://prod.example")
	provider := NewAntigravityProvider(daily, production)
	var hosts []string
	handler := &proxyHandler{transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		hosts = append(hosts, request.URL.Host)
		status := http.StatusTooManyRequests
		body := `{"error":{"message":"rate limited"}}`
		if request.URL.Host == production.Host {
			status = http.StatusOK
			body = `{"ok":true}`
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
	})}

	response, err := handler.doAntigravityRequest(context.Background(), nil, &Account{AccessToken: "token"}, provider, antigravityPreparedRequest{Body: []byte(`{}`), Operation: "streamGenerateContent"})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	if len(hosts) != 2 || hosts[0] != daily.Host || hosts[1] != production.Host {
		t.Fatalf("hosts = %v, want daily then production", hosts)
	}
}

func TestAntigravityRefreshesBeforeTokenExpiry(t *testing.T) {
	handler := &proxyHandler{}
	antigravity := &Account{Type: AccountTypeAntigravity, RefreshToken: "refresh", ExpiresAt: time.Now().Add(49 * time.Minute)}
	if !handler.needsRefresh(antigravity) {
		t.Fatal("Antigravity token inside the 50-minute refresh window should refresh")
	}

	codex := &Account{Type: AccountTypeCodex, RefreshToken: "refresh", ExpiresAt: time.Now().Add(49 * time.Minute)}
	if handler.needsRefresh(codex) {
		t.Fatal("other providers must retain expiry-only refresh behavior")
	}
}

func TestAntigravityTransientRetryClassification(t *testing.T) {
	now := time.Now()
	instant := []byte(`{"error":{"status":"RESOURCE_EXHAUSTED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"RATE_LIMIT_EXCEEDED"},{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"0.5s"}]}}`)
	delay, ok := antigravityInstantRetryDelay(instant, now)
	if !ok || delay < 1300*time.Millisecond || delay > 1400*time.Millisecond {
		t.Fatalf("instant retry = %s, %v", delay, ok)
	}
	long := []byte(`{"error":{"status":"RESOURCE_EXHAUSTED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"RATE_LIMIT_EXCEEDED"},{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"5s"}]}}`)
	if _, ok := antigravityInstantRetryDelay(long, now); ok {
		t.Fatal("five-second rate limit should switch accounts")
	}
	if !antigravityShouldRetryNoCapacity(http.StatusServiceUnavailable, []byte(`{"error":{"message":"No capacity available for model gemini-3.1-flash-image on the server"}}`)) {
		t.Fatal("standard no-capacity response should retry")
	}
	if antigravityShouldRetryNoCapacity(http.StatusBadGateway, []byte(`{"error":{"message":"No capacity available"}}`)) {
		t.Fatal("no-capacity retry must be limited to 503")
	}
}
