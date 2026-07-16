package main

import (
	"testing"
	"time"
)

func TestParseGeminiRateLimitResetDelay(t *testing.T) {
	now := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	body := []byte(`{"error":{"message":"Resource exhausted","details":[{"metadata":{"quotaResetDelay":"12.345s"}}]}}`)
	reset, ok := parseGeminiRateLimitReset(body, now)
	if !ok || !reset.Equal(now.Add(13*time.Second)) {
		t.Fatalf("reset = %v, ok = %v", reset, ok)
	}
}

func TestParseGeminiRateLimitRetryText(t *testing.T) {
	now := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	reset, ok := parseGeminiRateLimitReset([]byte(`{"error":{"message":"Please retry in 2.1s"}}`), now)
	if !ok || !reset.Equal(now.Add(3*time.Second)) {
		t.Fatalf("reset = %v, ok = %v", reset, ok)
	}
}

func TestParseGeminiDailyLimitUsesPacificMidnight(t *testing.T) {
	now := time.Date(2026, 7, 15, 6, 30, 0, 0, time.UTC)
	reset, ok := parseGeminiRateLimitReset([]byte(`{"error":{"message":"Requests per day quota exhausted"}}`), now)
	if !ok {
		t.Fatal("expected reset")
	}
	want := time.Date(2026, 7, 15, 7, 0, 0, 0, time.UTC)
	if !reset.Equal(want) {
		t.Fatalf("reset = %v, want %v", reset, want)
	}
}
