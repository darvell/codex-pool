package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAntigravityVersionRefreshUsesHubManifestAndCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "electron-builder" {
			t.Fatalf("User-Agent = %q", got)
		}
		_, _ = w.Write([]byte("version: 2.9.4\npath: Antigravity-arm64-mac.zip\n"))
	}))
	defer server.Close()

	state := newAntigravityVersionState("2.2.1", 6*time.Hour)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	if got := state.current(now); got != "2.2.1" {
		t.Fatalf("initial version = %q", got)
	}
	if err := state.refresh(context.Background(), server.Client(), server.URL, now); err != nil {
		t.Fatal(err)
	}
	if got := state.current(now.Add(5 * time.Hour)); got != "2.9.4" {
		t.Fatalf("cached version = %q", got)
	}
	if got := state.current(now.Add(7 * time.Hour)); got != "2.2.1" {
		t.Fatalf("expired version = %q", got)
	}
}

func TestAntigravityVersionRefreshRejectsInvalidManifest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("version: definitely-not-a-version\n"))
	}))
	defer server.Close()
	state := newAntigravityVersionState("2.2.1", 6*time.Hour)
	if err := state.refresh(context.Background(), server.Client(), server.URL, time.Now()); err == nil {
		t.Fatal("refresh accepted invalid version")
	}
}
