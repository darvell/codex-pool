package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	antigravityFallbackClientVersion = "2.2.1"
	antigravityVersionCacheTTL       = 6 * time.Hour
	antigravityVersionFetchTimeout   = 10 * time.Second
	antigravityVersionManifestURL    = "https://antigravity-hub-auto-updater-974169037036.us-central1.run.app/manifest/latest-arm64-mac.yml"
)

var antigravityManifestVersionPattern = regexp.MustCompile(`(?m)^\s*version:\s*["']?([0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?)`)

type antigravityVersionState struct {
	mu       sync.RWMutex
	fallback string
	ttl      time.Duration
	version  string
	expires  time.Time
}

func newAntigravityVersionState(fallback string, ttl time.Duration) *antigravityVersionState {
	return &antigravityVersionState{fallback: fallback, ttl: ttl}
}

func (s *antigravityVersionState) current(now time.Time) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.version != "" && now.Before(s.expires) {
		return s.version
	}
	return s.fallback
}

func (s *antigravityVersionState) refresh(ctx context.Context, client *http.Client, manifestURL string, now time.Time) error {
	if client == nil {
		return errors.New("Antigravity version refresh requires an HTTP client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "electron-builder")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch Antigravity version manifest: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read Antigravity version manifest: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("fetch Antigravity version manifest: %s", resp.Status)
	}
	match := antigravityManifestVersionPattern.FindSubmatch(body)
	if len(match) != 2 || strings.TrimSpace(string(match[1])) == "" {
		return errors.New("Antigravity version manifest has no valid version")
	}
	s.mu.Lock()
	s.version = strings.TrimSpace(string(match[1]))
	s.expires = now.Add(s.ttl)
	s.mu.Unlock()
	return nil
}

var antigravityVersions = newAntigravityVersionState(antigravityFallbackClientVersion, antigravityVersionCacheTTL)

// startAntigravityVersionUpdater refreshes the Hub version independently from
// requests. The last valid value remains available until its six-hour TTL.
func startAntigravityVersionUpdater(ctx context.Context) {
	client := &http.Client{Timeout: antigravityVersionFetchTimeout}
	go func() {
		refresh := func() {
			_ = antigravityVersions.refresh(ctx, client, antigravityVersionManifestURL, time.Now())
		}
		refresh()
		ticker := time.NewTicker(antigravityVersionCacheTTL / 2)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()
}
