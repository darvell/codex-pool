package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func codexFixture(t *testing.T) (*CodexProvider, *Account) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "account.json")
	body := map[string]any{"tokens": map[string]any{
		"access_token":  jwtWithExp(time.Now().Add(time.Hour).Unix()),
		"refresh_token": "fixture-refresh", "account_id": "fixture-seat",
	}, "extra": "preserve"}
	if err := atomicWriteJSON(path, body); err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse("https://fixture.invalid")
	provider := NewCodexProvider(base, base, base)
	return provider, readCodexFixture(t, provider, path)
}

func readCodexFixture(t *testing.T, p *CodexProvider, path string) *Account {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.LoadAccount(filepath.Base(path), path, body)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestCodexMetadataKeepsTokens(t *testing.T) {
	p, stale := codexFixture(t)
	body, _ := os.ReadFile(stale.File)
	var root map[string]any
	_ = json.Unmarshal(body, &root)
	root["tokens"].(map[string]any)["refresh_token"] = "new-fixture-refresh"
	if err := atomicWriteJSON(stale.File, root); err != nil {
		t.Fatal(err)
	}
	stale.CodexCookies = map[string]string{"__cf_bm": "fixture-cookie"}
	_ = saveAccount(stale)
	current := readCodexFixture(t, p, stale.File)
	if current.RefreshToken != "new-fixture-refresh" {
		t.Fatal("stale metadata overwrote newer credentials")
	}
}

func TestCodexFailedRefreshReload(t *testing.T) {
	p, a := codexFixture(t)
	var calls atomic.Int32
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":{"code":"refresh_token_reused"}}`))}, nil
	})
	if err := p.RefreshToken(context.Background(), a, transport); err == nil {
		t.Fatal("expected refresh rejection")
	}
	reloaded := readCodexFixture(t, p, a.File)
	preserveUsageSnapshots([]*Account{a}, []*Account{reloaded})
	if (&proxyHandler{}).needsRefresh(reloaded) {
		t.Fatal("rejected credential became refreshable after reload")
	}
	_ = p.RefreshToken(context.Background(), reloaded, transport)
	if calls.Load() != 1 {
		t.Fatalf("rejected refresh token sent %d times", calls.Load())
	}
}

func TestCodexRotationSerializes(t *testing.T) {
	p, first := codexFixture(t)
	second := readCodexFixture(t, p, first.File)
	stale := readCodexFixture(t, p, first.File)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var calls atomic.Int32
	newAccess := jwtWithExp(time.Now().Add(10 * 24 * time.Hour).Unix())
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if calls.Add(1) != 1 {
			t.Error("rotation replayed the refresh token")
		}
		body, _ := io.ReadAll(req.Body)
		if !strings.Contains(string(body), "fixture-refresh") {
			t.Error("unexpected refresh credential")
		}
		close(entered)
		select {
		case <-release:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		encoded, _ := json.Marshal(map[string]string{"access_token": newAccess, "refresh_token": "rotated-fixture-refresh"})
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(encoded)))}, nil
	})
	results := make(chan error, 3)
	go func() { results <- p.RefreshToken(context.Background(), first, transport) }()
	<-entered
	go func() { results <- p.RefreshToken(context.Background(), second, transport) }()
	stale.CodexCookies = map[string]string{"__cf_bm": "fixture-cookie"}
	go func() { results <- saveAccount(stale) }()
	unblock()
	staleErrors := 0
	for range 3 {
		if err := <-results; errors.Is(err, errCodexStale) {
			staleErrors++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 || staleErrors != 1 || second.AccessToken != newAccess {
		t.Fatalf("calls=%d stale=%d second=%q", calls.Load(), staleErrors, second.AccessToken)
	}
	current := readCodexFixture(t, p, first.File)
	if current.RefreshToken != "rotated-fixture-refresh" || current.AccessToken != newAccess || current.RefreshBlocked {
		t.Fatal("rotated credentials were not durably retained")
	}
}

func TestCodexRefreshUncertain(t *testing.T) {
	for _, failure := range []string{"transport", "malformed", "server"} {
		t.Run(failure, func(t *testing.T) {
			p, a := codexFixture(t)
			var calls atomic.Int32
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				if failure == "transport" {
					return nil, io.ErrUnexpectedEOF
				}
				status, body := http.StatusOK, "{"
				if failure == "server" {
					status, body = http.StatusInternalServerError, "server failed"
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			if err := p.RefreshToken(context.Background(), a, transport); err == nil {
				t.Fatal("expected uncertain refresh result")
			}
			a = readCodexFixture(t, p, a.File)
			if !a.RefreshBlocked || (&proxyHandler{}).needsRefresh(a) {
				t.Fatal("ambiguous rotation can be replayed after restart")
			}
			_ = p.RefreshToken(context.Background(), a, transport)
			if calls.Load() != 1 {
				t.Fatal("ambiguous rotation was retried")
			}
		})
	}
}

func TestCodexRefreshCooldown(t *testing.T) {
	p, a := codexFixture(t)
	var calls atomic.Int32
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusTooManyRequests, Status: "429 Too Many Requests", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":"rate limited"}`))}, nil
	})
	_ = p.RefreshToken(context.Background(), a, transport)
	reloaded := readCodexFixture(t, p, a.File)
	if reloaded.RefreshBlocked || (&proxyHandler{}).needsRefresh(reloaded) {
		t.Fatal("429 retry cooldown was not retained across reload")
	}
	_ = p.RefreshToken(context.Background(), reloaded, transport)
	if calls.Load() != 1 {
		t.Fatal("429 bypassed the failed-attempt cooldown")
	}
	root, auth, err := readCodexFile(a.File)
	if err != nil {
		t.Fatal(err)
	}
	auth.RefreshGuard.AttemptAt = time.Now().Add(-refreshPerAccountInterval - time.Minute)
	root["refresh_guard"] = auth.RefreshGuard
	if err := atomicWriteJSON(a.File, root); err != nil {
		t.Fatal(err)
	}
	reloaded = readCodexFixture(t, p, a.File)
	if !(&proxyHandler{}).needsRefresh(reloaded) {
		t.Fatal("definitively rate-limited request never recovered after cooldown")
	}
	_ = p.RefreshToken(context.Background(), reloaded, transport)
	if calls.Load() != 2 {
		t.Fatal("eligible retry did not run")
	}
}

func TestCodexFreshLoginResetsGuard(t *testing.T) {
	p, old := codexFixture(t)
	_ = p.RefreshToken(context.Background(), old, roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF }))
	root, _, err := readCodexFile(old.File)
	if err != nil {
		t.Fatal(err)
	}
	root["tokens"].(map[string]any)["refresh_token"] = "fresh-fixture-refresh"
	if err := atomicWriteJSON(old.File, root); err != nil {
		t.Fatal(err)
	}
	fresh := readCodexFixture(t, p, old.File)
	if fresh.RefreshBlocked || !(&proxyHandler{}).needsRefresh(fresh) {
		t.Fatal("old guard poisoned a fresh login")
	}
	var calls atomic.Int32
	if err := p.RefreshToken(context.Background(), old, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("stale object must adopt the fresh login")
	})); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || old.RefreshToken != "fresh-fixture-refresh" || old.RefreshBlocked {
		t.Fatal("stale object reused old credentials instead of the fresh login")
	}
}

func TestCodexStaleSaveKeepsRetired(t *testing.T) {
	p, a := codexFixture(t)
	stale := readCodexFixture(t, p, a.File)
	a.Dead = true
	if err := saveAccount(a); err != nil {
		t.Fatal(err)
	}
	if err := saveAccount(stale); !errors.Is(err, errCodexStale) {
		t.Fatalf("stale save returned %v", err)
	}
	if !readCodexFixture(t, p, a.File).Dead {
		t.Fatal("stale metadata resurrected a retired account")
	}
}

func TestCodexRefreshWaiterAdopts(t *testing.T) {
	_, waiting := codexFixture(t)
	root, _, err := readCodexFile(waiting.File)
	if err != nil {
		t.Fatal(err)
	}
	newAccess := jwtWithExp(time.Now().Add(10 * 24 * time.Hour).Unix())
	root["tokens"].(map[string]any)["access_token"] = newAccess
	root["tokens"].(map[string]any)["refresh_token"] = "waiter-fixture-refresh"
	if err := atomicWriteJSON(waiting.File, root); err != nil {
		t.Fatal(err)
	}
	pending := &refreshCall{done: make(chan struct{})}
	close(pending.done)
	h := &proxyHandler{refreshCalls: map[string]*refreshCall{string(waiting.Type) + ":" + waiting.ID: pending}}
	if err := h.refreshAccount(context.Background(), waiting); err != nil {
		t.Fatal(err)
	}
	if waiting.AccessToken != newAccess || waiting.RefreshToken != "waiter-fixture-refresh" {
		t.Fatal("single-flight waiter retained the old credential snapshot")
	}
}

func TestCodexModelsSkipRetired(t *testing.T) {
	for _, state := range []string{"dead", "disabled"} {
		t.Run(state, func(t *testing.T) {
			p, a := codexFixture(t)
			a.Dead, a.Disabled = state == "dead", state == "disabled"
			var calls atomic.Int32
			err := syncProviderModels(context.Background(), roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return nil, errors.New("unavailable accounts must not be polled")
			}), NewProviderRegistry(p, nil, nil), a)
			if err != nil || calls.Load() != 0 {
				t.Fatalf("poll err=%v calls=%d", err, calls.Load())
			}
		})
	}
}

func TestCodexReplacementDuringRotate(t *testing.T) {
	p, old := codexFixture(t)
	newAccess := jwtWithExp(time.Now().Add(10 * 24 * time.Hour).Unix())
	err := p.RefreshToken(context.Background(), old, roundTripFunc(func(*http.Request) (*http.Response, error) {
		root, _, err := readCodexFile(old.File)
		if err != nil {
			return nil, err
		}
		root["tokens"].(map[string]any)["refresh_token"] = "replacement-fixture-refresh"
		if err := atomicWriteJSON(old.File, root); err != nil {
			return nil, err
		}
		encoded, _ := json.Marshal(map[string]string{"access_token": newAccess, "refresh_token": "obsolete-rotation-result"})
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(encoded)))}, nil
	}))
	if !errors.Is(err, errCodexStale) {
		t.Fatalf("superseded rotation returned %v", err)
	}
	if readCodexFixture(t, p, old.File).RefreshToken != "replacement-fixture-refresh" {
		t.Fatal("rotation overwrote a replacement credential")
	}
}

func TestCodexCommitFailureBlocksReuse(t *testing.T) {
	p, a := codexFixture(t)
	backup := a.File + ".pending"
	var calls atomic.Int32
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		if err := os.Rename(a.File, backup); err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"issued-fixture-access","refresh_token":"issued-fixture-refresh"}`))}, nil
	})
	if err := p.RefreshToken(context.Background(), a, transport); err == nil {
		t.Fatal("refresh claimed success without a durable commit")
	}
	if err := os.Rename(backup, a.File); err != nil {
		t.Fatal(err)
	}
	a = readCodexFixture(t, p, a.File)
	if !a.RefreshBlocked {
		t.Fatal("lost rotation result left the consumed token eligible")
	}
	_ = p.RefreshToken(context.Background(), a, transport)
	if calls.Load() != 1 {
		t.Fatal("failed commit replayed the consumed token")
	}
}

func TestCodexCancelledBeforeRefresh(t *testing.T) {
	p, a := codexFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	err := p.RefreshToken(ctx, a, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("cancelled refresh reached transport")
	}))
	if !errors.Is(err, context.Canceled) || calls.Load() != 0 || readCodexFixture(t, p, a.File).RefreshBlocked {
		t.Fatalf("cancelled request err=%v calls=%d", err, calls.Load())
	}
}

func TestCodexRetiredNoRefresh(t *testing.T) {
	p, a := codexFixture(t)
	a.Dead = true
	if err := saveAccount(a); err != nil {
		t.Fatal(err)
	}
	if (&proxyHandler{}).needsRefresh(a) {
		t.Fatal("retired account requests proactive refresh")
	}
	var calls atomic.Int32
	err := p.RefreshToken(context.Background(), a, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("must not send retired credentials")
	}))
	if err == nil || calls.Load() != 0 {
		t.Fatalf("retired refresh err=%v calls=%d", err, calls.Load())
	}
}
