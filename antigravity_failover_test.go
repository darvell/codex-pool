package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const antigravitySuccessSSE = "data: {\"response\":{\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"ok\"}]},\"finishReason\":\"STOP\"}]}}\n\n"

func testAntigravityHandler(t *testing.T, transport http.RoundTripper, accounts ...*Account) (*proxyHandler, string) {
	t.Helper()
	antigravityModels.Reset()
	t.Cleanup(antigravityModels.Reset)
	model := "gemini-3.8-flash-medium"
	for _, account := range accounts {
		if account.ModelRateLimits == nil {
			account.ModelRateLimits = make(map[string]time.Time)
		}
		if account.ModelBackoffLevels == nil {
			account.ModelBackoffLevels = make(map[string]int)
		}
		antigravityModels.ReplaceAccount(account.ID, AntigravityAccountSnapshot{
			FetchedAt: time.Now(),
			Models:    map[string]AntigravityModelInfo{model: {ID: model}},
		})
	}
	daily, _ := url.Parse("https://daily.test")
	production, _ := url.Parse("https://production.test")
	provider := NewAntigravityProvider(daily, production)
	return &proxyHandler{
		cfg:                  &config{maxAttempts: len(accounts)},
		pool:                 newPoolState(accounts, false),
		registry:             NewProviderRegistry(nil, nil, nil, provider),
		transport:            transport,
		antigravityTransport: transport,
		recent:               newRecentErrors(10),
		metrics:              newMetrics(),
	}, model
}

func antigravityProxyRequest(model string) (*http.Request, []byte) {
	body := []byte(`{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1beta/models/"+model+":generateContent", strings.NewReader(string(body)))
	return req, body
}

func antigravityHTTPResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestAntigravityTwoAccountFailover(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"forbidden", http.StatusForbidden, antigravityVerifyFixture},
		{"rate limit", http.StatusTooManyRequests, `{"error":{"status":"RESOURCE_EXHAUSTED"}}`},
		{"server error", http.StatusInternalServerError, `{"error":{"message":"failed"}}`},
		{"no capacity", http.StatusServiceUnavailable, `{"error":{"message":"No capacity available"}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := &Account{Type: AccountTypeAntigravity, ID: "a", AccessToken: "a", ProjectID: "pa"}
			b := &Account{Type: AccountTypeAntigravity, ID: "b", AccessToken: "b", ProjectID: "pb"}
			var sawB atomic.Bool
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("Authorization") == "Bearer b" {
					sawB.Store(true)
					return antigravityHTTPResponse(http.StatusOK, antigravitySuccessSSE), nil
				}
				return antigravityHTTPResponse(tc.status, tc.body), nil
			})
			h, model := testAntigravityHandler(t, transport, a, b)
			req, body := antigravityProxyRequest(model)
			recorder := httptest.NewRecorder()
			if !h.handleAntigravityProxy(recorder, req, body, "antigravity/"+model, "conversation", "user", "origin", "", "request") {
				t.Fatal("request was not routed to Antigravity")
			}
			if recorder.Code != http.StatusOK || !sawB.Load() {
				t.Fatalf("status=%d sawB=%v body=%s", recorder.Code, sawB.Load(), recorder.Body.String())
			}
			if atomic.LoadInt64(&a.Inflight) != 0 || atomic.LoadInt64(&b.Inflight) != 0 || atomic.LoadInt64(&h.inflight) != 0 {
				t.Fatalf("reservation leak: a=%d b=%d handler=%d", a.Inflight, b.Inflight, h.inflight)
			}
			h.pool.mu.RLock()
			pinned := h.pool.convPin["antigravity:"+model+":conversation"]
			h.pool.mu.RUnlock()
			if pinned != "b" {
				t.Fatalf("pin=%q, want successful account b", pinned)
			}
		})
	}
}

func TestAntigravitySuccessSurvivesGenerationReplacement(t *testing.T) {
	a := &Account{Type: AccountTypeAntigravity, ID: "a", AccessToken: "a", ProjectID: "pa"}
	b := &Account{Type: AccountTypeAntigravity, ID: "b", AccessToken: "b", ProjectID: "pb"}
	var h *proxyHandler
	var calls, closes atomic.Int64
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		replacement := &Account{Type: AccountTypeAntigravity, ID: "a", AccessToken: "new-a", ProjectID: "new-pa", ModelRateLimits: map[string]time.Time{}}
		replacement.antigravitySnapshot = &AntigravityAccountSnapshot{FetchedAt: time.Now(), Models: map[string]AntigravityModelInfo{"gemini-3.8-flash-medium": {ID: "gemini-3.8-flash-medium"}}}
		h.pool.replaceWithAntigravityRegistry([]*Account{replacement, b})
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       &countingReadCloser{Reader: strings.NewReader(antigravitySuccessSSE), closed: &closes},
		}, nil
	})
	var model string
	h, model = testAntigravityHandler(t, transport, a, b)
	req, body := antigravityProxyRequest(model)
	recorder := httptest.NewRecorder()
	h.handleAntigravityProxy(recorder, req, body, "antigravity/"+model, "conversation", "user", "origin", "", "request")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "ok") {
		t.Fatalf("successful stale-generation response was not delivered: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls=%d, want successful response delivered without failover", calls.Load())
	}
	if closes.Load() != 1 {
		t.Fatalf("successful body closes=%d, want 1", closes.Load())
	}
	if atomic.LoadInt64(&a.Inflight) != 0 || atomic.LoadInt64(&h.inflight) != 0 {
		t.Fatalf("reservation leak: account=%d handler=%d", a.Inflight, h.inflight)
	}
	h.pool.mu.RLock()
	pinned := h.pool.convPin["antigravity:"+model+":conversation"]
	h.pool.mu.RUnlock()
	if pinned != "" {
		t.Fatalf("stale successful request committed pin %q", pinned)
	}
}

func TestAntigravityCountTokensSuccessSurvivesGenerationReplacement(t *testing.T) {
	a := &Account{Type: AccountTypeAntigravity, ID: "a", AccessToken: "a", ProjectID: "pa"}
	var h *proxyHandler
	var calls, closes atomic.Int64
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		replacement := &Account{Type: AccountTypeAntigravity, ID: "a", AccessToken: "new-a", ProjectID: "new-pa", ModelRateLimits: map[string]time.Time{}}
		replacement.antigravitySnapshot = &AntigravityAccountSnapshot{FetchedAt: time.Now(), Models: map[string]AntigravityModelInfo{"gemini-3.8-flash-medium": {ID: "gemini-3.8-flash-medium"}}}
		h.pool.replaceWithAntigravityRegistry([]*Account{replacement})
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       &countingReadCloser{Reader: strings.NewReader(`{"response":{"totalTokens":7}}`), closed: &closes},
		}, nil
	})
	var model string
	h, model = testAntigravityHandler(t, transport, a)
	body := []byte(`{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1beta/models/"+model+":countTokens", strings.NewReader(string(body)))
	recorder := httptest.NewRecorder()
	h.handleAntigravityProxy(recorder, req, body, "antigravity/"+model, "conversation", "user", "origin", "", "request")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"totalTokens":7`) {
		t.Fatalf("successful countTokens response was not delivered: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if calls.Load() != 1 || closes.Load() != 1 {
		t.Fatalf("calls=%d closes=%d, want 1/1", calls.Load(), closes.Load())
	}
	if atomic.LoadInt64(&a.Inflight) != 0 || atomic.LoadInt64(&h.inflight) != 0 {
		t.Fatalf("reservation leak: account=%d handler=%d", a.Inflight, h.inflight)
	}
}

func TestAntigravityTransportFailureFallsThrough(t *testing.T) {
	a := &Account{Type: AccountTypeAntigravity, ID: "a", AccessToken: "a", ProjectID: "pa"}
	b := &Account{Type: AccountTypeAntigravity, ID: "b", AccessToken: "b", ProjectID: "pb"}
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") == "Bearer a" {
			return nil, errors.New("dial failed")
		}
		return antigravityHTTPResponse(http.StatusOK, antigravitySuccessSSE), nil
	})
	h, model := testAntigravityHandler(t, transport, a, b)
	req, body := antigravityProxyRequest(model)
	recorder := httptest.NewRecorder()
	h.handleAntigravityProxy(recorder, req, body, "antigravity/"+model, "", "user", "origin", "", "request")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAntigravityServerCooldownSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "antigravity.json")
	a := &Account{Type: AccountTypeAntigravity, ID: "a", File: file, AccessToken: "a", RefreshToken: "refresh", ProjectID: "pa", ModelRateLimits: map[string]time.Time{}, ModelBackoffLevels: map[string]int{}}
	if err := saveAntigravityAccount(a); err != nil {
		t.Fatal(err)
	}
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return antigravityHTTPResponse(http.StatusInternalServerError, `{"error":{"message":"failed"}}`), nil
	})
	h, model := testAntigravityHandler(t, transport, a)
	req, body := antigravityProxyRequest(model)
	recorder := httptest.NewRecorder()
	h.handleAntigravityProxy(recorder, req, body, "antigravity/"+model, "", "user", "origin", "", "request")
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	loaded, err := (&AntigravityProvider{}).LoadAccount("antigravity.json", file, func() []byte { raw, _ := os.ReadFile(file); return raw }())
	if err != nil || loaded == nil || loaded.RateLimitUntil.IsZero() {
		t.Fatalf("cooldown was not persisted: loaded=%#v err=%v", loaded, err)
	}
}

func TestAntigravityTerminalBadRequestDoesNotRotate(t *testing.T) {
	a := &Account{Type: AccountTypeAntigravity, ID: "a", AccessToken: "a", ProjectID: "pa"}
	b := &Account{Type: AccountTypeAntigravity, ID: "b", AccessToken: "b", ProjectID: "pb"}
	var bCalls atomic.Int64
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") == "Bearer b" {
			bCalls.Add(1)
		}
		return antigravityHTTPResponse(http.StatusBadRequest, `{"error":{"message":"invalid request"}}`), nil
	})
	h, model := testAntigravityHandler(t, transport, a, b)
	req, body := antigravityProxyRequest(model)
	recorder := httptest.NewRecorder()
	h.handleAntigravityProxy(recorder, req, body, "antigravity/"+model, "", "user", "origin", "", "request")
	if recorder.Code != http.StatusBadRequest || bCalls.Load() != 0 {
		t.Fatalf("status=%d bCalls=%d body=%s", recorder.Code, bCalls.Load(), recorder.Body.String())
	}
}

func TestAntigravityRefreshCoalescesByAccountGeneration(t *testing.T) {
	dir := t.TempDir()
	account := &Account{
		Type: AccountTypeAntigravity, ID: "a", File: filepath.Join(dir, "a.json"),
		AccessToken: "old-access", RefreshToken: "old-refresh", ProjectID: "project",
		ModelRateLimits: map[string]time.Time{}, ModelBackoffLevels: map[string]int{},
	}
	if err := saveAntigravityAccount(account); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	proceed := make(chan struct{})
	var calls atomic.Int64
	var once sync.Once
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		once.Do(func() { close(started) })
		<-proceed
		return antigravityHTTPResponse(http.StatusOK, `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`), nil
	})
	daily, _ := url.Parse("https://daily.test")
	production, _ := url.Parse("https://production.test")
	h := &proxyHandler{
		pool:             newPoolState([]*Account{account}, false),
		registry:         NewProviderRegistry(nil, nil, nil, NewAntigravityProvider(daily, production)),
		refreshTransport: transport,
	}
	reservationA := &antigravityReservation{Account: account, generation: h.pool.generation}
	reservationB := &antigravityReservation{Account: account, generation: h.pool.generation}
	results := make(chan error, 2)
	go func() { results <- h.refreshAntigravityReservation(context.Background(), reservationA) }()
	<-started
	go func() { results <- h.refreshAntigravityReservation(context.Background(), reservationB) }()
	// Give the second caller time to join the in-flight keyed refresh before the
	// mocked OAuth response is released.
	time.Sleep(20 * time.Millisecond)
	close(proceed)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("refresh calls=%d, want one coalesced rotation", calls.Load())
	}
	account.mu.Lock()
	accessToken, refreshToken := account.AccessToken, account.RefreshToken
	account.mu.Unlock()
	if accessToken != "new-access" || refreshToken != "new-refresh" {
		t.Fatalf("tokens=%q/%q, want refreshed values", accessToken, refreshToken)
	}
}

func TestAntigravityUnauthorizedRefreshFailureRotates(t *testing.T) {
	a := &Account{Type: AccountTypeAntigravity, ID: "a", AccessToken: "a", RefreshToken: "refresh-a", ProjectID: "pa"}
	b := &Account{Type: AccountTypeAntigravity, ID: "b", AccessToken: "b", ProjectID: "pb"}
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "oauth2.googleapis.com" {
			return antigravityHTTPResponse(http.StatusBadRequest, `{"error":"invalid_grant"}`), nil
		}
		if req.Header.Get("Authorization") == "Bearer a" {
			return antigravityHTTPResponse(http.StatusUnauthorized, `{"error":{"message":"expired"}}`), nil
		}
		return antigravityHTTPResponse(http.StatusOK, antigravitySuccessSSE), nil
	})
	h, model := testAntigravityHandler(t, transport, a, b)
	h.refreshTransport = transport
	req, body := antigravityProxyRequest(model)
	recorder := httptest.NewRecorder()
	h.handleAntigravityProxy(recorder, req, body, "antigravity/"+model, "", "user", "origin", "", "request")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAntigravityRetryAfterAndTemporaryDiagnostics(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name   string
		header string
		body   string
		min    time.Duration
	}{
		{"seconds", "7", `{}`, 7 * time.Second},
		{"date", now.Add(9 * time.Second).UTC().Format(http.TimeFormat), `{}`, 7 * time.Second},
		{"body later", "2", `{"error":{"details":[{"retryDelay":"11s"}]}}`, 11 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := make(http.Header)
			header.Set("Retry-After", tc.header)
			got := antigravityRetryAt(header, []byte(tc.body), 0, now)
			if got.Sub(now) < tc.min {
				t.Fatalf("retry=%s, want at least %s", got.Sub(now), tc.min)
			}
		})
	}

	a := &Account{Type: AccountTypeAntigravity, ID: "a", ProjectID: "pa", ModelRateLimits: map[string]time.Time{"gemini-3.8-flash-medium": now.Add(5 * time.Second)}}
	b := &Account{Type: AccountTypeAntigravity, ID: "b", ProjectID: "pb", ModelRateLimits: map[string]time.Time{"gemini-3.8-flash-medium": now.Add(9 * time.Second)}}
	h, model := testAntigravityHandler(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("temporarily blocked request must not reach upstream")
		return nil, nil
	}), a, b)
	req, body := antigravityProxyRequest(model)
	recorder := httptest.NewRecorder()
	h.handleAntigravityProxy(recorder, req, body, "antigravity/"+model, "", "user", "origin", "", "request")
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	retry, err := strconv.Atoi(recorder.Header().Get("Retry-After"))
	if err != nil || retry < 1 || retry > 6 {
		t.Fatalf("Retry-After=%q, want earliest rounded deadline", recorder.Header().Get("Retry-After"))
	}
	if strings.Contains(recorder.Body.String(), "account a") || !strings.Contains(recorder.Body.String(), "model_cooldown") {
		t.Fatalf("unsafe or incomplete diagnostics: %s", recorder.Body.String())
	}
}

func TestAntigravityEligibilityAndReservationFairness(t *testing.T) {
	antigravityModels.Reset()
	t.Cleanup(antigravityModels.Reset)
	model := "gemini-3.8-flash-medium"
	low, high := 0.2, 0.8
	a := &Account{Type: AccountTypeAntigravity, ID: "a", ModelRateLimits: map[string]time.Time{}, ModelBackoffLevels: map[string]int{}}
	b := &Account{Type: AccountTypeAntigravity, ID: "b", ModelRateLimits: map[string]time.Time{}, ModelBackoffLevels: map[string]int{}}
	pool := newPoolState([]*Account{a, b}, false)
	antigravityModels.ReplaceAccount("a", AntigravityAccountSnapshot{FetchedAt: time.Now(), Models: map[string]AntigravityModelInfo{model: {ID: model, Quota: AntigravityQuotaInfo{RemainingFraction: &low}}}})
	antigravityModels.ReplaceAccount("b", AntigravityAccountSnapshot{FetchedAt: time.Now(), Models: map[string]AntigravityModelInfo{model: {ID: model, Quota: AntigravityQuotaInfo{RemainingFraction: &high}}}})
	reservation, _ := pool.reserveAntigravityModel("", nil, model, "")
	if reservation == nil || reservation.Account != b {
		t.Fatalf("reservation=%v, want high-headroom b", reservation)
	}
	reservation.Release()

	one := 1.0
	for _, id := range []string{"a", "b"} {
		antigravityModels.ReplaceAccount(id, AntigravityAccountSnapshot{FetchedAt: time.Now(), Models: map[string]AntigravityModelInfo{model: {ID: model, Quota: AntigravityQuotaInfo{RemainingFraction: &one}}}})
	}
	first, _ := pool.reserveAntigravityModel("", nil, model, "")
	second, _ := pool.reserveAntigravityModel("", nil, model, "")
	if first == nil || second == nil || first.Account == second.Account {
		t.Fatalf("concurrent reservations were not distributed: %#v %#v", first, second)
	}
	first.Release()
	first.Release()
	second.Release()
	if a.Inflight != 0 || b.Inflight != 0 {
		t.Fatalf("idempotent release leaked or underflowed: a=%d b=%d", a.Inflight, b.Inflight)
	}
}

func TestAntigravityExactModelAndFamilyQuotaScopes(t *testing.T) {
	now := time.Now()
	account := &Account{Type: AccountTypeAntigravity, ID: "a", ModelRateLimits: map[string]time.Time{"gemini-a": now.Add(time.Hour)}}
	snapshot := AntigravityAccountSnapshot{FetchedAt: now, Models: map[string]AntigravityModelInfo{"gemini-a": {ID: "gemini-a"}, "gemini-b": {ID: "gemini-b"}, "claude-a": {ID: "claude-a"}}}
	if decision := antigravityEvaluateAccount(account, snapshot, true, "gemini-b", "", false, now); !decision.eligible {
		t.Fatalf("exact model cooldown blocked sibling: %+v", decision)
	}
	account.ModelRateLimits["family:gemini"] = now.Add(time.Hour)
	if decision := antigravityEvaluateAccount(account, snapshot, true, "gemini-b", "", false, now); decision.reason != antigravityFamilyQuotaExhausted {
		t.Fatalf("family cooldown reason=%s", decision.reason)
	}
	if decision := antigravityEvaluateAccount(account, snapshot, true, "claude-a", "", false, now); !decision.eligible {
		t.Fatalf("Gemini family cooldown blocked Claude: %+v", decision)
	}
	delete(account.ModelRateLimits, "family:gemini")
	snapshot.Quota = &AntigravityQuotaSummary{Groups: []AntigravityQuotaGroup{{Family: antigravityQuotaFamilyGemini, Buckets: []AntigravityQuotaBucket{{ID: "gemini-weekly", Window: antigravityQuotaWindowWeekly, RemainingFraction: 0, ResetTime: now.Add(time.Hour)}}}}}
	if decision := antigravityEvaluateAccount(account, snapshot, true, "gemini-b", "", false, now); decision.reason != antigravityFamilyQuotaExhausted {
		t.Fatalf("authoritative family quota reason=%s", decision.reason)
	}
}

func TestAntigravityReplayIsTenantScopedAndCrossAccountNeutral(t *testing.T) {
	cache := newAntigravityReplayCache(time.Hour, 10)
	request := []byte(`{"model":"gemini-test","request":{"contents":[{"role":"user","parts":[{"text":"same prompt"}]}]}}`)
	a := antigravityReplayScopeFromBodyForTenant(request, "tenant-a")
	b := antigravityReplayScopeFromBodyForTenant(request, "tenant-b")
	if cache.key(a) == cache.key(b) {
		t.Fatal("different tenants share replay key")
	}
	if strings.Contains(cache.key(a), "account") {
		t.Fatal("replay key unexpectedly contains account identity")
	}
	response := []byte(`{"response":{"candidates":[{"content":{"parts":[{"functionCall":{"name":"tool","args":{}},"thoughtSignature":"signed"}]}}]}}`)
	if !cache.capture(a, request, response) {
		t.Fatal("failed to capture replay")
	}
	if _, ok := cache.get(b, time.Now()); ok {
		t.Fatal("tenant b observed tenant a replay")
	}
	if _, ok := cache.get(a, time.Now()); !ok {
		t.Fatal("tenant a replay did not survive account-neutral lookup")
	}
}

func TestAntigravityFailedLoadPreservesRegistry(t *testing.T) {
	antigravityModels.Reset()
	t.Cleanup(antigravityModels.Reset)
	antigravityModels.ReplaceAccount("live", AntigravityAccountSnapshot{FetchedAt: time.Now(), Models: map[string]AntigravityModelInfo{"gemini-live": {ID: "gemini-live"}}})
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "antigravity"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "antigravity", "broken.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	daily, _ := url.Parse("https://daily.test")
	prod, _ := url.Parse("https://prod.test")
	_, err := loadPool(dir, NewProviderRegistry(nil, nil, nil, NewAntigravityProvider(daily, prod)))
	if err == nil {
		t.Fatal("malformed load unexpectedly succeeded")
	}
	if snapshot, ok := antigravityModels.AccountSnapshot("live"); !ok || snapshot.Models["gemini-live"].ID == "" {
		t.Fatal("failed staged load mutated live registry")
	}
}

func TestAntigravityReloadRejectsCredentialsChangedAfterStaging(t *testing.T) {
	antigravityModels.Reset()
	t.Cleanup(antigravityModels.Reset)
	t.Setenv("ANTIGRAVITY_OAUTH_CLIENT_ID", "test-client")

	dir := t.TempDir()
	accountDir := filepath.Join(dir, "antigravity")
	if err := os.MkdirAll(accountDir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(accountDir, "account.json")
	snapshot := AntigravityAccountSnapshot{
		FetchedAt: time.Now(),
		Models:    map[string]AntigravityModelInfo{"gemini-test": {ID: "gemini-test"}},
	}
	initial, err := json.Marshal(AntigravityAuthJSON{
		Type:          string(AccountTypeAntigravity),
		AccessToken:   "old-access",
		RefreshToken:  "old-refresh",
		ProjectID:     "project",
		ModelSnapshot: &snapshot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, initial, 0o600); err != nil {
		t.Fatal(err)
	}

	daily, _ := url.Parse("https://daily.test")
	prod, _ := url.Parse("https://prod.test")
	provider := NewAntigravityProvider(daily, prod)
	registry := NewProviderRegistry(nil, nil, nil, provider)
	live, err := loadPool(dir, registry)
	if err != nil {
		t.Fatal(err)
	}
	pool := newPoolState(live, false)
	pool.initializeAntigravityRegistry(live)
	stagedOld, err := loadPool(dir, registry)
	if err != nil {
		t.Fatal(err)
	}

	refreshTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "oauth2.googleapis.com" {
			t.Fatalf("unexpected refresh URL %s", req.URL)
		}
		return antigravityHTTPResponse(http.StatusOK, `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`), nil
	})
	h := &proxyHandler{pool: pool, registry: registry, refreshTransport: refreshTransport}
	reservation := &antigravityReservation{Account: live[0], generation: pool.generation}
	if err := h.refreshAntigravityReservation(context.Background(), reservation); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	generation := pool.generation
	if err := pool.replaceWithAntigravityRegistry(stagedOld); !errors.Is(err, errAntigravityReloadChanged) {
		t.Fatalf("stale publication error = %v, want staged-file change", err)
	}
	pool.mu.RLock()
	stillLive := pool.accounts[0]
	pool.mu.RUnlock()
	if pool.generation != generation || stillLive != live[0] {
		t.Fatal("rejected publication mutated the live pool")
	}

	fresh, err := loadPool(dir, registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.replaceWithAntigravityRegistry(fresh); err != nil {
		t.Fatalf("publish refreshed load: %v", err)
	}
	pool.mu.RLock()
	published := pool.accounts[0]
	pool.mu.RUnlock()
	published.mu.Lock()
	accessToken, refreshToken := published.AccessToken, published.RefreshToken
	published.mu.Unlock()
	if accessToken != "new-access" || refreshToken != "new-refresh" {
		t.Fatalf("published stale credentials: access=%q refresh=%q", accessToken, refreshToken)
	}
}

func TestAntigravityStalePollCannotOverwriteReloadedCredentials(t *testing.T) {
	antigravityModels.Reset()
	t.Cleanup(antigravityModels.Reset)
	dir := t.TempDir()
	file := filepath.Join(dir, "account.json")
	old := &Account{Type: AccountTypeAntigravity, ID: "same", File: file, AccessToken: "old", RefreshToken: "old-refresh", ProjectID: "project", ModelRateLimits: map[string]time.Time{}, ModelBackoffLevels: map[string]int{}}
	pool := newPoolState([]*Account{old}, false)
	started := make(chan struct{})
	proceed := make(chan struct{})
	var once sync.Once
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, ":fetchAvailableModels") {
			once.Do(func() { close(started) })
			<-proceed
			return antigravityHTTPResponse(http.StatusOK, `{"models":{"gemini-live":{"displayName":"Gemini Live"}}}`), nil
		}
		return antigravityHTTPResponse(http.StatusOK, antigravityQuotaSummaryFixture), nil
	})
	daily, _ := url.Parse("https://daily.test")
	prod, _ := url.Parse("https://prod.test")
	h := &proxyHandler{pool: pool, transport: transport}
	done := make(chan error, 1)
	go func() { done <- h.syncAntigravityModelsGuarded(context.Background(), 1, old, daily, prod) }()
	<-started
	newAccount := &Account{Type: AccountTypeAntigravity, ID: "same", File: file, AccessToken: "new", RefreshToken: "new-refresh", ProjectID: "project", ModelRateLimits: map[string]time.Time{}, ModelBackoffLevels: map[string]int{}}
	newAccount.antigravitySnapshot = &AntigravityAccountSnapshot{FetchedAt: time.Now(), Models: map[string]AntigravityModelInfo{"gemini-new": {ID: "gemini-new"}}}
	pool.replaceWithAntigravityRegistry([]*Account{newAccount})
	if err := os.WriteFile(file, []byte(`{"type":"antigravity","access_token":"new","refresh_token":"new-refresh","project_id":"project"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	close(proceed)
	if err := <-done; !errors.Is(err, errStaleAntigravityAccount) {
		t.Fatalf("poll error=%v, want stale generation", err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved["access_token"] != "new" {
		t.Fatalf("stale poll overwrote credentials: %s", raw)
	}
	snapshot, ok := antigravityModels.AccountSnapshot("same")
	if !ok || snapshot.Models["gemini-new"].ID == "" || snapshot.Models["gemini-live"].ID != "" {
		t.Fatalf("replacement snapshot was overwritten: %#v", snapshot)
	}
}

type countingReadCloser struct {
	io.Reader
	closed *atomic.Int64
}

func (c *countingReadCloser) Close() error {
	c.closed.Add(1)
	return nil
}

type antigravityPartialStreamBody struct {
	chunk  []byte
	sent   bool
	closed *atomic.Int64
}

func (b *antigravityPartialStreamBody) Read(target []byte) (int, error) {
	if b.sent {
		return 0, errors.New("upstream stream interrupted")
	}
	b.sent = true
	return copy(target, b.chunk), nil
}

func (b *antigravityPartialStreamBody) Close() error {
	b.closed.Add(1)
	return nil
}

func TestAntigravityPartialStreamNeverFailsOverAfterCommit(t *testing.T) {
	a := &Account{Type: AccountTypeAntigravity, ID: "a", AccessToken: "a", ProjectID: "pa"}
	b := &Account{Type: AccountTypeAntigravity, ID: "b", AccessToken: "b", ProjectID: "pb"}
	var calls, closes atomic.Int64
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body: &antigravityPartialStreamBody{
				chunk:  []byte(antigravitySuccessSSE),
				closed: &closes,
			},
		}, nil
	})
	h, model := testAntigravityHandler(t, transport, a, b)
	body := []byte(`{"stream":true,"contents":[{"role":"user","parts":[{"text":"hello"}]}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1beta/models/"+model+":streamGenerateContent", strings.NewReader(string(body)))
	recorder := httptest.NewRecorder()
	h.handleAntigravityProxy(recorder, req, body, "antigravity/"+model, "", "user", "origin", "", "request")
	if recorder.Code != http.StatusOK || recorder.Body.Len() == 0 {
		t.Fatalf("partial stream was not committed: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls=%d, want no failover after stream commit", calls.Load())
	}
	if closes.Load() != 1 {
		t.Fatalf("stream body closes=%d, want 1", closes.Load())
	}
}

func TestAntigravityEligibilityReasons(t *testing.T) {
	now := time.Now()
	model := "gemini-test"
	freshNegative := AntigravityAccountSnapshot{FetchedAt: now, Models: map[string]AntigravityModelInfo{"other": {ID: "other"}}}
	staleNegative := freshNegative
	staleNegative.FetchedAt = now.Add(-25 * time.Hour)
	tests := []struct {
		name       string
		account    *Account
		snapshot   AntigravityAccountSnapshot
		has        bool
		clientIP   string
		attempted  bool
		wantReason antigravityEligibilityReason
		eligible   bool
	}{
		{"unknown", &Account{Type: AccountTypeAntigravity}, AntigravityAccountSnapshot{}, false, "", false, antigravityCapabilityUnknown, true},
		{"stale negative", &Account{Type: AccountTypeAntigravity}, staleNegative, true, "", false, antigravityCapabilityUnknown, true},
		{"fresh unsupported", &Account{Type: AccountTypeAntigravity}, freshNegative, true, "", false, antigravityUnsupported, false},
		{"disabled", &Account{Type: AccountTypeAntigravity, Disabled: true}, AntigravityAccountSnapshot{Models: map[string]AntigravityModelInfo{model: {ID: model}}}, true, "", false, antigravityDisabled, false},
		{"dead", &Account{Type: AccountTypeAntigravity, Dead: true}, AntigravityAccountSnapshot{Models: map[string]AntigravityModelInfo{model: {ID: model}}}, true, "", false, antigravityDead, false},
		{"verification", &Account{Type: AccountTypeAntigravity, NeedsVerification: true}, AntigravityAccountSnapshot{Models: map[string]AntigravityModelInfo{model: {ID: model}}}, true, "", false, antigravityVerificationRequired, false},
		{"source ip", &Account{Type: AccountTypeAntigravity, AllowedSourceIPs: []string{"192.0.2.1"}}, AntigravityAccountSnapshot{Models: map[string]AntigravityModelInfo{model: {ID: model}}}, true, "192.0.2.2", false, antigravitySourceIPDenied, false},
		{"account cooldown", &Account{Type: AccountTypeAntigravity, RateLimitUntil: now.Add(time.Minute)}, AntigravityAccountSnapshot{Models: map[string]AntigravityModelInfo{model: {ID: model}}}, true, "", false, antigravityAccountCooldown, false},
		{"model cooldown", &Account{Type: AccountTypeAntigravity, ModelRateLimits: map[string]time.Time{model: now.Add(time.Minute)}}, AntigravityAccountSnapshot{Models: map[string]AntigravityModelInfo{model: {ID: model}}}, true, "", false, antigravityModelCooldown, false},
		{"already attempted", &Account{Type: AccountTypeAntigravity}, AntigravityAccountSnapshot{}, false, "", true, antigravityAlreadyAttempted, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decision := antigravityEvaluateAccount(tc.account, tc.snapshot, tc.has, model, tc.clientIP, tc.attempted, now)
			if decision.reason != tc.wantReason || decision.eligible != tc.eligible {
				t.Fatalf("decision=%+v, want reason=%s eligible=%v", decision, tc.wantReason, tc.eligible)
			}
		})
	}
}

func TestAntigravityConcurrentReservationsBalanceAndRelease(t *testing.T) {
	antigravityModels.Reset()
	t.Cleanup(antigravityModels.Reset)
	model := "gemini-test"
	accounts := []*Account{
		{Type: AccountTypeAntigravity, ID: "a", ModelRateLimits: map[string]time.Time{}},
		{Type: AccountTypeAntigravity, ID: "b", ModelRateLimits: map[string]time.Time{}},
		{Type: AccountTypeAntigravity, ID: "c", ModelRateLimits: map[string]time.Time{}},
	}
	for _, account := range accounts {
		antigravityModels.ReplaceAccount(account.ID, AntigravityAccountSnapshot{FetchedAt: time.Now(), Models: map[string]AntigravityModelInfo{model: {ID: model}}})
	}
	pool := newPoolState(accounts, false)
	const requests = 30
	reservations := make(chan *antigravityReservation, requests)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reservation, _ := pool.reserveAntigravityModel("", nil, model, "")
			reservations <- reservation
		}()
	}
	wg.Wait()
	close(reservations)
	counts := map[string]int{}
	for reservation := range reservations {
		if reservation == nil {
			t.Fatal("reservation unexpectedly nil")
		}
		counts[reservation.Account.ID]++
		reservation.Release()
	}
	if len(counts) != len(accounts) {
		t.Fatalf("reservations did not use every account: %v", counts)
	}
	for _, account := range accounts {
		if account.Inflight != 0 {
			t.Fatalf("account %s leaked inflight=%d", account.ID, account.Inflight)
		}
	}
}

func TestAntigravityFailureBodiesClosedExactlyOnce(t *testing.T) {
	a := &Account{Type: AccountTypeAntigravity, ID: "a", AccessToken: "a", ProjectID: "pa"}
	b := &Account{Type: AccountTypeAntigravity, ID: "b", AccessToken: "b", ProjectID: "pb"}
	var closes atomic.Int64
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") == "Bearer b" {
			return antigravityHTTPResponse(http.StatusOK, antigravitySuccessSSE), nil
		}
		return &http.Response{StatusCode: http.StatusInternalServerError, Header: make(http.Header), Body: &countingReadCloser{Reader: strings.NewReader(`{"error":{"message":"failed"}}`), closed: &closes}}, nil
	})
	h, model := testAntigravityHandler(t, transport, a, b)
	req, body := antigravityProxyRequest(model)
	recorder := httptest.NewRecorder()
	h.handleAntigravityProxy(recorder, req, body, "antigravity/"+model, "", "user", "origin", "", "request")
	// daily and production failures are each consumed once.
	if closes.Load() != 2 {
		t.Fatalf("failure body closes=%d, want 2", closes.Load())
	}
}

func TestAntigravityStaleGenerationCannotPin(t *testing.T) {
	account := &Account{Type: AccountTypeAntigravity, ID: "a", ModelRateLimits: map[string]time.Time{}}
	pool := newPoolState([]*Account{account}, false)
	reservation := &antigravityReservation{Account: account, generation: pool.generation}
	pool.replaceWithAntigravityRegistry([]*Account{account})
	if pool.pinAntigravityModel(reservation, "conversation", "gemini-test") {
		t.Fatal("stale generation committed a pin")
	}
}

func TestAntigravityNonTemporaryExclusionsReturn503(t *testing.T) {
	account := &Account{Type: AccountTypeAntigravity, ID: "disabled", ProjectID: "project", Disabled: true}
	h, model := testAntigravityHandler(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("disabled account reached upstream")
		return nil, nil
	}), account)
	req, body := antigravityProxyRequest(model)
	recorder := httptest.NewRecorder()
	h.handleAntigravityProxy(recorder, req, body, "antigravity/"+model, "", "user", "origin", "", "request")
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "disabled") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAntigravityInvalidSignatureClearsReplayAndRetriesSameAccount(t *testing.T) {
	oldCache := antigravityNativeReplay
	antigravityNativeReplay = newAntigravityReplayCache(time.Hour, 10)
	t.Cleanup(func() { antigravityNativeReplay = oldCache })
	account := &Account{Type: AccountTypeAntigravity, ID: "a", AccessToken: "a", ProjectID: "project"}
	var calls atomic.Int64
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return antigravityHTTPResponse(http.StatusBadRequest, `{"error":{"message":"invalid thoughtSignature"}}`), nil
		}
		return antigravityHTTPResponse(http.StatusOK, antigravitySuccessSSE), nil
	})
	h, model := testAntigravityHandler(t, transport, account)
	req, body := antigravityProxyRequest(model)
	prepared, err := prepareAntigravityRequest(req.URL.Path, body, "antigravity/"+model, "project", "conversation")
	if err != nil {
		t.Fatal(err)
	}
	scope := antigravityReplayScopeFromBodyForTenant(prepared.Body, "user\x00origin")
	response := []byte(`{"response":{"candidates":[{"content":{"parts":[{"functionCall":{"name":"tool","args":{}},"thoughtSignature":"signed"}]}}]}}`)
	if !antigravityNativeReplay.capture(scope, prepared.Body, response) {
		t.Fatal("failed to seed replay cache")
	}
	recorder := httptest.NewRecorder()
	h.handleAntigravityProxy(recorder, req, body, "antigravity/"+model, "conversation", "user", "origin", "", "request")
	if recorder.Code != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("status=%d calls=%d body=%s", recorder.Code, calls.Load(), recorder.Body.String())
	}
	if _, ok := antigravityNativeReplay.get(scope, time.Now()); ok {
		t.Fatal("invalid replay entry was not cleared")
	}
}

func TestAntigravityReloadReplacesActiveLeaseIdentityAndPreservesValidPin(t *testing.T) {
	old := &Account{Type: AccountTypeAntigravity, ID: "same", AccessToken: "old", ModelRateLimits: map[string]time.Time{}}
	pool := newPoolState([]*Account{old}, false)
	pool.convPin["antigravity:gemini-test:conversation"] = old.ID
	atomic.AddInt64(&old.Inflight, 1)
	reservation := &antigravityReservation{Account: old, generation: pool.generation}
	loaded := &Account{Type: AccountTypeAntigravity, ID: "same", AccessToken: "new", ModelRateLimits: map[string]time.Time{}}
	pool.replaceWithAntigravityRegistry([]*Account{loaded})
	pool.mu.RLock()
	current := pool.accounts[0]
	pin := pool.convPin["antigravity:gemini-test:conversation"]
	pool.mu.RUnlock()
	if current == old || pin != old.ID {
		t.Fatalf("reload did not replace identity or preserve pin: current_old=%v pin=%q", current == old, pin)
	}
	reservation.Release()
	if old.Inflight != 0 {
		t.Fatalf("lease released wrong object: inflight=%d", old.Inflight)
	}
}

func TestAntigravityLiveRateLimitScopeRequiresKnownBucket(t *testing.T) {
	model := "gemini-3.8-flash-medium"
	if got := antigravityRateLimitScope(model, []byte(`{"error":{"status":"RESOURCE_EXHAUSTED"}}`)); got != model {
		t.Fatalf("generic exhaustion scope=%q, want exact model", got)
	}
	if got := antigravityRateLimitScope(model, []byte(`{"metadata":{"quotaId":"gemini-weekly"}}`)); got != "family:gemini" {
		t.Fatalf("known family scope=%q", got)
	}
}

func TestAntigravityCatalogAndRoutingShareAvailability(t *testing.T) {
	antigravityModels.Reset()
	t.Cleanup(antigravityModels.Reset)
	model := "gemini-test"
	reset := time.Now().Add(time.Minute)
	account := &Account{Type: AccountTypeAntigravity, ID: "a", ModelRateLimits: map[string]time.Time{model: reset}}
	pool := newPoolState([]*Account{account}, false)
	antigravityModels.ReplaceAccount(account.ID, AntigravityAccountSnapshot{FetchedAt: time.Now(), Models: map[string]AntigravityModelInfo{model: {ID: model}}})
	decisions := pool.antigravityDecisions(nil, model, "", time.Now())
	report := buildAntigravityReport(decisions)
	models := antigravityModels.Models(pool)
	if len(models) != 1 || models[0].AvailableNow || report.Ready != 0 || models[0].NextResetAt.IsZero() || report.NextRetryAt.IsZero() {
		t.Fatalf("catalog=%+v report=%+v", models, report)
	}
	if models[0].NextResetAt.Sub(report.NextRetryAt) > time.Millisecond || report.NextRetryAt.Sub(models[0].NextResetAt) > time.Millisecond {
		t.Fatalf("catalog reset=%s routing reset=%s", models[0].NextResetAt, report.NextRetryAt)
	}
}
