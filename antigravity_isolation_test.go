package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestAntigravityPoolReloadIsolation(t *testing.T) {
	t.Parallel()

	type upstreamCall struct {
		Model string `json:"model"`
		Token string
	}
	calls := make(chan upstreamCall, 8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var call upstreamCall
		if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		call.Token = r.Header.Get("Authorization")
		calls <- call
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, antigravitySuccessSSE)
	}))
	defer upstream.Close()
	base, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	provider := NewAntigravityProvider(base, base)
	registry := NewProviderRegistry(nil, nil, nil, provider)
	makeAccount := func(dir, model, token string) *Account {
		return &Account{
			Type: AccountTypeAntigravity, ID: "same", File: filepath.Join(dir, "antigravity", "same.json"),
			AccessToken: token, ProjectID: "project", ExpiresAt: time.Now().Add(24 * time.Hour),
			antigravitySnapshot: &AntigravityAccountSnapshot{
				FetchedAt: time.Now().UTC(),
				Models: map[string]AntigravityModelInfo{
					model: {ID: model, DisplayName: "Discovered " + model, MaxTokens: 123456, MaxOutputTokens: 8192, SupportsImages: true, SupportsThinking: true, SupportsTools: true},
				},
				Deprecated: map[string]string{"gemini-shared-alias": model},
			},
		}
	}
	loadAccounts := func(dir string) []*Account {
		accounts, err := loadPool(dir, registry)
		if err != nil {
			t.Fatal(err)
		}
		if len(accounts) != 1 {
			t.Fatalf("loaded %d accounts, want 1", len(accounts))
		}
		return accounts
	}
	makeHandler := func(dir, model, token string) *proxyHandler {
		if err := saveAntigravityAccount(makeAccount(dir, model, token)); err != nil {
			t.Fatal(err)
		}
		return &proxyHandler{
			cfg: &config{maxAttempts: 1}, pool: newPoolState(loadAccounts(dir), false), registry: registry,
			transport: upstream.Client().Transport, recent: newRecentErrors(10), metrics: newMetrics(),
		}
	}
	exports := func(pool *poolState) map[string][]byte {
		t.Helper()
		models := httptest.NewRecorder()
		servePoolModels(models, pool)
		pi, err := generatePiModelsJSON("https://pool.test", "codex-key", "claude-key", pool)
		if err != nil {
			t.Fatal(err)
		}
		cute, err := generateCuteCodeSettingsJSON("https://pool.test", "pool-key", pool)
		if err != nil {
			t.Fatal(err)
		}
		return map[string][]byte{
			"public": models.Body.Bytes(), "pi": pi, "cute": cute,
			"codex": injectClaudeModels([]byte(`{"models":[]}`), antigravityCatalog(pool)),
		}
	}
	assertPool := func(h *proxyHandler, model, token string) {
		t.Helper()
		catalog := antigravityCatalog(h.pool)
		if len(catalog) != 1 || catalog[0].ID != model || catalog[0].DisplayName != "Discovered "+model || catalog[0].MaxTokens != 123456 || !catalog[0].AvailableNow || catalog[0].Stale {
			t.Fatalf("pool catalog = %+v", catalog)
		}
		if !reflect.DeepEqual(catalog[0].Aliases, []string{"antigravity/" + model, "gemini-shared-alias"}) {
			t.Fatalf("aliases = %v", catalog[0].Aliases)
		}
		for name, data := range exports(h.pool) {
			if !bytes.Contains(data, []byte("antigravity/"+model)) || !bytes.Contains(data, []byte("Discovered "+model)) || !bytes.Contains(data, []byte("123456")) {
				t.Fatalf("%s export omitted discovered metadata: %s", name, data)
			}
		}
		req, body := antigravityProxyRequest("gemini-shared-alias")
		ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
		defer cancel()
		recorder := httptest.NewRecorder()
		if !h.handleAntigravityProxy(recorder, req.WithContext(ctx), body, "gemini-shared-alias", "", "user", "origin", "", "request") || recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "ok") {
			t.Fatalf("routed response = %d %s", recorder.Code, recorder.Body.String())
		}
		select {
		case call := <-calls:
			if call.Model != model || call.Token != "Bearer "+token {
				t.Fatalf("upstream call = %+v, want model=%s token=%s", call, model, token)
			}
		case <-ctx.Done():
			t.Fatal("request did not arrive at loopback upstream")
		}
	}

	dirA, dirB := t.TempDir(), t.TempDir()
	a := makeHandler(dirA, "gemini-pool-a", "token-a")
	b := makeHandler(dirB, "gemini-pool-b", "token-b")
	assertPool(a, "gemini-pool-a", "token-a")
	assertPool(b, "gemini-pool-b", "token-b")
	beforeB := exports(b.pool)
	generationB, _ := b.pool.generationAndAccounts()

	if err := saveAntigravityAccount(makeAccount(dirA, "gemini-pool-a-reloaded", "token-a-new")); err != nil {
		t.Fatal(err)
	}
	if err := a.pool.replaceWithAntigravityRegistry(loadAccounts(dirA)); err != nil {
		t.Fatal(err)
	}
	assertPool(a, "gemini-pool-a-reloaded", "token-a-new")
	assertPool(b, "gemini-pool-b", "token-b")
	if generation, _ := b.pool.generationAndAccounts(); generation != generationB {
		t.Fatalf("other pool generation changed: %d -> %d", generationB, generation)
	}
	for name, after := range exports(b.pool) {
		if !bytes.Equal(beforeB[name], after) {
			t.Fatalf("pool A reload changed pool B %s export", name)
		}
	}
	if isAntigravityModel(&b.pool.antigravityModels, "gemini-pool-a-reloaded") {
		t.Fatal("pool B routes a model discovered only by pool A")
	}
	if len(antigravityCatalog(nil)) != 0 || len(preparePiModels("https://pool.test", "key", "key", nil).Providers["antigravity"].Models) != 0 {
		t.Fatal("an absent pool consumed another pool's metadata")
	}
}

func TestAntigravitySnapshotRetainedOnSave(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, ":fetchAvailableModels") {
			_, _ = io.WriteString(w, `{"models":{"gemini-updated":{"displayName":"Updated Gemini","maxTokens":234567,"maxOutputTokens":4096,"supportsImages":true}},"deprecatedModelIds":{"gemini-old":{"newModelId":"gemini-updated"}}}`)
			return
		}
		_, _ = io.WriteString(w, `{"groups":[{"displayName":"Gemini Models","buckets":[{"bucketId":"gemini-5h","window":"5h","remainingFraction":0.75}]}]}`)
	}))
	defer upstream.Close()
	base, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	provider := NewAntigravityProvider(base, base)
	registry := NewProviderRegistry(nil, nil, nil, provider)
	dir := t.TempDir()
	account := &Account{
		Type: AccountTypeAntigravity, ID: "same", File: filepath.Join(dir, "antigravity", "same.json"),
		AccessToken: "token", RefreshToken: "refresh", ProjectID: "project",
		antigravitySnapshot: &AntigravityAccountSnapshot{FetchedAt: time.Now().UTC(), Models: map[string]AntigravityModelInfo{"gemini-original": {ID: "gemini-original"}}},
	}
	if err := saveAntigravityAccount(account); err != nil {
		t.Fatal(err)
	}
	pool := newPoolState([]*Account{account}, false)
	h := &proxyHandler{pool: pool, transport: upstream.Client().Transport}
	generation, _ := pool.generationAndAccounts()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.syncAntigravityModelsGuarded(ctx, generation, account, base, base); err != nil {
		t.Fatal(err)
	}
	want, ok := pool.antigravityModels.AccountSnapshot(account.ID)
	if !ok || want.Models["gemini-updated"].MaxTokens != 234567 || want.Deprecated["gemini-old"] != "gemini-updated" || want.Quota == nil {
		t.Fatalf("discovery snapshot = %+v", want)
	}
	account.mu.Lock()
	retained := account.antigravitySnapshot
	account.mu.Unlock()
	if retained == nil || !reflect.DeepEqual(*retained, want) {
		t.Fatalf("retained snapshot = %+v, want %+v", retained, want)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	assertSnapshot := func(snapshot *AntigravityAccountSnapshot) {
		t.Helper()
		actual, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, wantJSON) {
			t.Fatalf("saved snapshot = %s, want %s", actual, wantJSON)
		}
	}

	pool.replace(nil)
	account.mu.Lock()
	account.Disabled = true
	account.mu.Unlock()
	if err := provider.RefreshToken(ctx, account, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return antigravityHTTPResponse(http.StatusOK, `{"access_token":"refreshed-token","expires_in":3600}`), nil
	})); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadPool(dir, registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || !loaded[0].Disabled || loaded[0].AccessToken != "refreshed-token" {
		t.Fatalf("reloaded account = %+v", loaded)
	}
	assertSnapshot(loaded[0].antigravitySnapshot)
	if err := pool.replaceWithAntigravityRegistry(loaded); err != nil {
		t.Fatal(err)
	}
	models := antigravityCatalog(pool)
	if len(models) != 1 || models[0].ID != "gemini-updated" || models[0].MaxTokens != 234567 || models[0].AvailableNow || models[0].Stale {
		t.Fatalf("reloaded catalog = %+v", models)
	}
	raw, err := os.ReadFile(account.File)
	if err != nil {
		t.Fatal(err)
	}
	var saved AntigravityAuthJSON
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	assertSnapshot(saved.ModelSnapshot)
}

func TestAntigravityPoolFallbackCatalog(t *testing.T) {
	t.Parallel()

	pool := newPoolState([]*Account{{Type: AccountTypeAntigravity, ID: "cold"}}, false)
	want := make([]AntigravityCatalogModel, 0, len(antigravityFallbackModels))
	for _, fallback := range antigravityFallbackModels {
		fallback.Stale = true
		fallback.Aliases = []string{"antigravity/" + fallback.ID}
		want = append(want, fallback)
	}
	sort.Slice(want, func(i, j int) bool { return want[i].ID < want[j].ID })
	if got := antigravityCatalog(pool); !reflect.DeepEqual(got, want) {
		t.Fatalf("cold-start catalog = %+v, want %+v", got, want)
	}
	if got := pool.antigravityModels.Models(nil); !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata-only catalog = %+v, want %+v", got, want)
	}
	pool.replace(nil)
	if got := antigravityCatalog(pool); len(got) != 0 {
		t.Fatalf("removed account retained fallback catalog: %+v", got)
	}
}
