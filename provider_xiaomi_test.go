package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestXiaomiModelRoutingUsesLongContextCanonicalModel(t *testing.T) {
	t.Parallel()

	canonical := xiaomiCanonicalModel("mimo-v2.5-pro")
	if canonical != "mimo-v2.5-pro" {
		t.Fatalf("expected canonical Xiaomi model to use the Singapore-accepted 1M model id, got %q", canonical)
	}

	for _, model := range []string{"mimo-v2.5-pro", "MIMO-V2.5-PRO", "mimo-v2.5-pro[1m]", " MIMO-V2.5-PRO[1M] "} {
		if !isXiaomiModel(model) {
			t.Fatalf("expected %q to route to Xiaomi", model)
		}
		if got := xiaomiCanonicalModel(model); got != canonical {
			t.Fatalf("xiaomiCanonicalModel(%q) = %q, want %q", model, got, canonical)
		}
	}

	for _, model := range []string{"mimo-v2.5", "mimo", "mimo-v2.5-pro-preview"} {
		if isXiaomiModel(model) {
			t.Fatalf("did not expect %q to route to Xiaomi", model)
		}
	}
}

func TestXiaomiProviderAuthPathAndUsage(t *testing.T) {
	t.Parallel()

	base, _ := url.Parse("https://token-plan-sgp.xiaomimimo.com/anthropic")
	provider := NewXiaomiProvider(base)
	acc := &Account{Type: AccountTypeXiaomi, AccessToken: "tp-test"}
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	provider.SetAuthHeaders(req, acc)

	if got := req.Header.Get("Authorization"); got != "Bearer tp-test" {
		t.Fatalf("Authorization = %q", got)
	}
	if got := req.Header.Get("X-Api-Key"); got != "" {
		t.Fatalf("X-Api-Key should not be set, got %q", got)
	}
	if provider.MatchesPath("/v1/messages") {
		t.Fatal("Xiaomi should be model-routed, not path-routed")
	}
	if got := provider.UpstreamURL("/v1/messages").String(); got != base.String() {
		t.Fatalf("UpstreamURL = %q, want %q", got, base.String())
	}

	nonStream := provider.ParseUsage(map[string]any{
		"model": "mimo-v2.5-pro[1m]",
		"usage": map[string]any{"input_tokens": float64(12), "output_tokens": float64(3)},
	})
	if nonStream == nil || nonStream.InputTokens != 12 || nonStream.OutputTokens != 3 || nonStream.BillableTokens != 15 || nonStream.Model != "mimo-v2.5-pro[1m]" {
		t.Fatalf("unexpected non-stream usage: %#v", nonStream)
	}

	start := provider.ParseUsage(map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"model": "mimo-v2.5-pro[1m]",
			"usage": map[string]any{"input_tokens": float64(20), "cache_read_input_tokens": float64(4)},
		},
	})
	if start == nil || start.InputTokens != 20 || start.CachedInputTokens != 4 || start.BillableTokens != 16 || start.Model != "mimo-v2.5-pro[1m]" {
		t.Fatalf("unexpected message_start usage: %#v", start)
	}

	delta := provider.ParseUsage(map[string]any{
		"type":  "message_delta",
		"usage": map[string]any{"output_tokens": float64(7)},
	})
	if delta == nil || delta.OutputTokens != 7 || delta.BillableTokens != 7 {
		t.Fatalf("unexpected message_delta usage: %#v", delta)
	}
}

func TestModelRouteOverrideXiaomiUsesConfiguredBaseAndCanonicalModel(t *testing.T) {
	t.Parallel()

	xiaomiBase, _ := url.Parse("https://token-plan-sgp.xiaomimimo.com/anthropic")
	handler := &proxyHandler{
		registry: NewProviderRegistry(
			&CodexProvider{},
			&ClaudeProvider{},
			&GeminiProvider{},
			NewXiaomiProvider(xiaomiBase),
		),
	}

	for _, model := range []string{"mimo-v2.5-pro", "mimo-v2.5-pro[1m]"} {
		provider, base, rewritten := handler.modelRouteOverride("/v1/messages", model, []byte(`{"model":"`+model+`"}`))
		if provider == nil {
			t.Fatalf("expected override provider for %q", model)
		}
		if provider.Type() != AccountTypeXiaomi {
			t.Fatalf("provider type = %s, want Xiaomi", provider.Type())
		}
		if base == nil || base.String() != xiaomiBase.String() {
			t.Fatalf("base = %v, want %s", base, xiaomiBase)
		}
		var body map[string]any
		if err := json.Unmarshal(rewritten, &body); err != nil {
			t.Fatalf("unmarshal rewritten body: %v", err)
		}
		if got := body["model"]; got != xiaomiCanonicalModel(model) {
			t.Fatalf("rewritten model = %v, want %q", got, xiaomiCanonicalModel(model))
		}
	}
}

func TestFindTopLevelJSONStringFieldFindsOnlyTopLevelModel(t *testing.T) {
	t.Parallel()

	body := []byte(`{"messages":[{"model":"nested"}],"model":"mimo-v2.5-pro[1m]","max_tokens":1}`)
	value, start, end, ok := findTopLevelJSONStringField(body, "model")
	if !ok || value != "mimo-v2.5-pro[1m]" {
		t.Fatalf("field = %q ok=%v, want top-level Xiaomi model", value, ok)
	}
	rewritten, _, err := replaceJSONStringToken(body, start, end, "mimo-v2.5-pro")
	if err != nil {
		t.Fatal(err)
	}
	var rewrittenBody map[string]any
	if err := json.Unmarshal(rewritten, &rewrittenBody); err != nil {
		t.Fatalf("rewritten token produced invalid JSON: %v: %s", err, rewritten)
	}
	if rewrittenBody["model"] != "mimo-v2.5-pro" {
		t.Fatalf("rewritten model = %v", rewrittenBody["model"])
	}

	if value, _, _, ok := findTopLevelJSONStringField([]byte(`{"messages":[{"model":"nested"}],"max_tokens":1}`), "model"); ok || value != "" {
		t.Fatalf("unexpected nested model match: value=%q ok=%v", value, ok)
	}
}

func TestProxyRequestStreamsLargeXiaomiBodyAfterModelPeek(t *testing.T) {
	for _, model := range []string{"mimo-v2.5-pro", "mimo-v2.5-pro[1m]"} {
		t.Run(model, func(t *testing.T) {
			t.Setenv("POOL_JWT_SECRET", "test-secret")

			xiaomiBase, _ := url.Parse("https://token-plan-sgp.xiaomimimo.com/anthropic")
			claudeBase, _ := url.Parse("https://api.anthropic.com")
			codexBase, _ := url.Parse("https://chatgpt.com/backend-api/codex")
			acc := &Account{Type: AccountTypeXiaomi, ID: "xiaomi", AccessToken: "tp-upstream", PlanType: "xiaomi"}

			var upstreamURL string
			var upstreamAuth string
			var upstreamAPIKey string
			var upstreamBody map[string]any
			var upstreamContentLength int64

			h := &proxyHandler{
				cfg:     &config{maxAttempts: 1, maxInMemoryBodyBytes: 16 * 1024 * 1024},
				pool:    newPoolState([]*Account{acc}, false),
				metrics: newMetrics(),
				recent:  newRecentErrors(5),
				registry: NewProviderRegistry(
					NewCodexProvider(codexBase, codexBase, nil),
					NewClaudeProvider(claudeBase),
					NewGeminiProvider(claudeBase, claudeBase),
					NewXiaomiProvider(xiaomiBase),
				),
				transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					upstreamURL = req.URL.String()
					upstreamAuth = req.Header.Get("Authorization")
					upstreamAPIKey = req.Header.Get("X-Api-Key")
					upstreamContentLength = req.ContentLength
					body, _ := io.ReadAll(req.Body)
					_ = json.Unmarshal(body, &upstreamBody)
					return &http.Response{
						StatusCode: http.StatusOK,
						Status:     "200 OK",
						Header:     http.Header{"Content-Type": []string{"application/json"}},
						Body:       io.NopCloser(strings.NewReader(`{"type":"message","role":"assistant","model":"mimo-v2.5-pro","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`)),
					}, nil
				}),
			}

			largeContent := strings.Repeat("x", 4096)
			reqBody := []byte(`{"model":"` + model + `","max_tokens":32,"messages":[{"role":"user","content":"` + largeContent + `"}]}`)
			req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("anthropic-version", ccAnthropicVersion)
			req.Header.Set("X-Api-Key", generateClaudePoolToken("test-secret", "xiaomi-user"))
			rr := httptest.NewRecorder()

			h.proxyRequest(rr, req, "req-xiaomi-streamed")

			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
			}
			if !strings.HasPrefix(upstreamURL, "https://token-plan-sgp.xiaomimimo.com/anthropic/v1/messages") {
				t.Fatalf("upstream URL = %q", upstreamURL)
			}
			if upstreamAuth != "Bearer tp-upstream" {
				t.Fatalf("Authorization = %q", upstreamAuth)
			}
			if upstreamAPIKey != "" {
				t.Fatalf("X-Api-Key leaked upstream: %q", upstreamAPIKey)
			}
			if got := upstreamBody["model"]; got != xiaomiCanonicalModel(model) {
				t.Fatalf("upstream model = %v, want %q", got, xiaomiCanonicalModel(model))
			}
			messages, _ := upstreamBody["messages"].([]any)
			msg, _ := messages[0].(map[string]any)
			if msg["content"] != largeContent {
				t.Fatal("large streamed message content was not preserved")
			}
			if upstreamContentLength != int64(len(reqBody)) && model == "mimo-v2.5-pro" {
				t.Fatalf("ContentLength = %d, want %d", upstreamContentLength, len(reqBody))
			}
			if model == "mimo-v2.5-pro[1m]" && upstreamContentLength != int64(len(reqBody)-len("[1m]")) {
				t.Fatalf("rewritten ContentLength = %d, want %d", upstreamContentLength, len(reqBody)-len("[1m]"))
			}
		})
	}
}

func TestProxyRequestRoutesXiaomiModelsToSingaporeLongContext(t *testing.T) {
	for _, model := range []string{"mimo-v2.5-pro", "mimo-v2.5-pro[1m]"} {
		t.Run(model, func(t *testing.T) {
			t.Setenv("POOL_JWT_SECRET", "test-secret")

			xiaomiBase, _ := url.Parse("https://token-plan-sgp.xiaomimimo.com/anthropic")
			claudeBase, _ := url.Parse("https://api.anthropic.com")
			codexBase, _ := url.Parse("https://chatgpt.com/backend-api/codex")
			acc := &Account{Type: AccountTypeXiaomi, ID: "xiaomi", AccessToken: "tp-upstream", PlanType: "xiaomi"}

			var upstreamURL string
			var upstreamAuth string
			var upstreamAPIKey string
			var upstreamVersion string
			var upstreamBody map[string]any

			h := &proxyHandler{
				cfg:     &config{maxAttempts: 1, maxInMemoryBodyBytes: 4096},
				pool:    newPoolState([]*Account{acc}, false),
				metrics: newMetrics(),
				recent:  newRecentErrors(5),
				registry: NewProviderRegistry(
					NewCodexProvider(codexBase, codexBase, nil),
					NewClaudeProvider(claudeBase),
					NewGeminiProvider(claudeBase, claudeBase),
					NewXiaomiProvider(xiaomiBase),
				),
				transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					upstreamURL = req.URL.String()
					upstreamAuth = req.Header.Get("Authorization")
					upstreamAPIKey = req.Header.Get("X-Api-Key")
					upstreamVersion = req.Header.Get("anthropic-version")
					body, _ := io.ReadAll(req.Body)
					_ = json.Unmarshal(body, &upstreamBody)
					return &http.Response{
						StatusCode: http.StatusOK,
						Status:     "200 OK",
						Header:     http.Header{"Content-Type": []string{"application/json"}},
						Body:       io.NopCloser(strings.NewReader(`{"type":"message","role":"assistant","model":"mimo-v2.5-pro[1m]","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`)),
					}, nil
				}),
			}

			reqBody := []byte(`{"model":"` + model + `","max_tokens":32,"messages":[{"role":"user","content":"hi"}]}`)
			req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("anthropic-version", ccAnthropicVersion)
			req.Header.Set("X-Api-Key", generateClaudePoolToken("test-secret", "xiaomi-user"))
			rr := httptest.NewRecorder()

			h.proxyRequest(rr, req, "req-xiaomi")

			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
			}
			if !strings.HasPrefix(upstreamURL, "https://token-plan-sgp.xiaomimimo.com/anthropic/v1/messages") {
				t.Fatalf("upstream URL = %q", upstreamURL)
			}
			if upstreamAuth != "Bearer tp-upstream" {
				t.Fatalf("Authorization = %q", upstreamAuth)
			}
			if upstreamAPIKey != "" {
				t.Fatalf("X-Api-Key leaked upstream: %q", upstreamAPIKey)
			}
			if upstreamVersion == "" {
				t.Fatal("anthropic-version was not forwarded")
			}
			if got := upstreamBody["model"]; got != xiaomiCanonicalModel(model) {
				t.Fatalf("upstream model = %v, want %q", got, xiaomiCanonicalModel(model))
			}
		})
	}
}

func TestLoadPoolLoadsXiaomiAccounts(t *testing.T) {
	t.Parallel()

	poolDir := t.TempDir()
	xiaomiDir := filepath.Join(poolDir, "xiaomi")
	if err := os.MkdirAll(xiaomiDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(xiaomiDir, "one.json"), []byte(`{"api_key":"tp-one"}`), 0600); err != nil {
		t.Fatal(err)
	}

	xiaomiBase, _ := url.Parse("https://token-plan-sgp.xiaomimimo.com/anthropic")
	registry := NewProviderRegistry(&CodexProvider{}, &ClaudeProvider{}, &GeminiProvider{}, NewXiaomiProvider(xiaomiBase))
	accounts, err := loadPool(poolDir, registry)
	if err != nil {
		t.Fatalf("loadPool: %v", err)
	}
	if len(accounts) != 1 {
		t.Fatalf("loaded %d accounts, want 1", len(accounts))
	}
	if accounts[0].Type != AccountTypeXiaomi || accounts[0].ID != "one" || accounts[0].AccessToken != "tp-one" || accounts[0].PlanType != "xiaomi" {
		t.Fatalf("unexpected Xiaomi account: %#v", accounts[0])
	}
}

func TestXiaomiUsagePollerSkipsGenericFetch(t *testing.T) {
	t.Parallel()

	poolDir := t.TempDir()
	xiaomiDir := filepath.Join(poolDir, "xiaomi")
	if err := os.MkdirAll(xiaomiDir, 0755); err != nil {
		t.Fatal(err)
	}
	accountFile := filepath.Join(xiaomiDir, "one.json")
	if err := os.WriteFile(accountFile, []byte(`{"api_key":"tp-one"}`), 0600); err != nil {
		t.Fatal(err)
	}

	acc := &Account{
		Type:        AccountTypeXiaomi,
		ID:          "one",
		File:        accountFile,
		AccessToken: "tp-one",
		PlanType:    "xiaomi",
	}
	calls := 0
	h := &proxyHandler{
		cfg:  &config{usageRefresh: time.Minute},
		pool: newPoolState([]*Account{acc}, false),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			t.Fatalf("Xiaomi usage poller should not call transport, got %s %s", req.Method, req.URL.String())
			return nil, nil
		}),
	}

	h.pollUpstreamUsage()

	if calls != 0 {
		t.Fatalf("transport calls = %d, want 0", calls)
	}
	if acc.Dead {
		t.Fatal("Xiaomi account was marked dead by usage poller")
	}
	data, err := os.ReadFile(accountFile)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if _, ok := saved["dead"]; ok {
		t.Fatalf("usage poller persisted dead flag for Xiaomi account: %s", data)
	}
}

func TestXiaomiAdminAddValidatesAndSavesAccount(t *testing.T) {
	t.Parallel()

	poolDir := t.TempDir()
	xiaomiBase, _ := url.Parse("https://token-plan-sgp.xiaomimimo.com/anthropic")
	validationCalled := false
	h := &proxyHandler{
		cfg:     &config{poolDir: poolDir, xiaomiBase: xiaomiBase},
		pool:    newPoolState(nil, false),
		metrics: newMetrics(),
		recent:  newRecentErrors(5),
		registry: NewProviderRegistry(
			&CodexProvider{},
			&ClaudeProvider{},
			&GeminiProvider{},
			NewXiaomiProvider(xiaomiBase),
		),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			validationCalled = true
			if req.URL.String() != "https://token-plan-sgp.xiaomimimo.com/anthropic/v1/messages" {
				t.Fatalf("validation URL = %q", req.URL.String())
			}
			if req.Header.Get("Authorization") != "Bearer tp-valid" {
				t.Fatalf("validation auth = %q", req.Header.Get("Authorization"))
			}
			var body map[string]any
			payload, _ := io.ReadAll(req.Body)
			_ = json.Unmarshal(payload, &body)
			if body["model"] != xiaomiCanonicalModel("mimo-v2.5-pro") {
				t.Fatalf("validation model = %v", body["model"])
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/xiaomi/add", strings.NewReader(`{"api_key":"tp-valid"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleXiaomiAdd(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if !validationCalled {
		t.Fatal("validation was not called")
	}
	entries, err := os.ReadDir(filepath.Join(poolDir, "xiaomi"))
	if err != nil {
		t.Fatalf("read xiaomi pool dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("saved %d Xiaomi files, want 1", len(entries))
	}
	if h.pool.countByType(AccountTypeXiaomi) != 1 {
		t.Fatalf("pool Xiaomi count = %d, want 1", h.pool.countByType(AccountTypeXiaomi))
	}
}

func TestXiaomiAdminRejectsUnauthorizedKeyWithoutSaving(t *testing.T) {
	t.Parallel()

	poolDir := t.TempDir()
	xiaomiBase, _ := url.Parse("https://token-plan-sgp.xiaomimimo.com/anthropic")
	h := &proxyHandler{
		cfg:      &config{poolDir: poolDir, xiaomiBase: xiaomiBase},
		pool:     newPoolState(nil, false),
		registry: NewProviderRegistry(&CodexProvider{}, &ClaudeProvider{}, &GeminiProvider{}, NewXiaomiProvider(xiaomiBase)),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Status:     "401 Unauthorized",
				Body:       io.NopCloser(strings.NewReader(`{"error":"bad key"}`)),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/xiaomi/add", strings.NewReader(`{"api_key":"tp-bad"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleXiaomiAdd(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(poolDir, "xiaomi")); !os.IsNotExist(err) {
		t.Fatalf("xiaomi pool dir should not exist after rejected key, err=%v", err)
	}
}

func TestFriendLandingIncludesXiaomiKeyManagement(t *testing.T) {
	t.Parallel()

	page, err := os.ReadFile(filepath.Join("templates", "friend_landing.html"))
	if err != nil {
		t.Fatalf("read friend landing template: %v", err)
	}
	html := string(page)
	for _, needle := range []string{
		`id="xiaomi-api-key"`,
		`addXiaomiKey()`,
		`/admin/xiaomi/add`,
		`id="xiaomi-accounts-list"`,
		`mimo-v2.5-pro[1m]`,
	} {
		if !strings.Contains(html, needle) {
			t.Fatalf("friend landing page missing %q", needle)
		}
	}
}

func TestXiaomiAdminReportsNonAuthValidationFailureWithoutSaving(t *testing.T) {
	t.Parallel()

	poolDir := t.TempDir()
	xiaomiBase, _ := url.Parse("https://token-plan-sgp.xiaomimimo.com/anthropic")
	h := &proxyHandler{
		cfg:      &config{poolDir: poolDir, xiaomiBase: xiaomiBase},
		pool:     newPoolState(nil, false),
		registry: NewProviderRegistry(&CodexProvider{}, &ClaudeProvider{}, &GeminiProvider{}, NewXiaomiProvider(xiaomiBase)),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Status:     "400 Bad Request",
				Body:       io.NopCloser(strings.NewReader(`{"error":"validation"}`)),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/xiaomi/add", strings.NewReader(`{"api_key":"tp-validish"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleXiaomiAdd(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(poolDir, "xiaomi")); !os.IsNotExist(err) {
		t.Fatalf("xiaomi pool dir should not exist after validation failure, err=%v", err)
	}
}
