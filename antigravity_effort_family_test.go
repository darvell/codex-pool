package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func neonRegistry() *antigravityModelRegistry {
	registry := &antigravityModelRegistry{accounts: map[string]AntigravityAccountSnapshot{}, known: map[string]bool{}}
	models := map[string]AntigravityModelInfo{"gemini-3-flash": {ID: "gemini-3-flash"}}
	for _, tier := range []string{"low", "medium", "high", "xhigh"} {
		id := "gemini-4-neon-" + tier
		models[id] = AntigravityModelInfo{ID: id, DisplayName: "Gemini 4 Neon (" + strings.ToUpper(tier[:1]) + tier[1:] + ")"}
	}
	registry.ReplaceAccount("a", AntigravityAccountSnapshot{FetchedAt: time.Now(), Models: models})
	return registry
}

func TestAntigravityFamilyResolvesEffortToTier(t *testing.T) {
	registry := neonRegistry()
	cases := map[string]string{
		"":        "antigravity/gemini-4-neon-medium",
		"minimal": "antigravity/gemini-4-neon-low",
		"low":     "antigravity/gemini-4-neon-low",
		"high":    "antigravity/gemini-4-neon-high",
		"xhigh":   "antigravity/gemini-4-neon-xhigh",
		"max":     "antigravity/gemini-4-neon-xhigh",
	}
	for effort, want := range cases {
		if got := registry.resolveEffortTier("antigravity/gemini-4-neon", effort); got != want {
			t.Fatalf("effort %q -> %q, want %q", effort, got, want)
		}
	}
	for _, model := range []string{
		"antigravity/gemini-4-neon-high", "antigravity/gemini-3-flash",
		"antigravity/claude-opus-5-5-high", "gpt-5.5",
	} {
		if got := registry.resolveEffortTier(model, "low"); got != model {
			t.Fatalf("%s rewritten to %s", model, got)
		}
	}
	if canonical, ok := registry.Canonical("antigravity/gemini-4-neon"); !ok || canonical != "gemini-4-neon-medium" {
		t.Fatalf("Canonical(family) = %q, %v", canonical, ok)
	}
}

func TestRequestReasoningEffortShapes(t *testing.T) {
	cases := map[string]string{
		`{"reasoning":{"effort":"xhigh"}}`:                                "xhigh",
		`{"reasoning_effort":"low"}`:                                      "low",
		`{"output_config":{"effort":"high"}}`:                             "high",
		`{"thinking":{"type":"enabled","budget_tokens":32000}}`:           "high",
		`{"generationConfig":{"thinkingConfig":{"thinkingLevel":"low"}}}`: "low",
		`{"generationConfig":{"thinkingConfig":{"thinkingBudget":1024}}}`: "low",
		`{"input":"hi"}`: "",
	}
	for body, want := range cases {
		if got := requestReasoningEffort([]byte(body)); got != want {
			t.Fatalf("%s -> %q, want %q", body, got, want)
		}
	}
}

func TestCollapseAntigravityEffortFamilies(t *testing.T) {
	models := []AntigravityCatalogModel{
		{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3-flash"}},
		{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-4-neon-high", DisplayName: "Gemini 4 Neon (High)"}, SupportingAccounts: 2},
		{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-4-neon-low", DisplayName: "Gemini 4 Neon (Low)"}, SupportingAccounts: 2, AvailableAccounts: 1, AvailableNow: true},
		{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-4-neon-medium", DisplayName: "Gemini 4 Neon (Medium)", MaxTokens: 1048576}, SupportingAccounts: 2},
		{AntigravityModelInfo: AntigravityModelInfo{ID: "solo-high", DisplayName: "Solo (High)"}},
		{AntigravityModelInfo: AntigravityModelInfo{ID: "claude-opus-5-5-low", DisplayName: "Claude Opus 5.5 (Low)"}},
		{AntigravityModelInfo: AntigravityModelInfo{ID: "claude-opus-5-5-medium", DisplayName: "Claude Opus 5.5 (Medium)"}},
		{AntigravityModelInfo: AntigravityModelInfo{ID: "claude-opus-5-5-high", DisplayName: "Claude Opus 5.5 (High)"}},
		{AntigravityModelInfo: AntigravityModelInfo{ID: "claude-opus-5-5-xhigh", DisplayName: "Claude Opus 5.5 (XHigh)"}},
	}
	out := collapseAntigravityEffortFamilies(models)
	var ids []string
	var neon AntigravityCatalogModel
	for _, model := range out {
		ids = append(ids, model.ID)
		if model.ID == "gemini-4-neon" {
			neon = model
		}
	}
	if strings.Join(ids, ",") != "gemini-3-flash,gemini-4-neon,solo-high,claude-opus-5-5-low,claude-opus-5-5-medium,claude-opus-5-5-high,claude-opus-5-5-xhigh" {
		t.Fatalf("listed ids = %v", ids)
	}
	if neon.DisplayName != "Gemini 4 Neon" || neon.MaxTokens != 1048576 || neon.DefaultReasoningLevel != "medium" ||
		strings.Join(neon.ReasoningLevels, ",") != "low,medium,high" || !neon.AvailableNow || neon.AvailableAccounts != 1 {
		t.Fatalf("family entry = %+v", neon)
	}
}

func TestAntigravityFamilyRequestUsesEffortTier(t *testing.T) {
	var upstreamModels []string
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		var envelope struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(body, &envelope)
		upstreamModels = append(upstreamModels, envelope.Model)
		resp := antigravityHTTPResponse(http.StatusOK, antigravitySuccessSSE)
		resp.Header.Set("Content-Type", "text/event-stream")
		return resp, nil
	})
	account := &Account{Type: AccountTypeAntigravity, ID: "a", AccessToken: "a", ProjectID: "p", ModelRateLimits: map[string]time.Time{}, ModelBackoffLevels: map[string]int{}}
	h, _ := testAntigravityHandler(t, transport, account)
	neon := neonRegistry()
	snapshot, _ := neon.AccountSnapshot("a")
	h.pool.antigravityModels.ReplaceAccount("a", snapshot)

	for effort, want := range map[string]string{"high": "gemini-4-neon-high", "low": "gemini-4-neon-low"} {
		body := []byte(`{"model":"antigravity/gemini-4-neon","stream":true,"input":"hi","reasoning":{"effort":"` + effort + `"}}`)
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(string(body)))
		rr := httptest.NewRecorder()
		if !h.handleAntigravityProxy(rr, req, body, "antigravity/gemini-4-neon", "", "user", "", "127.0.0.1", "req") {
			t.Fatal("family model was not routed to Antigravity")
		}
		if rr.Code != http.StatusOK || len(upstreamModels) == 0 || upstreamModels[len(upstreamModels)-1] != want {
			t.Fatalf("effort %s: status=%d upstream=%v, want %s", effort, rr.Code, upstreamModels, want)
		}
	}
}

func TestClaudeOpusEffortStaysOffAntigravity(t *testing.T) {
	models := map[string]AntigravityModelInfo{}
	for _, tier := range []string{"low", "medium", "high"} {
		id := "claude-opus-5-5-" + tier
		models[id] = AntigravityModelInfo{ID: id}
	}
	registry := &antigravityModelRegistry{accounts: map[string]AntigravityAccountSnapshot{}, known: map[string]bool{}}
	registry.ReplaceAccount("a", AntigravityAccountSnapshot{FetchedAt: time.Now(), Models: models})

	if shouldRouteAntigravityModel(registry, "claude-opus-5-5") || shouldRouteAntigravityModel(registry, "claude-opus-5-5-high") {
		t.Fatal("bare Opus routed to Antigravity")
	}
	if !shouldRouteAntigravityModel(registry, "antigravity/claude-opus-5-5") || !shouldRouteAntigravityModel(registry, "antigravity/claude-opus-5-5-high") {
		t.Fatal("prefixed Opus was not routed to Antigravity")
	}
	if got := registry.resolveEffortTier("claude-opus-5-5", "high"); got != "claude-opus-5-5" {
		t.Fatalf("bare resolve = %s", got)
	}
	if got := registry.resolveEffortTier("antigravity/claude-opus-5-5", "high"); got != "antigravity/claude-opus-5-5" {
		t.Fatalf("prefixed resolve = %s", got)
	}
	if got := registry.resolveEffortTier("antigravity/claude-opus-5-5-high", "low"); got != "antigravity/claude-opus-5-5-high" {
		t.Fatalf("tier resolve = %s", got)
	}

	var calls int
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		resp := antigravityHTTPResponse(http.StatusOK, antigravitySuccessSSE)
		resp.Header.Set("Content-Type", "text/event-stream")
		return resp, nil
	})
	account := &Account{Type: AccountTypeAntigravity, ID: "a", AccessToken: "a", ProjectID: "p", ModelRateLimits: map[string]time.Time{}, ModelBackoffLevels: map[string]int{}}
	h, _ := testAntigravityHandler(t, transport, account)
	snapshot, _ := registry.AccountSnapshot("a")
	h.pool.antigravityModels.ReplaceAccount("a", snapshot)

	for _, model := range []string{"claude-opus-5-5", "claude-opus-5-5-high"} {
		body := []byte(`{"model":"` + model + `","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"output_config":{"effort":"high"}}`)
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(body)))
		rr := httptest.NewRecorder()
		if h.handleAntigravityProxy(rr, req, body, model, "", "user", "", "127.0.0.1", "req") {
			t.Fatalf("%s was handled by Antigravity: %d %s", model, rr.Code, rr.Body.String())
		}
	}
	if calls != 0 {
		t.Fatalf("upstream calls = %d", calls)
	}

	canonical, effort := claudeRoutedModel("claude-opus-5-5-high")
	if canonical != "claude-opus-5-5" || effort != "high" {
		t.Fatalf("routed model = %s effort %s", canonical, effort)
	}
	body := ensureClaudeEffort([]byte(`{"model":"claude-opus-5-5-high","messages":[]}`), effort)
	rewritten := rewriteModelInBody(body, canonical)
	if !strings.Contains(string(body), `"effort":"high"`) || rewritten == nil || !strings.Contains(string(rewritten), "claude-opus-5-5") {
		t.Fatalf("effort body = %s rewritten = %s", body, rewritten)
	}
}

func TestCodexCatalogListsAntigravityFamilyWithLevels(t *testing.T) {
	family := collapseAntigravityEffortFamilies([]AntigravityCatalogModel{
		{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-4-neon-low", DisplayName: "Gemini 4 Neon (Low)"}},
		{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-4-neon-medium", DisplayName: "Gemini 4 Neon (Medium)"}},
	})
	out := injectClaudeModels([]byte(`{"models":[]}`), family)
	var catalog struct {
		Models []struct {
			Slug    string `json:"slug"`
			Default string `json:"default_reasoning_level"`
			Levels  []struct {
				Effort string `json:"effort"`
			} `json:"supported_reasoning_levels"`
		} `json:"models"`
	}
	if err := json.Unmarshal(out, &catalog); err != nil {
		t.Fatal(err)
	}
	for _, model := range catalog.Models {
		if model.Slug != "antigravity/gemini-4-neon" {
			continue
		}
		if model.Default != "medium" || len(model.Levels) != 2 || model.Levels[0].Effort != "low" {
			t.Fatalf("catalog entry = %+v", model)
		}
		return
	}
	t.Fatalf("family missing from catalog: %s", out)
}
