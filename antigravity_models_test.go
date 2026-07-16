package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseAntigravityModelSnapshotKeepsFullInventoryAndCapabilities(t *testing.T) {
	remaining := 0.42
	body := []byte(`{
		"models": {
			"gemini-new": {
				"displayName": "Gemini New",
				"maxTokens": 1000000,
				"maxOutputTokens": 65536,
				"supportsImages": true,
				"supportsThinking": true,
				"thinkingBudget": 24576,
				"recommended": false,
				"supportedMimeTypes": {"image/png": true, "audio/wav": false},
				"quotaInfo": {"remainingFraction": 0.42, "resetTime": "2026-07-15T00:00:00Z"},
				"futureCapability": {"enabled": true}
			}
		},
		"webSearchModelIds": ["gemini-new"],
		"deprecatedModelIds": {"gemini-old": {"newModelId": "gemini-new"}},
		"futureTopLevel": true
	}`)
	snapshot, err := parseAntigravityModelSnapshot(body, time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	model, ok := snapshot.Models["gemini-new"]
	if !ok {
		t.Fatal("full models map entry was not imported")
	}
	if model.DisplayName != "Gemini New" || model.MaxTokens != 1000000 || model.MaxOutputTokens != 65536 || !model.SupportsImages || !model.SupportsThinking || !model.WebSearch {
		t.Fatalf("capabilities were not preserved: %#v", model)
	}
	if model.Quota.RemainingFraction == nil || *model.Quota.RemainingFraction != remaining {
		t.Fatalf("quota was not parsed: %#v", model.Quota)
	}
	if _, ok := model.Raw["futureCapability"]; !ok {
		t.Fatal("unknown model fields must remain available for schema-drift diagnostics")
	}
	if _, ok := snapshot.Raw["futureTopLevel"]; !ok {
		t.Fatal("unknown top-level fields must remain available for schema-drift diagnostics")
	}
	if snapshot.Deprecated["gemini-old"] != "gemini-new" {
		t.Fatalf("deprecated alias missing: %#v", snapshot.Deprecated)
	}
	if _, err := json.Marshal(snapshot); err != nil {
		t.Fatalf("snapshot is not durable JSON: %v", err)
	}
}

func TestParseAntigravityModelSnapshotHidesInternalAndRetiredModels(t *testing.T) {
	body := []byte(`{"models":{
		"chat_20706":{},
		"tab_flash_lite_preview":{},
		"gemini-2.5-flash-thinking":{"displayName":"wrong"},
		"gemini-2.5-pro":{"displayName":"Gemini 2.5 Pro"},
		"gemini-2.5-flash":{"displayName":"Gemini 3.1 Flash Lite"},
		"gemini-2.5-flash-lite":{"displayName":"Gemini 3.1 Flash Lite"},
		"gemini-pro-agent":{"displayName":"Gemini 3.1 Pro (High)"},
		"gemini-3.1-pro-high":{"displayName":"Gemini 3.1 Pro (High)"}
	},"deprecatedModelIds":{"gemini-3.1-pro-high":{"newModelId":"gemini-pro-agent"}}}`)
	snapshot, err := parseAntigravityModelSnapshot(body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"chat_20706", "tab_flash_lite_preview", "gemini-2.5-flash-thinking", "gemini-2.5-pro"} {
		if _, exists := snapshot.Models[id]; exists {
			t.Fatalf("internal or retired model %q was advertised", id)
		}
	}
	if snapshot.Models["gemini-2.5-flash"].DisplayName != "Gemini 2.5 Flash" || snapshot.Models["gemini-2.5-flash-lite"].DisplayName != "Gemini 2.5 Flash Lite" {
		t.Fatalf("legacy display names were not corrected: %#v", snapshot.Models)
	}
	registry := &antigravityModelRegistry{accounts: make(map[string]AntigravityAccountSnapshot)}
	registry.ReplaceAccount("account", snapshot)
	models := registry.Models(nil)
	for _, model := range models {
		if model.ID == "gemini-3.1-pro-high" {
			t.Fatal("deprecated model was emitted beside its replacement")
		}
	}
}

func TestFetchAntigravityModelsUsesDailyThenProductionAndEmptyBody(t *testing.T) {
	daily, _ := url.Parse("https://daily.example.test")
	production, _ := url.Parse("https://prod.example.test")
	var hosts []string
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		hosts = append(hosts, req.URL.Host)
		body, _ := io.ReadAll(req.Body)
		if string(body) != `{}` {
			t.Fatalf("request body = %s", body)
		}
		if req.URL.Host == daily.Host {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Status: "503 Service Unavailable", Body: io.NopCloser(strings.NewReader("unavailable")), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"models":{"gemini-live":{"displayName":"Gemini Live"}}}`)), Header: make(http.Header)}, nil
	})
	snapshot, err := fetchAntigravityModels(context.Background(), transport, &Account{AccessToken: "token"}, daily, production)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(hosts, ",") != "daily.example.test,prod.example.test" || snapshot.Models["gemini-live"].DisplayName != "Gemini Live" {
		t.Fatalf("hosts=%v snapshot=%#v", hosts, snapshot)
	}
}

func TestAntigravityCanonicalModelUsesForcedPrefixAndDeprecatedAlias(t *testing.T) {
	registry := &antigravityModelRegistry{accounts: make(map[string]AntigravityAccountSnapshot)}
	registry.ReplaceAccount("account", AntigravityAccountSnapshot{
		FetchedAt:  time.Now(),
		Models:     map[string]AntigravityModelInfo{"gemini-live": {ID: "gemini-live"}},
		Deprecated: map[string]string{"gemini-old": "gemini-live"},
	})
	if got, ok := registry.Canonical("antigravity/gemini-live"); !ok || got != "gemini-live" {
		t.Fatalf("forced name resolved to %q, %v", got, ok)
	}
	if got, ok := registry.Canonical("gemini-old"); !ok || got != "gemini-live" {
		t.Fatalf("deprecated name resolved to %q, %v", got, ok)
	}
}

func TestAntigravityModelCooldownDoesNotBlockAnotherModel(t *testing.T) {
	account := &Account{Type: AccountTypeAntigravity, ID: "ag", ModelRateLimits: map[string]time.Time{"gemini-a": time.Now().Add(time.Hour)}}
	pool := newPoolState([]*Account{account}, false)
	antigravityModels.ReplaceAccount(account.ID, AntigravityAccountSnapshot{FetchedAt: time.Now(), Models: map[string]AntigravityModelInfo{"gemini-a": {ID: "gemini-a"}, "gemini-b": {ID: "gemini-b"}}})
	if got := pool.candidateForAntigravityModel("", nil, "gemini-a", ""); got != nil {
		t.Fatalf("cooling model selected account %#v", got)
	}
	if got := pool.candidateForAntigravityModel("", nil, "gemini-b", ""); got != account {
		t.Fatalf("unlimited model should use the account, got %#v", got)
	}
}
