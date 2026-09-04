package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseProviderModelsReadsSlugWhenIDMissing(t *testing.T) {
	body := []byte(`{"models":[{"slug":"gpt-daybreak-blue-latest","display_name":"Daybreak Blue"}]}`)
	models, err := parseProviderModels(body)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := models["gpt-daybreak-blue-latest"]; !ok {
		t.Fatalf("models = %#v", models)
	}
}

func TestCodexModelsURLUsesDesktopClientVersion(t *testing.T) {
	wham, _ := url.Parse("https://chatgpt.com/backend-api")
	target, ok := providerModelsURL(NewCodexProvider(wham, wham, nil))
	if !ok {
		t.Fatal("expected Codex model discovery URL")
	}
	got := target.Query().Get("client_version")
	want := currentCodexFingerprint().AppVersion
	if got != want {
		t.Fatalf("client_version = %q, want desktop app version %q", got, want)
	}
}

func TestSyncCodexModelsSetsCyberFromDaybreak(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cont.json")
	if err := os.WriteFile(path, []byte(`{"tokens":{"access_token":"a","refresh_token":"r"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	wham, _ := url.Parse("https://chatgpt.com/backend-api")
	codex := NewCodexProvider(wham, wham, nil)
	registry := &ProviderRegistry{byType: map[AccountType]Provider{AccountTypeCodex: codex}}
	account := &Account{ID: "cont", Type: AccountTypeCodex, File: path, AccessToken: "a"}
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Query().Get("client_version") != currentCodexFingerprint().AppVersion {
			t.Fatalf("client_version = %q", req.URL.Query().Get("client_version"))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"models":[{"slug":"gpt-daybreak-blue-latest","display_name":"Daybreak Blue"}]}`)),
			Header:     make(http.Header),
		}, nil
	})

	if err := syncProviderModels(context.Background(), transport, registry, account); err != nil {
		t.Fatal(err)
	}
	if !account.CyberAccess {
		t.Fatal("daybreak entitlement should mark the account cyber")
	}

	transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"models":[{"slug":"gpt-5.5","display_name":"GPT-5.5"}]}`)),
			Header:     make(http.Header),
		}, nil
	})
	if err := syncProviderModels(context.Background(), transport, registry, account); err != nil {
		t.Fatal(err)
	}
	if account.CyberAccess {
		t.Fatal("losing daybreak should clear cyber")
	}
}

func TestParseProviderModelsPreservesCapabilities(t *testing.T) {
	body := []byte(`{"data":[
		{"id":"gpt-daybreak-blue-latest","display_name":"GPT Daybreak Blue","context_window":372000,"max_output_tokens":128000},
		{"id":"k3-256k","display_name":"K3-256k","context_length":262144,"supports_reasoning":true,"supports_image_in":true,"supports_video_in":false}
	]}`)

	models, err := parseProviderModels(body)
	if err != nil {
		t.Fatal(err)
	}
	daybreak := models["gpt-daybreak-blue-latest"]
	if daybreak.DisplayName != "GPT Daybreak Blue" || daybreak.ContextWindow != 372000 || daybreak.MaxOutputTokens != 128000 {
		t.Fatalf("daybreak metadata = %#v", daybreak)
	}
	k3 := models["k3-256k"]
	if !k3.Reasoning || !containsString(k3.Modalities, "image") || containsString(k3.Modalities, "video") {
		t.Fatalf("K3-256k capabilities = %#v", k3)
	}
}

func TestFetchProviderModelsUsesProviderModelEndpoint(t *testing.T) {
	provider := NewKimiProvider(mustParse("https://api.kimi.test/coding"))
	account := &Account{ID: "kimi", Type: AccountTypeKimi, AccessToken: "secret"}
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://api.kimi.test/coding/v1/models" {
			t.Fatalf("model discovery URL = %s", req.URL)
		}
		if req.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("authorization header = %q", req.Header.Get("Authorization"))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"data":[{"id":"k3-256k"}]}`)),
			Header:     make(http.Header),
		}, nil
	})

	snapshot, err := fetchProviderModels(context.Background(), transport, provider, account)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snapshot.Models["k3-256k"]; !ok {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestPoolCandidateForModelHonorsPerAccountEntitlement(t *testing.T) {
	eligible := &Account{ID: "eligible", Type: AccountTypeCodex, PlanType: "pro", Models: map[string]DiscoveredModel{
		"gpt-daybreak-blue-latest": {ID: "gpt-daybreak-blue-latest"},
	}}
	ineligible := &Account{ID: "ineligible", Type: AccountTypeCodex, PlanType: "pro", Models: map[string]DiscoveredModel{
		"gpt-5.5": {ID: "gpt-5.5"},
	}}
	pool := newPoolState([]*Account{ineligible, eligible}, false)

	got := pool.candidateForModel("", nil, AccountTypeCodex, "", "", "GPT-DAYBREAK-BLUE-LATEST")
	if got != eligible {
		t.Fatalf("candidate = %#v, want eligible account", got)
	}
}

func TestCodexWebSocketSwapsToModelEntitledAccount(t *testing.T) {
	eligible := &Account{ID: "eligible", Type: AccountTypeCodex, PlanType: "pro", Models: map[string]DiscoveredModel{
		"gpt-daybreak-blue-latest": {ID: "gpt-daybreak-blue-latest"},
	}}
	ineligible := &Account{ID: "ineligible", Type: AccountTypeCodex, PlanType: "pro", Models: map[string]DiscoveredModel{
		"gpt-5.5": {ID: "gpt-5.5"},
	}}
	state := &codexRelayState{
		h:             &proxyHandler{pool: newPoolState([]*Account{ineligible, eligible}, false)},
		activeAccount: ineligible,
		opts:          codexCyberSwapOptions{RequiredPlan: "pro"},
	}

	_, err := state.inspectClient([]byte(`{"type":"response.create","model":"gpt-daybreak-blue-latest"}`))
	var swap *swapPendingErr
	if !errors.As(err, &swap) || swap.next != eligible {
		t.Fatalf("inspectClient error = %#v, want swap to eligible", err)
	}
}

func TestPoolDescriptorsIncludeDiscoveredModelsWithAvailability(t *testing.T) {
	account := &Account{
		ID:              "codex",
		Type:            AccountTypeCodex,
		PlanType:        "pro",
		ModelsFetchedAt: time.Now(),
		Models: map[string]DiscoveredModel{
			"gpt-daybreak-blue-latest": {
				ID:              "gpt-daybreak-blue-latest",
				DisplayName:     "GPT Daybreak Blue",
				ContextWindow:   372000,
				MaxOutputTokens: 128000,
				Reasoning:       true,
				Modalities:      []string{"text", "image"},
			},
		},
	}
	pool := newPoolState([]*Account{account}, false)

	for _, descriptor := range poolModelDescriptors(pool) {
		if descriptor.ID != "gpt-daybreak-blue-latest" {
			continue
		}
		if descriptor.Provider != string(AccountTypeCodex) || descriptor.SupportingAccounts != 1 || !descriptor.AvailableNow {
			t.Fatalf("daybreak descriptor = %#v", descriptor)
		}
		return
	}
	t.Fatal("discovered Daybreak model missing")
}
