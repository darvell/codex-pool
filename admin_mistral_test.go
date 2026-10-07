package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMistralAdminAddValidatesAndSavesAccount(t *testing.T) {
	t.Parallel()

	poolDir := t.TempDir()
	mistralBase, _ := url.Parse("https://api.mistral.ai")
	validationCalled := false
	h := &proxyHandler{
		cfg:     &config{poolDir: poolDir, mistralBase: mistralBase},
		pool:    newPoolState(nil, false),
		metrics: newMetrics(),
		recent:  newRecentErrors(5),
		registry: NewProviderRegistry(
			&CodexProvider{},
			&ClaudeProvider{},
			&GeminiProvider{},
			NewMistralProvider(mistralBase),
		),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			validationCalled = true
			if req.URL.String() != "https://api.mistral.ai/v1/models" {
				t.Fatalf("validation URL = %q", req.URL.String())
			}
			if req.Method != http.MethodGet {
				t.Fatalf("validation method = %q, want GET (no spend)", req.Method)
			}
			if req.Header.Get("Authorization") != "Bearer sk-valid" {
				t.Fatalf("validation auth = %q", req.Header.Get("Authorization"))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body: io.NopCloser(strings.NewReader(`{"data":[
					{"id":"mistral-large-latest","name":"Mistral Large","max_context_length":128000,"capabilities":{"completion_chat":true,"function_calling":true}},
					{"id":"mistral-embed","name":"Embed","capabilities":{"completion_chat":false}}
				]}`)),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/mistral/add", strings.NewReader(`{"api_key":"sk-valid"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleMistralAdd(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if !validationCalled {
		t.Fatal("validation was not called")
	}
	entries, err := os.ReadDir(filepath.Join(poolDir, "mistral"))
	if err != nil {
		t.Fatalf("read mistral pool dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("saved %d Mistral files, want 1", len(entries))
	}
	if h.pool.countByType(AccountTypeMistral) != 1 {
		t.Fatalf("pool Mistral count = %d, want 1", h.pool.countByType(AccountTypeMistral))
	}
	reloaded, err := loadPool(poolDir, h.registry)
	if err != nil {
		t.Fatal(err)
	}
	for _, pool := range []*poolState{h.pool, newPoolState(reloaded, false)} {
		if account := pool.candidateForModel("", nil, AccountTypeMistral, "", "", "mistral/mistral-large-latest"); account == nil {
			t.Fatal("validated Mistral model must be routable immediately and after reload")
		}
	}
}

func TestMistralAdminRejectsUnauthorizedKeyWithoutSaving(t *testing.T) {
	t.Parallel()

	poolDir := t.TempDir()
	mistralBase, _ := url.Parse("https://api.mistral.ai")
	h := &proxyHandler{
		cfg:      &config{poolDir: poolDir, mistralBase: mistralBase},
		pool:     newPoolState(nil, false),
		registry: NewProviderRegistry(&CodexProvider{}, &ClaudeProvider{}, &GeminiProvider{}, NewMistralProvider(mistralBase)),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Status:     "401 Unauthorized",
				Body:       io.NopCloser(strings.NewReader(`{"message":"Unauthorized"}`)),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/mistral/add", strings.NewReader(`{"api_key":"sk-bad"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleMistralAdd(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(poolDir, "mistral")); !os.IsNotExist(err) {
		t.Fatalf("mistral pool dir should not exist after rejected key, err=%v", err)
	}
}

func TestMistralAdminRejectsCatalogWithNoChatModelsWithoutSaving(t *testing.T) {
	t.Parallel()

	poolDir := t.TempDir()
	mistralBase, _ := url.Parse("https://api.mistral.ai")
	h := &proxyHandler{
		cfg:      &config{poolDir: poolDir, mistralBase: mistralBase},
		pool:     newPoolState(nil, false),
		registry: NewProviderRegistry(&CodexProvider{}, &ClaudeProvider{}, &GeminiProvider{}, NewMistralProvider(mistralBase)),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(strings.NewReader(`{"data":[{"id":"mistral-embed","capabilities":{"completion_chat":false}}]}`)),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/mistral/add", strings.NewReader(`{"api_key":"sk-noaccess"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleMistralAdd(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(poolDir, "mistral")); !os.IsNotExist(err) {
		t.Fatalf("mistral pool dir should not exist when the key has no chat models, err=%v", err)
	}
}

func TestMistralAdminReportsNonAuthValidationFailureWithoutSaving(t *testing.T) {
	t.Parallel()

	poolDir := t.TempDir()
	mistralBase, _ := url.Parse("https://api.mistral.ai")
	h := &proxyHandler{
		cfg:      &config{poolDir: poolDir, mistralBase: mistralBase},
		pool:     newPoolState(nil, false),
		registry: NewProviderRegistry(&CodexProvider{}, &ClaudeProvider{}, &GeminiProvider{}, NewMistralProvider(mistralBase)),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Status:     "500 Internal Server Error",
				Body:       io.NopCloser(strings.NewReader(`{"message":"oops"}`)),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/mistral/add", strings.NewReader(`{"api_key":"sk-whatever"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleMistralAdd(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(poolDir, "mistral")); !os.IsNotExist(err) {
		t.Fatalf("mistral pool dir should not exist after validation failure, err=%v", err)
	}
}

func TestMistralAdminRejectsEmptyAPIKey(t *testing.T) {
	t.Parallel()

	h := &proxyHandler{}
	req := httptest.NewRequest(http.MethodPost, "/admin/mistral/add", strings.NewReader(`{"api_key":"   "}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleMistralAdd(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestServeMistralAdminRoutesListAddRemove(t *testing.T) {
	t.Parallel()

	poolDir := t.TempDir()
	mistralBase, _ := url.Parse("https://api.mistral.ai")
	h := &proxyHandler{
		cfg:      &config{poolDir: poolDir, mistralBase: mistralBase},
		pool:     newPoolState(nil, false),
		metrics:  newMetrics(),
		recent:   newRecentErrors(5),
		registry: NewProviderRegistry(&CodexProvider{}, &ClaudeProvider{}, &GeminiProvider{}, NewMistralProvider(mistralBase)),
	}

	listReq := httptest.NewRequest(http.MethodGet, "/admin/mistral", nil)
	listRR := httptest.NewRecorder()
	h.serveMistralAdmin(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list status = %d, body=%s", listRR.Code, listRR.Body.String())
	}

	unknownReq := httptest.NewRequest(http.MethodGet, "/admin/mistral/unknown", nil)
	unknownRR := httptest.NewRecorder()
	h.serveMistralAdmin(unknownRR, unknownReq)
	if unknownRR.Code != http.StatusNotFound {
		t.Fatalf("unknown path status = %d", unknownRR.Code)
	}
}
