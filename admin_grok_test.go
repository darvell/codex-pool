package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGrokAdminImportAddsAccount(t *testing.T) {
	base, _ := url.Parse("https://cli-chat-proxy.grok.com/v1")
	poolDir := t.TempDir()
	h := &proxyHandler{
		cfg:      &config{poolDir: poolDir, grokBase: base},
		pool:     newPoolState(nil, false),
		registry: NewProviderRegistry(NewCodexProvider(base, base, nil), NewClaudeProvider(base), NewGeminiProvider(base, base), NewGrokProvider(base)),
	}

	body := `{"auth_json":"{\"access\":\"access-token\",\"refresh\":\"refresh-token\",\"expires\":1790000000000,\"tokenEndpoint\":\"https://auth.x.ai/oauth2/token\"}"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/grok/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleGrokImport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["account_id"] == "" {
		t.Fatalf("missing account_id: %s", rr.Body.String())
	}
	files, err := os.ReadDir(filepath.Join(poolDir, "grok"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("grok files = %d, want 1", len(files))
	}
	accounts := h.pool.allAccounts()
	if len(accounts) != 1 || accounts[0].Type != AccountTypeGrok || accounts[0].AccessToken != "access-token" {
		t.Fatalf("accounts = %#v", accounts)
	}
}
