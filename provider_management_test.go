package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestProviderAdminRoutesRequireAdminToken(t *testing.T) {
	h := &proxyHandler{
		cfg:  &config{friendCode: "friend", adminToken: "admin"},
		pool: newPoolState([]*Account{{ID: "kimi", Type: AccountTypeKimi}}, false),
	}

	friendRequest := httptest.NewRequest(http.MethodGet, "/admin/kimi", nil)
	friendRequest.Header.Set("X-Friend-Code", "friend")
	friendResponse := httptest.NewRecorder()
	h.ServeHTTP(friendResponse, friendRequest)
	if friendResponse.Code != http.StatusUnauthorized {
		t.Fatalf("friend-auth provider admin status = %d, want 401", friendResponse.Code)
	}

	adminRequest := httptest.NewRequest(http.MethodGet, "/admin/kimi", nil)
	adminRequest.Header.Set("X-Admin-Token", "admin")
	adminResponse := httptest.NewRecorder()
	h.ServeHTTP(adminResponse, adminRequest)
	if adminResponse.Code != http.StatusOK {
		t.Fatalf("admin-auth provider status = %d, want 200", adminResponse.Code)
	}
}

func TestSetAccountDisabledPersistsAndReloads(t *testing.T) {
	file := filepath.Join(t.TempDir(), "kimi.json")
	if err := os.WriteFile(file, []byte(`{"api_key":"secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	account := &Account{ID: "kimi", Type: AccountTypeKimi, File: file, AccessToken: "secret"}
	h := &proxyHandler{pool: newPoolState([]*Account{account}, false)}

	recorder := httptest.NewRecorder()
	h.setAccountDisabled(recorder, account.ID, true)
	if recorder.Code != http.StatusOK || !account.Disabled {
		t.Fatalf("disable response=%d account.disabled=%v", recorder.Code, account.Disabled)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	if root["disabled"] != true {
		t.Fatalf("persisted disabled = %#v, want true", root["disabled"])
	}

	provider := NewKimiProvider(nil)
	reloaded, err := provider.LoadAccount(filepath.Base(file), file, data)
	if err != nil {
		t.Fatal(err)
	}
	applyCommonAccountFileState(reloaded, data)
	if !reloaded.Disabled {
		t.Fatal("reloaded account lost disabled state")
	}
}
