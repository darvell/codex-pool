package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPassportSetupLifecycle(t *testing.T) {
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "test-passport-encryption-key")
	t.Setenv("POOL_JWT_SECRET", "test-jwt-secret")
	store := testUsageStore(t)
	passport, err := newPassportStore(store.db, nil, passportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	principal, _, client, _, err := passport.createGuest("operator", "Setup test", "Setup test", nil)
	if err != nil {
		t.Fatal(err)
	}
	legacy := &PoolUserStore{users: map[string]*PoolUser{}, byTok: map[string]*PoolUser{}}
	h := &proxyHandler{cfg: &config{}, passport: passport, poolUsers: legacy, pool: newPoolState(nil, false), metrics: newMetrics()}

	check := func(token string, want int) {
		t.Helper()
		for _, path := range []string{"/setup/claude/", "/setup/gemini/", "/setup/cute-code/", "/config/claude/", "/config/cute-code/"} {
			for _, shell := range []string{"", "?shell=powershell"} {
				response := httptest.NewRecorder()
				h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path+token+shell, nil))
				if response.Code != want {
					t.Errorf("%s%s status = %d, want %d", path, shell, response.Code, want)
				}
			}
		}
	}

	check(client.DownloadToken, http.StatusOK)
	oldToken := client.DownloadToken
	client, err = passport.rotateClient(principal.ID, principal.ID, client.ID)
	if err != nil {
		t.Fatal(err)
	}
	check(oldToken, http.StatusNotFound)
	check(client.DownloadToken, http.StatusOK)

	// A stale legacy lookup must not reopen a rotated Passport credential.
	legacy.byTok[oldToken] = &PoolUser{ID: principal.ID, Token: oldToken}
	check(oldToken, http.StatusNotFound)
	if err := passport.revokeClient(principal.ID, principal.ID, client.ID); err != nil {
		t.Fatal(err)
	}
	check(client.DownloadToken, http.StatusNotFound)

	expired := time.Now().Add(-time.Hour)
	client, err = passport.createClient(principal.ID, "Expired", &expired)
	if err != nil {
		t.Fatal(err)
	}
	check(client.DownloadToken, http.StatusNotFound)

	client, err = passport.createClient(principal.ID, "Suspended owner", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = passport.setPrincipalStatus("operator", principal.ID, PrincipalSuspended); err != nil {
		t.Fatal(err)
	}
	check(client.DownloadToken, http.StatusNotFound)
}

func TestPassportClaudeSetupAuth(t *testing.T) {
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "test-passport-encryption-key")
	t.Setenv("POOL_JWT_SECRET", "test-jwt-secret")
	store := testUsageStore(t)
	passport, err := newPassportStore(store.db, nil, passportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	principal, _, client, _, err := passport.createGuest("operator", "Macbook", "Macbook", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &proxyHandler{cfg: &config{}, passport: passport, pool: newPoolState(nil, false), metrics: newMetrics()}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/setup/claude/"+client.DownloadToken, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("setup status = %d: %s", response.Code, response.Body.String())
	}
	home := t.TempDir()
	cmd := exec.Command("bash", "-s")
	cmd.Env = append(os.Environ(), "HOME="+home, "CLAUDE_CONFIG_DIR="+filepath.Join(home, ".claude"))
	cmd.Stdin = strings.NewReader(response.Body.String())
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("setup script failed: %v\n%s", err, output)
	}
	data, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	request.Header.Set("Authorization", "Bearer "+settings.Env["CLAUDE_CODE_OAUTH_TOKEN"])
	_, principalID, clientID, _, allowed := h.authorizePoolCredentialRequest(request)
	if !allowed || principalID != principal.ID || clientID != client.ID {
		t.Fatalf("installed key authorization = %t, principal = %q, client = %q", allowed, principalID, clientID)
	}
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("installed key model-list status = %d", response.Code)
	}
}
