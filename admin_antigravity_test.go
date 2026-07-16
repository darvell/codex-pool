package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewAntigravityOAuthSessionUsesPKCESafeValues(t *testing.T) {
	session, err := newAntigravityOAuthSession()
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"id": session.ID, "state": session.State, "verifier": session.Verifier} {
		if value == "" {
			t.Fatalf("%s was empty", name)
		}
		if _, err := base64.RawURLEncoding.DecodeString(value); err != nil {
			t.Fatalf("%s is not base64url: %v", name, err)
		}
	}
}

func TestAntigravityAddUsesConfiguredOAuthIdentity(t *testing.T) {
	t.Setenv("ANTIGRAVITY_OAUTH_CLIENT_ID", "test-client-id")
	t.Setenv("ANTIGRAVITY_OAUTH_CLIENT_SECRET", "test-client-secret")
	old := os.Getenv("ANTIGRAVITY_OAUTH_REDIRECT_URI")
	t.Cleanup(func() { _ = os.Setenv("ANTIGRAVITY_OAUTH_REDIRECT_URI", old) })
	_ = os.Unsetenv("ANTIGRAVITY_OAUTH_REDIRECT_URI")
	if got := antigravityOAuthRedirectURI(); got != antigravityOAuthCallbackURL {
		t.Fatalf("redirect URI = %q", got)
	}
	if got := antigravityOAuthClientID(); got != "test-client-id" {
		t.Fatalf("client ID = %q", got)
	}
	if got := antigravityOAuthClientSecret(); got != "test-client-secret" {
		t.Fatalf("client secret = %q", got)
	}
	if got := antigravityUserAgent(); got != "antigravity/hub/2.2.1 darwin/arm64" {
		t.Fatalf("user agent = %q", got)
	}
}

func TestAntigravityAddBuildsRealGoogleAuthorizationURL(t *testing.T) {
	t.Setenv("ANTIGRAVITY_OAUTH_CLIENT_ID", "test-client-id")
	t.Setenv("ANTIGRAVITY_OAUTH_CLIENT_SECRET", "")
	t.Setenv("ANTIGRAVITY_OAUTH_REDIRECT_URI", "https://pool.example.test/admin/antigravity/callback")
	request := httptest.NewRequest(http.MethodPost, "/api/pool/accounts/antigravity/add", strings.NewReader("{}"))
	request.Header.Set("Origin", "https://pool.example.test")
	recorder := httptest.NewRecorder()
	(&proxyHandler{}).handleAntigravityAdd(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected response %d %s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		OAuthURL  string `json:"oauth_url"`
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	authorize, err := url.Parse(result.OAuthURL)
	if err != nil {
		t.Fatal(err)
	}
	query := authorize.Query()
	if authorize.Scheme+"://"+authorize.Host+authorize.Path != antigravityOAuthAuthorizeURL || query.Get("client_id") != "test-client-id" || query.Get("redirect_uri") != "https://pool.example.test/admin/antigravity/callback" {
		t.Fatalf("unexpected authorization URL %s", result.OAuthURL)
	}
	if query.Get("access_type") != "offline" || query.Get("prompt") != "consent" || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("missing OAuth parameters: %v", query)
	}
	antigravityOAuthSessions.Lock()
	if session := antigravityOAuthSessions.byID[result.SessionID]; session != nil {
		delete(antigravityOAuthSessions.byState, session.State)
	}
	delete(antigravityOAuthSessions.byID, result.SessionID)
	antigravityOAuthSessions.Unlock()
}

func TestSafeAntigravityAccountID(t *testing.T) {
	if got := safeAntigravityAccountID("Person+AI@Example.COM"); got != "antigravity-person-ai-example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestAntigravityManualExchangeRequiresMatchingState(t *testing.T) {
	session, err := newAntigravityOAuthSession()
	if err != nil {
		t.Fatal(err)
	}
	antigravityOAuthSessions.Lock()
	antigravityOAuthSessions.byID[session.ID] = session
	antigravityOAuthSessions.byState[session.State] = session
	antigravityOAuthSessions.Unlock()
	t.Cleanup(func() {
		antigravityOAuthSessions.Lock()
		delete(antigravityOAuthSessions.byID, session.ID)
		delete(antigravityOAuthSessions.byState, session.State)
		antigravityOAuthSessions.Unlock()
	})
	body, _ := json.Marshal(map[string]string{"session_id": session.ID, "code": "code", "state": "wrong"})
	recorder := httptest.NewRecorder()
	(&proxyHandler{}).handleAntigravityExchange(recorder, httptest.NewRequest(http.MethodPost, "/api/pool/accounts/antigravity/exchange", strings.NewReader(string(body))))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "state") {
		t.Fatalf("unexpected response %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestAntigravityProjectIDUsesKnownShapes(t *testing.T) {
	root := map[string]any{"unrelated": map[string]any{"project": "wrong"}, "cloudaicompanionProject": map[string]any{"id": "right"}}
	if got := antigravityLoadProjectID(root); got != "right" {
		t.Fatalf("got %q", got)
	}
}

func TestAntigravityOnboardProjectRequiresCompletion(t *testing.T) {
	response := map[string]any{"cloudaicompanionProject": map[string]any{"id": "project"}}
	if got := antigravityOnboardProjectID(map[string]any{"done": false, "response": response}); got != "" {
		t.Fatalf("incomplete onboarding returned %q", got)
	}
	if got := antigravityOnboardProjectID(map[string]any{"done": true, "response": response}); got != "project" {
		t.Fatalf("completed onboarding returned %q", got)
	}
}

func TestSaveAntigravityAccountIsOwnerOnlyAndDurable(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "account.json")
	account := &Account{Type: AccountTypeAntigravity, ID: "account", File: file, AccessToken: "access", RefreshToken: "refresh", Email: "a@example.com", ProjectID: "project", PlanType: "pro", ExpiresAt: time.Now().Add(time.Hour), ModelRateLimits: make(map[string]time.Time)}
	antigravityModels.ReplaceAccount(account.ID, AntigravityAccountSnapshot{FetchedAt: time.Now(), Models: map[string]AntigravityModelInfo{"gemini-test": {ID: "gemini-test"}}})
	if err := saveAntigravityAccount(account); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode is %o", info.Mode().Perm())
	}
	var saved AntigravityAuthJSON
	raw, _ := os.ReadFile(file)
	if err := json.Unmarshal(raw, &saved); err != nil || saved.ProjectID != "project" || saved.ModelSnapshot == nil {
		t.Fatalf("bad saved credential: %v %#v", err, saved)
	}
}
