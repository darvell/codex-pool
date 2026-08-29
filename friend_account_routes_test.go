package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

func TestRetiredFriendCodeNeverAuthenticates(t *testing.T) {
	h := &proxyHandler{cfg: &config{legacyFriendCode: "legacy-salt-only", adminToken: "admin"}}
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/api/pool/stats?code=legacy-salt-only", nil),
		httptest.NewRequest(http.MethodGet, "/api/pool/stats", nil),
	} {
		request.Header.Set("X-Friend-Code", "legacy-salt-only")
		response := httptest.NewRecorder()
		if h.checkMemberOrAdminAuth(response, request) {
			t.Fatal("retired friend code authenticated a request")
		}
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
		}
	}
}

func TestBreakGlassAdminCanStartAccountContribution(t *testing.T) {
	h := &proxyHandler{cfg: &config{adminToken: "admin"}}
	request := httptest.NewRequest(http.MethodPost, "/api/pool/accounts/codex/add", nil)
	request.Header.Set("X-Admin-Token", "admin")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", response.Code, response.Body.String())
	}
}

func TestAccountContributionRequiresAuthentication(t *testing.T) {
	h := &proxyHandler{cfg: &config{adminToken: "admin"}}
	request := httptest.NewRequest(http.MethodPost, "/api/pool/accounts/codex/add", nil)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func addTestPassportMember(t *testing.T, passport *PassportStore, id string) (sessionToken, csrf string) {
	t.Helper()
	principal := &Principal{ID: id, Kind: PrincipalMember, Status: PrincipalActive, Email: id + "@example.com", CreatedAt: time.Now().UTC()}
	if err := passport.db.Update(func(tx *bbolt.Tx) error {
		return putJSON(tx.Bucket([]byte(bucketPrincipals)), principal.ID, principal)
	}); err != nil {
		t.Fatal(err)
	}
	passport.mu.Lock()
	passport.principals[id] = principal
	passport.mu.Unlock()
	sessionToken, csrf, err := passport.createSession(id)
	if err != nil {
		t.Fatal(err)
	}
	return sessionToken, csrf
}

func passportContributionRequest(method, path, sessionToken, csrf string, body []byte) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: "pool_session", Value: sessionToken})
	if csrf != "" {
		request.AddCookie(&http.Cookie{Name: "pool_csrf", Value: csrf})
		request.Header.Set("X-CSRF-Token", csrf)
	}
	return request
}

func TestAccountContributionRequiresCSRFAndBindsOAuthActor(t *testing.T) {
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "test-passport-encryption-key")
	store := testUsageStore(t)
	passport, err := newPassportStore(store.db, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstSession, firstCSRF := addTestPassportMember(t, passport, "member-one")
	secondSession, secondCSRF := addTestPassportMember(t, passport, "member-two")
	h := &proxyHandler{cfg: &config{}, passport: passport}

	withoutCSRF := httptest.NewRecorder()
	h.ServeHTTP(withoutCSRF, passportContributionRequest(http.MethodPost, "/api/pool/accounts/codex/add", firstSession, "", []byte(`{}`)))
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing-CSRF status = %d, want 403", withoutCSRF.Code)
	}

	started := httptest.NewRecorder()
	h.ServeHTTP(started, passportContributionRequest(http.MethodPost, "/api/pool/accounts/codex/add", firstSession, firstCSRF, []byte(`{}`)))
	if started.Code != http.StatusOK {
		t.Fatalf("start status = %d body=%s", started.Code, started.Body.String())
	}
	var flow struct {
		Verifier string `json:"verifier"`
	}
	if json.Unmarshal(started.Body.Bytes(), &flow) != nil || flow.Verifier == "" {
		t.Fatalf("invalid start response: %s", started.Body.String())
	}

	exchangeBody, _ := json.Marshal(map[string]string{"code": "unused", "verifier": flow.Verifier})
	crossActor := httptest.NewRecorder()
	h.ServeHTTP(crossActor, passportContributionRequest(http.MethodPost, "/api/pool/accounts/codex/exchange", secondSession, secondCSRF, exchangeBody))
	if crossActor.Code != http.StatusForbidden {
		t.Fatalf("cross-actor exchange status = %d body=%s", crossActor.Code, crossActor.Body.String())
	}
}
