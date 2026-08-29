package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

type authoritySession struct {
	token string
	csrf  string
}

func addAuthorityPrincipal(t *testing.T, passport *PassportStore, id string, kind PrincipalKind) authoritySession {
	t.Helper()
	principal := &Principal{ID: id, Kind: kind, Status: PrincipalActive, Username: id, CreatedAt: time.Now().UTC()}
	if err := passport.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx.Bucket([]byte(bucketPrincipals)), id, principal) }); err != nil {
		t.Fatal(err)
	}
	passport.mu.Lock()
	passport.principals[id] = principal
	passport.mu.Unlock()
	token, csrf, err := passport.createSession(id)
	if err != nil {
		t.Fatal(err)
	}
	return authoritySession{token: token, csrf: csrf}
}

func authorityRequest(method, path string, session authoritySession, body string) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: "pool_session", Value: session.token})
	request.AddCookie(&http.Cookie{Name: "pool_csrf", Value: session.csrf})
	request.Header.Set("X-CSRF-Token", session.csrf)
	return request
}

func TestAuthorityMatrix(t *testing.T) {
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "test-passport-encryption-key")
	store := testUsageStore(t)
	passport, err := newPassportStore(store.db, nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := map[PrincipalKind]authoritySession{
		PrincipalGuest:    addAuthorityPrincipal(t, passport, "guest", PrincipalGuest),
		PrincipalMember:   addAuthorityPrincipal(t, passport, "member", PrincipalMember),
		PrincipalOperator: addAuthorityPrincipal(t, passport, "operator", PrincipalOperator),
	}
	handler := &proxyHandler{cfg: &config{}, passport: passport, metrics: newMetrics(), pool: newPoolState(nil, false)}

	tests := []struct {
		name    string
		method  string
		path    string
		body    string
		allowed map[PrincipalKind]bool
	}{
		{"self clients", http.MethodGet, "/api/me/clients", "", map[PrincipalKind]bool{PrincipalGuest: true, PrincipalMember: true, PrincipalOperator: true}},
		{"guest passes", http.MethodGet, "/api/passes", "", map[PrincipalKind]bool{PrincipalMember: true, PrincipalOperator: true}},
		{"console", http.MethodGet, "/api/console/principals", "", map[PrincipalKind]bool{PrincipalMember: true, PrincipalOperator: true}},
		{"member creation", http.MethodPost, "/api/console/members", `{"email":"new@example.com","purpose":"onboard"}`, map[PrincipalKind]bool{PrincipalOperator: true}},
		{"provider contribution", http.MethodPost, "/api/pool/accounts/codex/add", `{}`, map[PrincipalKind]bool{PrincipalMember: true, PrincipalOperator: true}},
		{"principal suspension", http.MethodPatch, "/api/principals/guest", `{"status":"suspended"}`, map[PrincipalKind]bool{PrincipalOperator: true}},
	}
	for _, test := range tests {
		for kind, session := range sessions {
			t.Run(test.name+"/"+string(kind), func(t *testing.T) {
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, authorityRequest(test.method, test.path, session, test.body))
				if test.allowed[kind] && (response.Code == http.StatusUnauthorized || response.Code == http.StatusForbidden) {
					t.Fatalf("allowed %s received %d: %s", kind, response.Code, response.Body.String())
				}
				if !test.allowed[kind] && response.Code != http.StatusForbidden {
					t.Fatalf("denied %s received %d, want 403: %s", kind, response.Code, response.Body.String())
				}
			})
		}
	}
}
