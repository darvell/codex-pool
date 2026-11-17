package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
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
		for _, kind := range []PrincipalKind{PrincipalGuest, PrincipalMember, PrincipalOperator} {
			t.Run(test.name+"/"+string(kind), func(t *testing.T) {
				store := testUsageStore(t)
				passport, err := newPassportStore(store.db, nil, passportOptions{})
				if err != nil {
					t.Fatal(err)
				}
				sessions := map[PrincipalKind]authoritySession{
					PrincipalGuest:    addAuthorityPrincipal(t, passport, "guest", PrincipalGuest),
					PrincipalMember:   addAuthorityPrincipal(t, passport, "member", PrincipalMember),
					PrincipalOperator: addAuthorityPrincipal(t, passport, "operator", PrincipalOperator),
				}
				handler := &proxyHandler{cfg: &config{}, passport: passport, metrics: newMetrics(), pool: newPoolState(nil, false)}
				if test.name == "console" {
					duck, err := newDuckAnalytics(filepath.Join(t.TempDir(), "authority.duckdb"), store.db)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = duck.Close() })
					handler.duckAnalytics = duck
				}

				response := httptest.NewRecorder()
				handler.ServeHTTP(response, authorityRequest(test.method, test.path, sessions[kind], test.body))
				wantStatus := http.StatusForbidden
				if test.allowed[kind] {
					wantStatus = http.StatusOK
				}
				if response.Code != wantStatus {
					t.Fatalf("status=%d, want %d: %s", response.Code, wantStatus, response.Body.String())
				}
				wantGuestStatus := PrincipalActive
				if test.name == "principal suspension" && test.allowed[kind] {
					wantGuestStatus = PrincipalSuspended
				}
				if guest := passport.principal("guest"); guest.Status != wantGuestStatus {
					t.Fatalf("guest status=%s, want %s", guest.Status, wantGuestStatus)
				}
				if !test.allowed[kind] {
					if len(passport.principals) != len(sessions) {
						t.Fatal("denied request created a principal")
					}
					return
				}

				switch test.name {
				case "self clients", "guest passes":
					var rows []json.RawMessage
					if err := json.Unmarshal(response.Body.Bytes(), &rows); err != nil {
						t.Fatal(err)
					}
					if rows == nil || len(rows) != 0 {
						t.Fatalf("list=%s, want []", response.Body.String())
					}
				case "console":
					var result struct {
						Principals          []ConsolePrincipal `json:"principals"`
						Hours               int                `json:"hours"`
						ExcludesPassthrough bool               `json:"excludes_passthrough"`
					}
					if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
						t.Fatal(err)
					}
					if len(result.Principals) != len(sessions) || result.Hours != 168 || !result.ExcludesPassthrough {
						t.Fatalf("console=%+v", result)
					}
					seen := make(map[string]bool)
					for _, principal := range result.Principals {
						if _, ok := sessions[principal.Kind]; !ok || principal.ID != string(principal.Kind) || principal.Status != PrincipalActive || seen[principal.ID] {
							t.Fatalf("unexpected console principal=%+v", principal)
						}
						seen[principal.ID] = true
					}
				case "member creation":
					var result struct {
						Principal Principal `json:"principal"`
						Link      string    `json:"link"`
					}
					if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
						t.Fatal(err)
					}
					created := passport.principal(result.Principal.ID)
					if created == nil || created.Kind != PrincipalMember || created.Status != PrincipalActive || created.Email != "new@example.com" || result.Principal.Email != created.Email || !strings.Contains(result.Link, "/recover#") {
						t.Fatalf("created member=%+v response=%s", created, response.Body.String())
					}
				case "provider contribution":
					var result struct {
						OAuthURL string `json:"oauth_url"`
						Verifier string `json:"verifier"`
						State    string `json:"state"`
					}
					if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
						t.Fatal(err)
					}
					u, err := url.Parse(result.OAuthURL)
					if err != nil || result.Verifier == "" || result.State == "" || u.Query().Get("state") != result.State || u.Query().Get("code_challenge") == "" || u.Query().Get("code_challenge_method") != "S256" {
						t.Fatalf("OAuth response=%+v error=%v", result, err)
					}
					t.Cleanup(func() {
						codexOAuthSessions.Lock()
						delete(codexOAuthSessions.sessions, result.Verifier)
						codexOAuthSessions.Unlock()
					})
				case "principal suspension":
					var principal Principal
					if err := json.Unmarshal(response.Body.Bytes(), &principal); err != nil {
						t.Fatal(err)
					}
					if principal.ID != "guest" || principal.Status != PrincipalSuspended {
						t.Fatalf("suspended principal=%+v", principal)
					}
				}
			})
		}
	}
}
