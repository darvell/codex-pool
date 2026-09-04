package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

func testPassportWithOperator(t *testing.T) (*PassportStore, *Principal) {
	t.Helper()
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "test-passport-encryption-key")
	s := testUsageStore(t)
	p, err := newPassportStore(s.db, nil)
	if err != nil {
		t.Fatal(err)
	}
	guest, _, _, _, err := p.createGuest("bootstrap", "Operator", "Operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := p.setPrincipalKind("bootstrap", guest.ID, PrincipalOperator)
	if err != nil {
		t.Fatal(err)
	}
	return p, operator
}

func insertTestPrincipal(t *testing.T, p *PassportStore, id string, kind PrincipalKind, username, email string) *Principal {
	t.Helper()
	member := &Principal{ID: id, Kind: kind, Status: PrincipalActive, Username: username, Email: email, CreatedAt: time.Now().UTC()}
	if err := p.db.Update(func(tx *bbolt.Tx) error {
		return putJSON(tx.Bucket([]byte(bucketPrincipals)), id, member)
	}); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.principals[id] = member
	p.mu.Unlock()
	return member
}

func TestSetPrincipalKindPromoteAndDemote(t *testing.T) {
	p, operator := testPassportWithOperator(t)

	member := insertTestPrincipal(t, p, "member-1", PrincipalMember, "neon", "neon@pool.local")

	promoted, err := p.setPrincipalKind(operator.ID, member.ID, PrincipalOperator)
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Kind != PrincipalOperator {
		t.Fatalf("kind = %q, want operator", promoted.Kind)
	}
	if got := p.principal(member.ID); got.Kind != PrincipalOperator {
		t.Fatalf("stored kind = %q, want operator", got.Kind)
	}

	// Demoting one of two operators succeeds.
	demoted, err := p.setPrincipalKind(operator.ID, member.ID, PrincipalMember)
	if err != nil {
		t.Fatal(err)
	}
	if demoted.Kind != PrincipalMember {
		t.Fatalf("kind = %q, want member", demoted.Kind)
	}

	// Demoting the last operator fails.
	if _, err := p.setPrincipalKind(operator.ID, operator.ID, PrincipalGuest); err == nil {
		t.Fatal("expected error demoting the last operator")
	}
	if got := p.principal(operator.ID); got.Kind != PrincipalOperator {
		t.Fatalf("last operator kind = %q, want operator", got.Kind)
	}

	// No-op and invalid inputs.
	if _, err := p.setPrincipalKind(operator.ID, operator.ID, PrincipalOperator); err != nil {
		t.Fatal(err)
	}
	if _, err := p.setPrincipalKind(operator.ID, member.ID, PrincipalKind("superadmin")); err == nil {
		t.Fatal("expected error for invalid kind")
	}
	if _, err := p.setPrincipalKind(operator.ID, "missing", PrincipalMember); err == nil {
		t.Fatal("expected error for unknown principal")
	}
}

func operatorSessionRequest(t *testing.T, p *PassportStore, operator *Principal, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	token, csrf, err := p.createSession(operator.ID)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPatch, "/api/principals/"+target, strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "pool_session", Value: token})
	req.AddCookie(&http.Cookie{Name: "pool_csrf", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	(&proxyHandler{passport: p}).handlePrincipalItem(rr, req)
	return rr
}

func TestPrincipalItemPatchKindByIDAndLogin(t *testing.T) {
	p, operator := testPassportWithOperator(t)
	insertTestPrincipal(t, p, "member-1", PrincipalMember, "neon", "neon@pool.local")

	rr := operatorSessionRequest(t, p, operator, "member-1", `{"kind":"operator"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var updated map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated["kind"] != "operator" {
		t.Fatalf("kind = %v", updated["kind"])
	}

	// Login fallback: username works in place of the principal ID.
	rr = operatorSessionRequest(t, p, operator, "neon", `{"kind":"member"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if got := p.principal("member-1"); got.Kind != PrincipalMember {
		t.Fatalf("kind = %q, want member", got.Kind)
	}

	// Unknown login is a 404, not a promotion.
	rr = operatorSessionRequest(t, p, operator, "stranger", `{"kind":"operator"}`)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestPrincipalItemPatchStatusStillWorks(t *testing.T) {
	p, operator := testPassportWithOperator(t)
	member := insertTestPrincipal(t, p, "member-1", PrincipalMember, "neon", "neon@pool.local")

	rr := operatorSessionRequest(t, p, operator, member.ID, `{"status":"suspended"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if got := p.principal(member.ID); got.Status != PrincipalSuspended {
		t.Fatalf("status = %q, want suspended", got.Status)
	}
}

func TestPrincipalItemPatchRequiresOperator(t *testing.T) {
	p, operator := testPassportWithOperator(t)
	member := insertTestPrincipal(t, p, "member-1", PrincipalMember, "neon", "neon@pool.local")

	// A member session cannot change roles.
	token, csrf, err := p.createSession(member.ID)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPatch, "/api/principals/"+operator.ID, strings.NewReader(`{"kind":"member"}`))
	req.AddCookie(&http.Cookie{Name: "pool_session", Value: token})
	req.AddCookie(&http.Cookie{Name: "pool_csrf", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	(&proxyHandler{passport: p}).handlePrincipalItem(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if got := p.principal(operator.ID); got.Kind != PrincipalOperator {
		t.Fatal("operator was demoted by a member session")
	}

	// Missing CSRF is rejected even for operators.
	opToken, opCsrf, err := p.createSession(operator.ID)
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPatch, "/api/principals/"+member.ID, strings.NewReader(`{"kind":"operator"}`))
	req.AddCookie(&http.Cookie{Name: "pool_session", Value: opToken})
	req.AddCookie(&http.Cookie{Name: "pool_csrf", Value: opCsrf})
	rr = httptest.NewRecorder()
	(&proxyHandler{passport: p}).handlePrincipalItem(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 without CSRF", rr.Code)
	}
}
