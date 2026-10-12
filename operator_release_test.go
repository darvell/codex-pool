package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

func TestOperatorRoleRestoration(t *testing.T) {
	_, passport, owner, _ := testOperatorAPI(t)
	other := &Principal{ID: "operator-two", Kind: PrincipalOperator, Status: PrincipalActive}
	if err := passport.db.Update(func(tx *bbolt.Tx) error {
		return putJSON(tx.Bucket([]byte(bucketPrincipals)), other.ID, other)
	}); err != nil {
		t.Fatal(err)
	}
	passport.principals[other.ID] = other
	_, secret, err := passport.createOperatorToken(owner.ID, owner.ID, "automation", operatorScopeWrite, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := passport.setPrincipalKind(other.ID, owner.ID, PrincipalMember); err != nil {
		t.Fatal(err)
	}
	if _, err := passport.setPrincipalKind(other.ID, owner.ID, PrincipalOperator); err != nil {
		t.Fatal(err)
	}
	if principal, _ := passport.authenticateOperatorToken(secret); principal != nil {
		t.Error("demoted operator token regained authority after promotion")
	}
	path := filepath.Join(t.TempDir(), "reopened.db")
	if err := passport.db.View(func(tx *bbolt.Tx) error { return tx.CopyFile(path, 0600) }); err != nil {
		t.Fatal(err)
	}
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reloaded, err := newPassportStore(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if principal, _ := reloaded.authenticateOperatorToken(secret); principal != nil {
		t.Error("demoted operator token regained authority after database reopen")
	}
}

func TestOperatorCredentialCutoff(t *testing.T) {
	_, passport, owner, _ := testOperatorAPI(t)
	_, secret, err := passport.createOperatorToken(owner.ID, owner.ID, "automation", operatorScopeRead, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	updated := *owner
	updated.CredentialsValidAfter = nextCredentialCutoff(time.Now())
	if err := passport.db.Update(func(tx *bbolt.Tx) error {
		return putJSON(tx.Bucket([]byte(bucketPrincipals)), owner.ID, &updated)
	}); err != nil {
		t.Fatal(err)
	}
	passport.principals[owner.ID] = &updated
	if principal, _ := passport.authenticateOperatorToken(secret); principal != nil {
		t.Fatal("operator token ignored principal credential cutoff")
	}
}

func TestOperatorAuditAccountPrivacy(t *testing.T) {
	h, passport, owner, session := testOperatorAPI(t)
	rawID := "antigravity-alice-example.com"
	if err := passport.recordAudit(owner.ID, "provider.account_added", rawID, "antigravity"); err != nil {
		t.Fatal(err)
	}
	_, secret, err := passport.createOperatorToken(owner.ID, owner.ID, "diagnostics", operatorScopeRead, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, browser := range []bool{false, true} {
		r := operatorBearerRequest(http.MethodGet, "/api/console/audit", secret)
		if browser {
			r.Header.Del("Authorization")
			r.AddCookie(&http.Cookie{Name: "pool_session", Value: session.token})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("audit status = %d: %s", w.Code, w.Body.String())
		}
		var entries []AuditEntry
		if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range entries {
			if entry.Action != "provider.account_added" {
				continue
			}
			found = true
			want := hashAccountID(rawID)
			if browser {
				want = rawID
			}
			if entry.SubjectID != want {
				t.Errorf("browser=%v audit subject=%q, want %q", browser, entry.SubjectID, want)
			}
		}
		if !found || (!browser && strings.Contains(w.Body.String(), rawID)) {
			t.Errorf("browser=%v incorrect audit disclosure: %s", browser, w.Body.String())
		}
	}
}
