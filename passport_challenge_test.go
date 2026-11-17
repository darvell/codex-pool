package main

import (
	"testing"
	"time"

	wa "github.com/go-webauthn/webauthn/webauthn"
	"go.etcd.io/bbolt"
)

func TestWebAuthnChallengeMetadata(t *testing.T) {
	p, operator := testPassportWithOperator(t)
	const label = "Laptop | security key"
	id, err := p.saveWebAuthnChallenge(operator.ID, webAuthnRegister, label, &wa.SessionData{Challenge: "challenge"})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := p.takeWebAuthnChallenge(id, webAuthnRegister)
	if err != nil || challenge.Purpose != webAuthnRegister || challenge.Label != label || challenge.Session.Challenge != "challenge" {
		t.Fatalf("challenge=%+v error=%v", challenge, err)
	}
	if _, err := p.takeWebAuthnChallenge(id, webAuthnRegister); err == nil {
		t.Fatal("challenge was reusable")
	}
	legacy := storedWebAuthnChallenge{ID: "legacy", PrincipalID: operator.ID, Purpose: "register|" + label, ExpiresAt: time.Now().Add(time.Minute)}
	if err := p.db.Update(func(tx *bbolt.Tx) error {
		return putJSON(tx.Bucket([]byte(bucketWebAuthnChallenges)), legacy.ID, legacy)
	}); err != nil {
		t.Fatal(err)
	}
	challenge, err = p.takeWebAuthnChallenge(legacy.ID, webAuthnRegister)
	if err != nil || challenge.Purpose != webAuthnRegister || challenge.Label != label {
		t.Fatalf("legacy challenge=%+v error=%v", challenge, err)
	}
}
