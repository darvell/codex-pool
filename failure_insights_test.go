package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"go.etcd.io/bbolt"
)

func TestClassifyFailureRedactsTransportDetails(t *testing.T) {
	class, domain, code := classifyFailure(http.StatusTooManyRequests, nil)
	if class != ErrorClassRateLimit.String() || domain != "http" || code != "429" {
		t.Fatalf("classification = %q/%q/%q", class, domain, code)
	}
	class, domain, code = classifyFailure(0, errors.New("secret token body"))
	if class != ErrorClassFatal.String() || domain != "transport" || code != "error" {
		t.Fatalf("transport classification = %q/%q/%q", class, domain, code)
	}
	if _, _, code = classifyFailure(0, context.DeadlineExceeded); code != "context_deadline" {
		t.Fatalf("deadline code = %q", code)
	}
}

func TestPublicFailureAccountIDIsHashed(t *testing.T) {
	if got := publicFailureAccountID("user@example.test"); got == "user@example.test" || got != hashAccountID("user@example.test") {
		t.Fatalf("public account id = %q", got)
	}
}

func TestFailureOutboxPayloadIsRedactedAndDurable(t *testing.T) {
	db, err := bbolt.Open(t.TempDir()+"/ledger.db", 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucket([]byte(bucketAnalyticsOutbox)); err != nil {
			return err
		}
		event := PoolFailureAttempt{EventID: "e1", RequestID: "r1", AccountID: "account-hash", Provider: "codex", ErrorClass: "auth", ErrorDomain: "http", ErrorCode: "401", Outcome: "terminal_failure"}
		return putFailureAttemptOutbox(tx, event)
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketAnalyticsOutbox))
		k, raw := b.Cursor().First()
		if k == nil {
			t.Fatal("missing outbox event")
		}
		if binary.BigEndian.Uint64(k) == 0 {
			t.Fatal("invalid outbox sequence")
		}
		var envelope struct {
			Type string             `json:"type"`
			Data PoolFailureAttempt `json:"data"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return err
		}
		if envelope.Type != "pool_failure_attempt" || envelope.Data.AccountID != "account-hash" {
			t.Fatalf("envelope = %+v", envelope)
		}
		if string(raw) == "" || strings.Contains(string(raw), "secret token body") {
			t.Fatal("outbox payload contains unexpected secret")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
