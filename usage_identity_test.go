package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

func TestUsageIdentityFanout(t *testing.T) {
	for _, tc := range []struct {
		name, identity, client string
	}{
		{"passport", "member-c-device", "device"},
		{"legacy", "member", "legacy-member"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := testUsageStore(t)
			projection, err := newAnalyticsStore(filepath.Join(t.TempDir(), "costs.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = projection.Close() })
			h := &proxyHandler{cfg: &config{}, store: store, analyticsStore: projection}
			h.recordUsage(&Account{ID: "account"}, RequestUsage{
				Timestamp: time.Now().UTC(), UserID: tc.identity, AccountID: "account",
				AccountType: AccountTypeCodex, InputTokens: 11, OutputTokens: 7, BillableTokens: 18,
			})
			var projected string
			if err := projection.db.QueryRow("SELECT user_id FROM request_costs").Scan(&projected); err != nil {
				t.Fatal(err)
			}
			if projected != "member" {
				t.Fatalf("projected principal=%q", projected)
			}
			if err := store.db.View(func(tx *bbolt.Tx) error {
				_, raw := tx.Bucket([]byte(bucketUsageRequests)).Cursor().First()
				var usage RequestUsage
				if err := decodeRequestUsage(raw, &usage); err != nil {
					return err
				}
				_, rawFact := tx.Bucket([]byte(bucketAnalyticsOutbox)).Cursor().First()
				var fact AnalyticsFact
				if err := json.Unmarshal(rawFact, &fact); err != nil {
					return err
				}
				if usage.UserID != "member" || usage.ClientCredentialID != tc.client || fact.PrincipalID != usage.UserID || fact.ClientCredentialID != tc.client {
					t.Fatalf("identity mismatch: request=%+v fact=%+v", usage, fact)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
