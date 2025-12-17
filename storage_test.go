package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

func TestUsageStoreRecordAndAggregate(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "proxy.db")
	s, err := newUsageStore(path, 30)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	ru := RequestUsage{AccountID: "acct1", InputTokens: 100, CachedInputTokens: 20, OutputTokens: 5, BillableTokens: 85, Timestamp: time.Now(), RequestID: "req1"}
	if err := s.record(ru); err != nil {
		t.Fatalf("record: %v", err)
	}

	agg, err := s.loadAccountUsage("acct1")
	if err != nil {
		t.Fatalf("load aggregate: %v", err)
	}
	if agg.TotalBillableTokens != 85 || agg.TotalInputTokens != 100 {
		t.Fatalf("unexpected aggregate: %+v", agg)
	}

	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 {
		t.Fatalf("db not created")
	}
}

func TestUsageStorePrune(t *testing.T) {
	s, err := newUsageStore(filepath.Join(t.TempDir(), "db.db"), 1)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	old := time.Now().Add(-48 * time.Hour)
	s.record(RequestUsage{AccountID: "acct", BillableTokens: 1, Timestamp: old})
	s.record(RequestUsage{AccountID: "acct", BillableTokens: 1, Timestamp: time.Now()})
	// Force prune
	s.nextPrune = time.Now().Add(-time.Hour)
	_ = s.record(RequestUsage{AccountID: "acct", BillableTokens: 1, Timestamp: time.Now()})

	err = s.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket([]byte(bucketUsageRequests)).Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if strings.Contains(string(k), fmt.Sprintf("%d", old.UnixNano())) {
				t.Fatalf("old entry not pruned")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}
}
