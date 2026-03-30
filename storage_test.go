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

func TestUsageStoreRecordTracksOriginUsage(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "proxy.db")
	s, err := newUsageStore(path, 30)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	now := time.Now()
	ru := RequestUsage{
		AccountID:         "acct1",
		OriginID:          "ip_deadbeefcafebabe",
		InputTokens:       120,
		CachedInputTokens: 20,
		OutputTokens:      10,
		BillableTokens:    110,
		Timestamp:         now,
		RequestID:         "req-origin-1",
	}
	if err := s.record(ru); err != nil {
		t.Fatalf("record: %v", err)
	}

	origins, err := s.getAllOriginUsage()
	if err != nil {
		t.Fatalf("get origins: %v", err)
	}
	if len(origins) != 1 {
		t.Fatalf("expected 1 origin, got %d", len(origins))
	}
	if origins[0].OriginID != ru.OriginID {
		t.Fatalf("origin id = %q, want %q", origins[0].OriginID, ru.OriginID)
	}
	if origins[0].TotalBillableTokens != ru.BillableTokens || origins[0].RequestCount != 1 {
		t.Fatalf("unexpected origin aggregate: %+v", origins[0])
	}
}

func TestUsageStoreOriginMetadata(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "proxy.db")
	s, err := newUsageStore(path, 30)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Second)
	if err := s.recordOriginMetadata(
		"ip_deadbeefcafebabe",
		"203.0.113.42",
		"user123",
		"claude-cli/test",
		"/v1/messages",
		now,
	); err != nil {
		t.Fatalf("record origin metadata: %v", err)
	}

	metas, err := s.getAllOriginMetadata()
	if err != nil {
		t.Fatalf("get origin metadata: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("expected 1 origin metadata row, got %d", len(metas))
	}
	meta := metas[0]
	if meta.OriginID != "ip_deadbeefcafebabe" {
		t.Fatalf("origin id = %q", meta.OriginID)
	}
	if meta.RawIP != "203.0.113.42" {
		t.Fatalf("raw ip = %q", meta.RawIP)
	}
	if meta.LastUserID != "user123" || meta.LastPath != "/v1/messages" {
		t.Fatalf("unexpected metadata: %+v", meta)
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
