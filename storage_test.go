package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

func TestRequestUsageStorageCodec(t *testing.T) {
	usage := RequestUsage{
		Timestamp: time.Now().UTC().Truncate(time.Nanosecond), AccountID: "account", PlanType: "pro",
		UserID: "principal", OriginID: "origin", PromptCacheKey: "cache", RequestID: "upstream",
		ProxyRequestID: "proxy", ClientCredentialID: "client", UsageSequence: 2, AttemptNumber: 3,
		UsageCompleteness: "complete", InputTokens: 100, CachedInputTokens: 40, CacheCreationTokens: 5,
		InputTokenMode: "inclusive", OutputTokens: 20, ReasoningTokens: 10, BillableTokens: 80,
		PrimaryUsedPct: 0.2, SecondaryUsedPct: 0.4, PrimaryResetAt: time.Now().UTC().Add(time.Hour).Truncate(time.Nanosecond),
		SecondaryResetAt: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Nanosecond), PrimaryWindowMinutes: 300,
		SecondaryWindowMinutes: 10080, Model: "gpt-test", AccountType: AccountTypeCodex,
	}
	compact, err := encodeRequestUsage(usage)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := json.Marshal(usage)
	if err != nil {
		t.Fatal(err)
	}
	if len(compact) >= len(legacy) {
		t.Fatalf("compact bytes = %d, legacy bytes = %d", len(compact), len(legacy))
	}
	for name, data := range map[string][]byte{"compact": compact, "legacy": legacy} {
		var decoded RequestUsage
		if err := decodeRequestUsage(data, &decoded); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if decoded != usage {
			t.Fatalf("%s decoded = %+v, want %+v", name, decoded, usage)
		}
	}
	if err := decodeRequestUsage([]byte(`{"v":2}`), new(RequestUsage)); err == nil {
		t.Fatal("accepted unsupported storage version")
	}
}

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
	if err := s.db.View(func(tx *bbolt.Tx) error {
		key, _ := tx.Bucket([]byte(bucketUsageRequests)).Cursor().First()
		if !strings.HasPrefix(string(key), usageTimeKeyPrefix) {
			t.Fatalf("usage key %q is not time ordered", key)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
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

	now := time.Now()
	old := now.Add(-48 * time.Hour)
	s.record(RequestUsage{AccountID: "aaa", BillableTokens: 1, Timestamp: now})
	s.record(RequestUsage{AccountID: "zzz", BillableTokens: 1, Timestamp: old})
	if err := s.db.Update(func(tx *bbolt.Tx) error {
		requests := tx.Bucket([]byte(bucketUsageRequests))
		for account, at := range map[string]time.Time{"aaa": now, "zzz": old} {
			value, err := json.Marshal(RequestUsage{AccountID: account, BillableTokens: 1, Timestamp: at})
			if err != nil {
				return err
			}
			key := fmt.Sprintf("%s|%020d|legacy", account, at.UnixNano())
			if err := requests.Put([]byte(key), value); err != nil {
				return err
			}
		}

		bucket := tx.Bucket([]byte(bucketCapacitySamples))
		for _, at := range []time.Time{old, now} {
			value, err := json.Marshal(CapacitySample{Timestamp: at, PlanType: "team"})
			if err != nil {
				return err
			}
			key := fmt.Sprintf("team|%020d", at.UnixNano())
			if err := bucket.Put([]byte(key), value); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Force prune
	s.nextPrune = time.Now().Add(-time.Hour)
	_ = s.record(RequestUsage{AccountID: "aaa", BillableTokens: 1, Timestamp: now})

	err = s.db.View(func(tx *bbolt.Tx) error {
		requests := tx.Bucket([]byte(bucketUsageRequests))
		c := requests.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if strings.Contains(string(k), fmt.Sprintf("%d", old.UnixNano())) {
				t.Fatalf("old request not pruned")
			}
		}
		recentLegacyKey := fmt.Sprintf("aaa|%020d|legacy", now.UnixNano())
		if requests.Get([]byte(recentLegacyKey)) == nil {
			t.Fatal("recent legacy request was pruned")
		}

		samples := tx.Bucket([]byte(bucketCapacitySamples))
		c = samples.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if strings.Contains(string(k), fmt.Sprintf("%d", old.UnixNano())) {
				t.Fatalf("old capacity sample not pruned")
			}
		}
		recentKey := fmt.Sprintf("team|%020d", now.UnixNano())
		if samples.Get([]byte(recentKey)) == nil {
			t.Fatal("recent capacity sample was pruned")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}
}

func TestUsageStoreReadsBoundedTimeSeries(t *testing.T) {
	s, err := newUsageStore(filepath.Join(t.TempDir(), "db.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Hour)
	for _, usage := range []RequestUsage{
		{Timestamp: now, AccountID: "a", AccountType: AccountTypeCodex, UserID: "p1", BillableTokens: 1},
		{Timestamp: now.Add(-time.Hour), AccountID: "a", AccountType: AccountTypeCodex, UserID: "p1", BillableTokens: 2},
		{Timestamp: now.Add(-72 * time.Hour), AccountID: "a", AccountType: AccountTypeCodex, UserID: "p1", BillableTokens: 100},
	} {
		if err := s.record(usage); err != nil {
			t.Fatal(err)
		}
	}

	daily, err := s.getUserDailyUsage("p1", 2)
	if err != nil {
		t.Fatal(err)
	}
	hourly, err := s.getUserHourlyUsage("p1", 2)
	if err != nil {
		t.Fatal(err)
	}
	global, err := s.getGlobalHourlyUsage(2)
	if err != nil {
		t.Fatal(err)
	}
	for name, rows := range map[string][]UserHourlyUsage{"user": hourly, "global": global} {
		var total int64
		for _, row := range rows {
			total += row.BillableTokens
		}
		if total != 3 {
			t.Fatalf("%s hourly total = %d, want 3", name, total)
		}
	}
	var dailyTotal int64
	for _, row := range daily {
		dailyTotal += row.BillableTokens
	}
	if dailyTotal != 3 {
		t.Fatalf("daily total = %d, want 3", dailyTotal)
	}
}

func TestUsageStoreBackfillsLegacyOriginWeeklyIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := bbolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	usage := RequestUsage{
		Timestamp:         time.Now().UTC().Add(-24 * time.Hour),
		AccountID:         "legacy-account",
		AccountType:       AccountTypeCodex,
		OriginID:          "legacy-origin",
		InputTokens:       120,
		CachedInputTokens: 80,
		OutputTokens:      15,
		BillableTokens:    55,
	}
	encoded, err := json.Marshal(usage)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(bucketUsageRequests))
		if err != nil {
			return err
		}
		key := fmt.Sprintf("%s|%020d|legacy", usage.AccountID, usage.Timestamp.UnixNano())
		return bucket.Put([]byte(key), encoded)
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := newUsageStore(path, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// Serialize behind the startup backfill and return only once its marker is
	// durable. This keeps the test deterministic without sleeps.
	store.backfillOriginWeeklyUsage(time.Now().UTC())

	rows, err := store.getOriginWeeklyUsage(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("weekly rows = %d, want 1", len(rows))
	}
	if rows[0].OriginID != usage.OriginID || rows[0].AccountID != hashAccountID(usage.AccountID) || rows[0].BillableTokens != usage.BillableTokens {
		t.Fatalf("weekly row = %+v", rows[0])
	}
}
