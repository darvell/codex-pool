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

func TestCompactUsageDatabaseRewritesLegacyRows(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.db")
	outputPath := filepath.Join(dir, "output.db")
	store, err := newUsageStore(sourcePath, 30)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Nanosecond)
	if err := store.record(RequestUsage{Timestamp: now, AccountID: "new", RequestID: "new-request", InputTokens: 1}); err != nil {
		t.Fatal(err)
	}
	legacy := RequestUsage{Timestamp: now.Add(-time.Hour), AccountID: "legacy", RequestID: "legacy-request", InputTokens: 2}
	legacyValue, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketUsageRequests))
		if err := bucket.SetSequence(42); err != nil {
			return err
		}
		key := fmt.Sprintf("legacy|%020d|%s", legacy.Timestamp.UnixNano(), legacy.RequestID)
		return bucket.Put([]byte(key), legacyValue)
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := compactUsageDatabase(sourcePath, outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if result.RewrittenRows != 1 || result.BeforeBytes == 0 || result.AfterBytes == 0 {
		t.Fatalf("result=%+v", result)
	}

	db, err := bbolt.Open(outputPath, 0o600, &bbolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := verifyBoltCopy(sourcePath, outputPath); err != nil {
		t.Fatal(err)
	}
	if err := db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketUsageRequests))
		if bucket.Sequence() != 42 {
			t.Fatalf("sequence=%d, want 42", bucket.Sequence())
		}
		rows := 0
		err := bucket.ForEach(func(key, value []byte) error {
			rows++
			if !strings.HasPrefix(string(key), usageTimeKeyPrefix) {
				t.Fatalf("legacy key remains: %q", key)
			}
			var usage RequestUsage
			if err := decodeRequestUsage(value, &usage); err != nil {
				return err
			}
			if usage.AccountID != "new" && usage.AccountID != "legacy" {
				t.Fatalf("unexpected usage: %+v", usage)
			}
			return nil
		})
		if rows != 2 {
			t.Fatalf("rows=%d, want 2", rows)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCompactUsageDatabaseRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	output := filepath.Join(dir, "output.db")
	db, err := bbolt.Open(source, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := compactUsageDatabase(source, output); err == nil {
		t.Fatal("compaction overwrote an existing output")
	}
}
