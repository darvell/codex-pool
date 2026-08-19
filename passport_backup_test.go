package main

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/duckdb/duckdb-go/v2"
	"go.etcd.io/bbolt"
)

func TestPairedBackupManifestRestore(t *testing.T) {
	directory := t.TempDir()
	boltPath := filepath.Join(directory, "proxy.db")
	duckPath := filepath.Join(directory, "usage.duckdb")
	backupDir := filepath.Join(directory, "backups")

	bolt, err := bbolt.Open(boltPath, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := bolt.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("proof"))
		if err != nil {
			return err
		}
		return bucket.Put([]byte("value"), []byte("before"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := bolt.Close(); err != nil {
		t.Fatal(err)
	}

	duck, err := sql.Open("duckdb", duckPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := duck.Exec("CREATE TABLE proof(value VARCHAR); INSERT INTO proof VALUES ('before')"); err != nil {
		t.Fatal(err)
	}
	if err := duck.Close(); err != nil {
		t.Fatal(err)
	}

	manifest, err := createPairedBackup(boltPath, duckPath, backupDir)
	if err != nil {
		t.Fatal(err)
	}

	bolt, err = bbolt.Open(boltPath, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := bolt.Update(func(tx *bbolt.Tx) error { return tx.Bucket([]byte("proof")).Put([]byte("value"), []byte("after")) }); err != nil {
		t.Fatal(err)
	}
	if err := bolt.Close(); err != nil {
		t.Fatal(err)
	}
	duck, err = sql.Open("duckdb", duckPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := duck.Exec("UPDATE proof SET value='after'"); err != nil {
		t.Fatal(err)
	}
	if err := duck.Close(); err != nil {
		t.Fatal(err)
	}

	if err := restorePairedBackup(manifest, boltPath, duckPath); err != nil {
		t.Fatal(err)
	}
	bolt, err = bbolt.Open(boltPath, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := bolt.View(func(tx *bbolt.Tx) error {
		if value := string(tx.Bucket([]byte("proof")).Get([]byte("value"))); value != "before" {
			t.Fatalf("restored Bolt value = %q", value)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = bolt.Close()
	duck, err = sql.Open("duckdb", duckPath)
	if err != nil {
		t.Fatal(err)
	}
	var value string
	if err := duck.QueryRow("SELECT value FROM proof").Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "before" {
		t.Fatalf("restored DuckDB value = %q", value)
	}
	_ = duck.Close()
}
