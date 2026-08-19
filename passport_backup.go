package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
	"go.etcd.io/bbolt"
)

const passportBackupFormat = 1

type backupFileManifest struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type passportBackupManifest struct {
	Format    int                `json:"format"`
	CreatedAt time.Time          `json:"created_at"`
	Bolt      backupFileManifest `json:"bolt"`
	DuckDB    backupFileManifest `json:"duckdb"`
}

func fileManifest(path string) (backupFileManifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return backupFileManifest{}, err
	}
	defer file.Close()
	hash := sha256.New()
	bytes, err := io.Copy(hash, file)
	if err != nil {
		return backupFileManifest{}, err
	}
	return backupFileManifest{Name: filepath.Base(path), SHA256: hex.EncodeToString(hash.Sum(nil)), Bytes: bytes}, nil
}

func copyFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = output.Close()
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	ok = true
	return output.Close()
}

func createPairedBackup(boltPath, duckPath, directory string) (string, error) {
	if directory == "" {
		return "", errors.New("backup directory required")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	boltBackup := filepath.Join(directory, "proxy-"+stamp+".db")
	duckBackup := filepath.Join(directory, "usage-"+stamp+".duckdb")

	bolt, err := bbolt.Open(boltPath, 0o600, &bbolt.Options{ReadOnly: true, Timeout: 2 * time.Second})
	if err != nil {
		return "", fmt.Errorf("open Bolt read-only (stop the service before backup): %w", err)
	}
	if err := bolt.View(func(tx *bbolt.Tx) error { return tx.CopyFile(boltBackup, 0o600) }); err != nil {
		bolt.Close()
		return "", fmt.Errorf("copy Bolt: %w", err)
	}
	if err := bolt.Close(); err != nil {
		return "", err
	}

	duck, err := sql.Open("duckdb", duckPath)
	if err != nil {
		return "", err
	}
	if _, err := duck.Exec("CHECKPOINT"); err != nil {
		duck.Close()
		return "", fmt.Errorf("checkpoint DuckDB (stop the service before backup): %w", err)
	}
	if err := duck.Close(); err != nil {
		return "", err
	}
	if err := copyFile(duckPath, duckBackup, 0o600); err != nil {
		return "", fmt.Errorf("copy DuckDB: %w", err)
	}

	boltFile, err := fileManifest(boltBackup)
	if err != nil {
		return "", err
	}
	duckFile, err := fileManifest(duckBackup)
	if err != nil {
		return "", err
	}
	manifest := passportBackupManifest{Format: passportBackupFormat, CreatedAt: time.Now().UTC(), Bolt: boltFile, DuckDB: duckFile}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	manifestPath := filepath.Join(directory, "passport-backup-"+stamp+".json")
	if err := os.WriteFile(manifestPath, append(encoded, '\n'), 0o600); err != nil {
		return "", err
	}
	return manifestPath, nil
}

func verifyBackupFile(path string, expected backupFileManifest) error {
	actual, err := fileManifest(path)
	if err != nil {
		return err
	}
	if actual.Bytes != expected.Bytes || actual.SHA256 != expected.SHA256 {
		return fmt.Errorf("backup checksum mismatch for %s", expected.Name)
	}
	return nil
}

func restorePairedBackup(manifestPath, boltPath, duckPath string) error {
	encoded, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest passportBackupManifest
	if json.Unmarshal(encoded, &manifest) != nil || manifest.Format != passportBackupFormat {
		return errors.New("unsupported backup manifest")
	}
	directory := filepath.Dir(manifestPath)
	boltBackup := filepath.Join(directory, manifest.Bolt.Name)
	duckBackup := filepath.Join(directory, manifest.DuckDB.Name)
	if err := verifyBackupFile(boltBackup, manifest.Bolt); err != nil {
		return err
	}
	if err := verifyBackupFile(duckBackup, manifest.DuckDB); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(boltPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(duckPath), 0o700); err != nil {
		return err
	}
	boltTemp, duckTemp := boltPath+".restore", duckPath+".restore"
	_ = os.Remove(boltTemp)
	_ = os.Remove(duckTemp)
	if err := copyFile(boltBackup, boltTemp, 0o600); err != nil {
		return err
	}
	if err := copyFile(duckBackup, duckTemp, 0o600); err != nil {
		_ = os.Remove(boltTemp)
		return err
	}
	if err := os.Rename(boltTemp, boltPath); err != nil {
		return err
	}
	if err := os.Rename(duckTemp, duckPath); err != nil {
		return err
	}
	return nil
}
