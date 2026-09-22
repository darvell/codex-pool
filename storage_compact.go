package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.etcd.io/bbolt"
)

const (
	boltCompactTransactionBytes = 64 << 20
	boltRewriteBatchSize        = 2048
)

type boltCompactionResult struct {
	BeforeBytes   int64
	AfterBytes    int64
	RewrittenRows int
}

type usageRewrite struct {
	oldKey []byte
	newKey []byte
	value  []byte
}

func compactUsageDatabase(sourcePath, outputPath string) (result boltCompactionResult, err error) {
	if sourcePath == "" || outputPath == "" {
		return result, errors.New("source and output paths are required")
	}
	if filepath.Clean(sourcePath) == filepath.Clean(outputPath) {
		return result, errors.New("compacted output must differ from source")
	}
	if _, err := os.Stat(outputPath); err == nil {
		return result, fmt.Errorf("compacted output already exists: %s", outputPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	info, err := os.Stat(sourcePath)
	if err != nil {
		return result, err
	}
	result.BeforeBytes = info.Size()
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return result, err
	}

	temp, err := os.CreateTemp(filepath.Dir(outputPath), ".bolt-compact-*.db")
	if err != nil {
		return result, err
	}
	tempPath := temp.Name()
	if err := temp.Close(); err != nil {
		return result, err
	}
	defer os.Remove(tempPath)
	final, err := os.CreateTemp(filepath.Dir(outputPath), ".bolt-verified-*.db")
	if err != nil {
		return result, err
	}
	finalPath := final.Name()
	defer os.Remove(finalPath)
	if err := final.Close(); err != nil {
		return result, err
	}

	if err = compactBoltCopy(sourcePath, tempPath); err != nil {
		return result, err
	}
	result.RewrittenRows, err = rewriteUsageRows(tempPath)
	if err != nil {
		return result, err
	}
	if err = compactBoltCopy(tempPath, finalPath); err != nil {
		return result, err
	}
	if err = checkBoltDatabase(finalPath); err != nil {
		return result, err
	}
	if err = verifyBoltCopy(sourcePath, finalPath); err != nil {
		return result, err
	}
	info, err = os.Stat(finalPath)
	if err != nil {
		return result, err
	}
	result.AfterBytes = info.Size()
	// Publish only verified data, without replacing an existing path or symlink.
	if err = os.Link(finalPath, outputPath); err != nil {
		return result, err
	}
	return result, nil
}

func compactBoltCopy(sourcePath, outputPath string) error {
	source, err := bbolt.Open(sourcePath, 0o600, &bbolt.Options{ReadOnly: true, Timeout: 2 * time.Second})
	if err != nil {
		return fmt.Errorf("open source Bolt database: %w", err)
	}
	defer source.Close()

	output, err := bbolt.Open(outputPath, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return fmt.Errorf("open compacted Bolt database: %w", err)
	}
	if err := bbolt.Compact(output, source, boltCompactTransactionBytes); err != nil {
		output.Close()
		return fmt.Errorf("compact Bolt database: %w", err)
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}

func rewriteUsageRows(path string) (int, error) {
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return 0, err
	}
	defer db.Close()

	total := 0
	for {
		batch := make([]usageRewrite, 0, boltRewriteBatchSize)
		err := db.View(func(tx *bbolt.Tx) error {
			bucket := tx.Bucket([]byte(bucketUsageRequests))
			if bucket == nil {
				return nil
			}
			cursor := bucket.Cursor()
			for key, value := cursor.Seek([]byte{1}); key != nil && len(batch) < boltRewriteBatchSize; key, value = cursor.Next() {
				var usage RequestUsage
				if err := decodeRequestUsage(value, &usage); err != nil {
					return fmt.Errorf("decode usage row %q: %w", key, err)
				}
				newKey := fmt.Sprintf("%s%020d|%s", usageTimeKeyPrefix, usage.Timestamp.UnixNano(), safeID(usage.AccountID))
				if usage.RequestID != "" {
					newKey += "|" + usage.RequestID
				}
				encoded, err := encodeRequestUsage(usage)
				if err != nil {
					return err
				}
				batch = append(batch, usageRewrite{
					oldKey: append([]byte(nil), key...),
					newKey: []byte(newKey),
					value:  encoded,
				})
			}
			return nil
		})
		if err != nil {
			return total, err
		}
		if len(batch) == 0 {
			return total, nil
		}
		if err := db.Update(func(tx *bbolt.Tx) error {
			bucket := tx.Bucket([]byte(bucketUsageRequests))
			bucket.FillPercent = 0.9
			for _, row := range batch {
				if existing := bucket.Get(row.newKey); existing != nil {
					return fmt.Errorf("usage key collision while compacting %q", row.newKey)
				}
				if err := bucket.Put(row.newKey, row.value); err != nil {
					return err
				}
				if err := bucket.Delete(row.oldKey); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return total, err
		}
		total += len(batch)
	}
}

func checkBoltDatabase(path string) error {
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{ReadOnly: true, Timeout: 2 * time.Second})
	if err != nil {
		return err
	}
	defer db.Close()
	return db.View(func(tx *bbolt.Tx) error {
		var first error
		for err := range tx.Check() {
			if first == nil {
				first = err
			}
		}
		return first
	})
}

func verifyBoltCopy(sourcePath, outputPath string) error {
	source, err := bbolt.Open(sourcePath, 0o600, &bbolt.Options{ReadOnly: true, Timeout: 2 * time.Second})
	if err != nil {
		return err
	}
	defer source.Close()
	output, err := bbolt.Open(outputPath, 0o600, &bbolt.Options{ReadOnly: true, Timeout: 2 * time.Second})
	if err != nil {
		return err
	}
	defer output.Close()
	return source.View(func(src *bbolt.Tx) error {
		return output.View(func(dst *bbolt.Tx) error {
			if err := src.ForEach(func(name []byte, bucket *bbolt.Bucket) error {
				return verifyBoltBucket(bucket, dst.Bucket(name), string(name))
			}); err != nil {
				return err
			}
			return dst.ForEach(func(name []byte, _ *bbolt.Bucket) error {
				if src.Bucket(name) == nil {
					return errors.New("unexpected compacted bucket")
				}
				return nil
			})
		})
	})
}

func verifyBoltBucket(src, dst *bbolt.Bucket, name string) error {
	if dst == nil || src.Sequence() != dst.Sequence() || src.Stats().KeyN != dst.Stats().KeyN {
		return fmt.Errorf("compacted bucket structure differs: %s", name)
	}
	return src.ForEach(func(key, value []byte) error {
		if value == nil {
			return verifyBoltBucket(src.Bucket(key), dst.Bucket(key), name+"/"+string(key))
		}
		if name != bucketUsageRequests {
			if !bytes.Equal(value, dst.Get(key)) {
				return fmt.Errorf("compacted bucket contents differ: %s", name)
			}
			return nil
		}
		var before, after RequestUsage
		if err := decodeRequestUsage(value, &before); err != nil {
			return err
		}
		if !bytes.HasPrefix(key, []byte(usageTimeKeyPrefix)) {
			key = []byte(fmt.Sprintf("%s%020d|%s", usageTimeKeyPrefix, before.Timestamp.UnixNano(), safeID(before.AccountID)))
			if before.RequestID != "" {
				key = append(key, []byte("|"+before.RequestID)...)
			}
		}
		if err := decodeRequestUsage(dst.Get(key), &after); err != nil {
			return err
		}
		before.Timestamp = before.Timestamp.UTC()
		before.PrimaryResetAt = before.PrimaryResetAt.UTC()
		before.SecondaryResetAt = before.SecondaryResetAt.UTC()
		after.Timestamp = after.Timestamp.UTC()
		after.PrimaryResetAt = after.PrimaryResetAt.UTC()
		after.SecondaryResetAt = after.SecondaryResetAt.UTC()
		if before != after {
			return errors.New("compacted usage row differs")
		}
		return nil
	})
}
