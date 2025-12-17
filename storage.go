package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

const (
	bucketUsageRequests = "usage_requests"
	bucketAccountUsage  = "account_usage"
)

type usageStore struct {
	db        *bbolt.DB
	retention time.Duration
	nextPrune time.Time
}

func newUsageStore(path string, retentionDays int) (*usageStore, error) {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		if _, e := tx.CreateBucketIfNotExists([]byte(bucketUsageRequests)); e != nil {
			return e
		}
		if _, e := tx.CreateBucketIfNotExists([]byte(bucketAccountUsage)); e != nil {
			return e
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	return &usageStore{db: db, retention: time.Duration(retentionDays) * 24 * time.Hour, nextPrune: time.Now().Add(1 * time.Hour)}, nil
}

func (s *usageStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *usageStore) record(u RequestUsage) error {
	if s == nil || s.db == nil {
		return nil
	}
	key := fmt.Sprintf("%s|%020d", safeID(u.AccountID), u.Timestamp.UnixNano())
	if u.RequestID != "" {
		key = key + "|" + u.RequestID
	}
	val, err := json.Marshal(u)
	if err != nil {
		return err
	}
	err = s.db.Update(func(tx *bbolt.Tx) error {
		if err := tx.Bucket([]byte(bucketUsageRequests)).Put([]byte(key), val); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketAccountUsage))
		var agg AccountUsage
		if raw := b.Get([]byte(u.AccountID)); raw != nil {
			_ = json.Unmarshal(raw, &agg)
		}
		agg.TotalInputTokens += u.InputTokens
		agg.TotalCachedTokens += u.CachedInputTokens
		agg.TotalOutputTokens += u.OutputTokens
		agg.TotalBillableTokens += u.BillableTokens
		if enc, err := json.Marshal(&agg); err == nil {
			_ = b.Put([]byte(u.AccountID), enc)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if time.Now().After(s.nextPrune) {
		s.prune()
	}
	return nil
}

func (s *usageStore) prune() {
	cutoff := time.Now().Add(-s.retention)
	_ = s.db.Update(func(tx *bbolt.Tx) error {
		c := tx.Bucket([]byte(bucketUsageRequests)).Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			parts := strings.Split(string(k), "|")
			if len(parts) < 2 {
				continue
			}
			ts, err := timeFromKey(parts[1])
			if err != nil {
				continue
			}
			if ts.Before(cutoff) {
				_ = c.Delete()
			} else {
				// keys are ordered; can break once beyond cutoff
				break
			}
		}
		return nil
	})
	s.nextPrune = time.Now().Add(1 * time.Hour)
}

func timeFromKey(tsPart string) (time.Time, error) {
	var n int64
	if _, err := fmt.Sscanf(tsPart, "%d", &n); err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, n), nil
}

func safeID(id string) string {
	if id == "" {
		return "unknown"
	}
	return id
}

// loadAccountUsage is used in tests to fetch aggregates.
func (s *usageStore) loadAccountUsage(accountID string) (AccountUsage, error) {
	var out AccountUsage
	if s == nil || s.db == nil {
		return out, nil
	}
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketAccountUsage))
		if raw := b.Get([]byte(accountID)); raw != nil {
			return json.Unmarshal(raw, &out)
		}
		return nil
	})
	return out, err
}
