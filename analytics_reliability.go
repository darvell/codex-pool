package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"go.etcd.io/bbolt"
)

const analyticsGapsKey = "accounting_gaps"

func (s *usageStore) loadActiveAccountingGapSidecar() {
	if s == nil || s.analyticsGapPath == "" {
		return
	}
	encoded, err := os.ReadFile(s.analyticsGapPath)
	if err != nil {
		return
	}
	var gap AccountingGap
	if json.Unmarshal(encoded, &gap) == nil && !gap.StartedAt.IsZero() && gap.EndedAt == nil {
		s.analyticsGap = &gap
	}
}

func (s *usageStore) persistActiveAccountingGapSidecar(gap *AccountingGap) {
	if s == nil || s.analyticsGapPath == "" || gap == nil {
		return
	}
	encoded, err := json.Marshal(gap)
	if err != nil {
		return
	}
	temporary := s.analyticsGapPath + ".tmp"
	if os.WriteFile(temporary, encoded, 0o600) == nil {
		_ = os.Rename(temporary, s.analyticsGapPath)
	}
}

type AccountingGap struct {
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Reason    string     `json:"reason"`
}

func (s *usageStore) configureAnalyticsReserve(path string, bytes int64) error {
	if s == nil || bytes <= 0 {
		return nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	block := make([]byte, 1024*1024)
	for written := int64(0); written < bytes; {
		chunk := int64(len(block))
		if remaining := bytes - written; remaining < chunk {
			chunk = remaining
		}
		n, err := file.Write(block[:chunk])
		if err != nil {
			return err
		}
		written += int64(n)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	s.analyticsReliabilityMu.Lock()
	s.analyticsReservePath = path
	s.analyticsReliabilityMu.Unlock()
	return nil
}

func (s *usageStore) releaseAnalyticsReserve() bool {
	s.analyticsReliabilityMu.Lock()
	path := s.analyticsReservePath
	s.analyticsReservePath = ""
	s.analyticsReliabilityMu.Unlock()
	if path == "" {
		return false
	}
	return os.Remove(path) == nil
}

func (s *usageStore) recordReliably(usage RequestUsage, costUSD float64) error {
	err := s.recordWithCost(usage, costUSD)
	if err == nil {
		s.closeAccountingGap(usage.Timestamp)
		return nil
	}
	if s.releaseAnalyticsReserve() {
		if retryErr := s.recordWithCost(usage, costUSD); retryErr == nil {
			s.closeAccountingGap(usage.Timestamp)
			return nil
		} else {
			err = retryErr
		}
	}
	s.openAccountingGap(usage.Timestamp, err)
	return err
}

func (s *usageStore) loadAccountingGaps(tx *bbolt.Tx) []AccountingGap {
	var gaps []AccountingGap
	if bucket := tx.Bucket([]byte(bucketAnalyticsState)); bucket != nil {
		_ = json.Unmarshal(bucket.Get([]byte(analyticsGapsKey)), &gaps)
	}
	return gaps
}

func (s *usageStore) persistAccountingGap(gap AccountingGap) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketAnalyticsState))
		if bucket == nil {
			return errors.New("analytics state bucket missing")
		}
		gaps := s.loadAccountingGaps(tx)
		gaps = append(gaps, gap)
		encoded, err := json.Marshal(gaps)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(analyticsGapsKey), encoded)
	})
}

func (s *usageStore) openAccountingGap(at time.Time, cause error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	s.analyticsReliabilityMu.Lock()
	if s.analyticsGap == nil {
		s.analyticsGap = &AccountingGap{StartedAt: at.UTC(), Reason: fmt.Sprintf("durable usage write failed: %v", cause)}
	}
	gap := *s.analyticsGap
	s.analyticsReliabilityMu.Unlock()
	s.persistActiveAccountingGapSidecar(&gap)
}

func (s *usageStore) closeAccountingGap(at time.Time) {
	s.analyticsReliabilityMu.Lock()
	if s.analyticsGap == nil {
		s.analyticsReliabilityMu.Unlock()
		return
	}
	gap := *s.analyticsGap
	ended := at.UTC()
	if ended.Before(gap.StartedAt) {
		ended = time.Now().UTC()
	}
	gap.EndedAt = &ended
	s.analyticsReliabilityMu.Unlock()
	if s.persistAccountingGap(gap) == nil {
		s.analyticsReliabilityMu.Lock()
		if s.analyticsGap != nil && s.analyticsGap.StartedAt.Equal(gap.StartedAt) {
			s.analyticsGap = nil
		}
		s.analyticsReliabilityMu.Unlock()
		_ = os.Remove(s.analyticsGapPath)
	}
}

func (s *usageStore) accountingGaps() ([]AccountingGap, *AccountingGap, error) {
	gaps := make([]AccountingGap, 0)
	err := s.db.View(func(tx *bbolt.Tx) error {
		gaps = s.loadAccountingGaps(tx)
		return nil
	})
	s.analyticsReliabilityMu.Lock()
	var active *AccountingGap
	if s.analyticsGap != nil {
		copy := *s.analyticsGap
		active = &copy
	}
	s.analyticsReliabilityMu.Unlock()
	return gaps, active, err
}
