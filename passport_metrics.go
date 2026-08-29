package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.etcd.io/bbolt"
)

func activePassportSessions(passport *PassportStore) int {
	if passport == nil {
		return 0
	}
	now := time.Now()
	count := 0
	_ = passport.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketPassportSessions)).ForEach(func(_, value []byte) error {
			var session passportSession
			if json.Unmarshal(value, &session) == nil && now.Before(session.ExpiresAt) {
				count++
			}
			return nil
		})
	})
	return count
}

func fileBytes(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func (h *proxyHandler) serveOperationalMetrics(w http.ResponseWriter, r *http.Request) {
	h.metrics.serve(w, r)
	fmt.Fprintf(w, "codexpool_active_sessions %d\n", activePassportSessions(h.passport))
	if h.duckAnalytics != nil {
		health := h.duckAnalytics.Health()
		fmt.Fprintf(w, "codexpool_analytics_outbox_depth %d\n", health.OutboxDepth)
		age := 0.0
		if health.OldestOutboxAt != nil {
			age = time.Since(*health.OldestOutboxAt).Seconds()
			if age < 0 {
				age = 0
			}
		}
		fmt.Fprintf(w, "codexpool_analytics_outbox_oldest_age_seconds %.3f\n", age)
		faulted := 0
		if health.State == "FAULTED" {
			faulted = 1
		}
		fmt.Fprintf(w, "codexpool_analytics_faulted %d\n", faulted)
	}
	if h.store != nil {
		_, active, _ := h.store.accountingGaps()
		open := 0
		if active != nil {
			open = 1
		}
		fmt.Fprintf(w, "codexpool_accounting_gap_open %d\n", open)
	}
	if h.cfg != nil {
		fmt.Fprintf(w, "codexpool_bolt_database_bytes %d\n", fileBytes(h.cfg.storePath))
		fmt.Fprintf(w, "codexpool_duckdb_database_bytes %d\n", fileBytes(h.cfg.duckPath))
	}
}
