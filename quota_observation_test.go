package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestQuotaObservationReturnsFailure(t *testing.T) {
	store, err := newAnalyticsStore(filepath.Join(t.TempDir(), "quota.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	h := &proxyHandler{analyticsStore: store, pool: newPoolState([]*Account{{ID: "account", Type: AccountTypeCodex}}, false)}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.recordQuotaWasteSnapshot(time.Now()); err == nil {
		t.Fatal("quota observation hid a database failure")
	}
}
