package main

import (
	"math"
	"path/filepath"
	"testing"
	"time"
)

func TestRebuildPricingFromBoltDBRestoresCacheCreationAndCosts(t *testing.T) {
	usage, err := newUsageStore(filepath.Join(t.TempDir(), "usage.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	defer usage.Close()

	now := time.Now().UTC()
	ru := RequestUsage{
		Timestamp:           now,
		AccountID:           "claude-account",
		AccountType:         AccountTypeClaude,
		Model:               "claude-sonnet-5",
		InputTokens:         100, // Anthropic: uncached input only.
		CachedInputTokens:   900,
		CacheCreationTokens: 100,
		OutputTokens:        10,
	}
	if err := usage.record(ru); err != nil {
		t.Fatal(err)
	}

	analytics, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer analytics.Close()
	pricing := newPricingData()
	if err := analytics.rebuildPricingFromBoltDB(usage, pricing); err != nil {
		t.Fatal(err)
	}

	var input, cached, cacheCreation int64
	var cost float64
	if err := analytics.db.QueryRow(`SELECT input_tokens, cached_tokens, cache_creation_tokens, cost_usd FROM request_costs`).Scan(&input, &cached, &cacheCreation, &cost); err != nil {
		t.Fatal(err)
	}
	if input != 100 || cached != 900 || cacheCreation != 100 {
		t.Fatalf("rebuilt tokens = input:%d cached:%d creation:%d", input, cached, cacheCreation)
	}
	want := 100*2e-6 + 900*0.2e-6 + 100*2.5e-6 + 10*10e-6
	if math.Abs(cost-want) > 1e-12 {
		t.Fatalf("rebuilt cost = %.12f, want %.12f", cost, want)
	}

	// The version marker makes startup idempotent.
	if err := analytics.rebuildPricingFromBoltDB(usage, pricing); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := analytics.db.QueryRow(`SELECT COUNT(*) FROM request_costs`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("second rebuild produced %d rows, want 1", count)
	}
}
