package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Measure authorization across cached principals to expose per-request database
// work through its latency and allocations.
func BenchmarkAuthorizePrincipal(b *testing.B) {
	b.Setenv("POOL_AUTH_ENCRYPTION_KEY", "bench-passport-encryption-key")
	store, err := newUsageStore(filepath.Join(b.TempDir(), "proxy.db"), 30)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.Close() })
	passport, err := newPassportStore(store.db, nil, passportOptions{})
	if err != nil {
		b.Fatal(err)
	}

	const principals = 200
	identities := make([]string, 0, principals)
	for i := 0; i < principals; i++ {
		pr, _, client, _, err := passport.createGuest("operator", fmt.Sprintf("bench principal %d", i), "", nil)
		if err != nil {
			b.Fatal(err)
		}
		identities = append(identities, pr.ID+"-c-"+client.ID)
	}

	issuedAt := time.Now().Add(-time.Hour)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		identity := identities[i%len(identities)]
		if _, _, ok := passport.authorizeIssuedCredential(identity, issuedAt); !ok {
			b.Fatalf("authorization denied for %s", identity)
		}
	}
}

// Set ANALYTICS_BENCH_ROWS to measure query latency with a staging-sized ledger.
// The allocator can exceed a development machine's memory budget.
func BenchmarkDuckDBUsageQueries(b *testing.B) {
	if os.Getenv("ANALYTICS_BENCH_ROWS") == "" {
		b.Skip("skipped locally; set ANALYTICS_BENCH_ROWS to run on staging hardware")
	}
	b.Setenv("POOL_AUTH_ENCRYPTION_KEY", "bench-passport-encryption-key")
	store, err := newUsageStore(filepath.Join(b.TempDir(), "proxy.db"), 30)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.Close() })
	analytics, err := newDuckAnalytics(filepath.Join(b.TempDir(), "usage.duckdb"), store.db)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = analytics.Close() })

	mem := os.Getenv("ANALYTICS_BENCH_MEMORY")
	if mem == "" {
		mem = "4GB"
	}
	if _, err := analytics.db.Exec("SET memory_limit='" + mem + "'"); err != nil {
		b.Fatal(err)
	}
	if _, err := analytics.db.Exec("SET threads=2"); err != nil {
		b.Fatal(err)
	}
	if _, err := analytics.db.Exec("SET preserve_insertion_order=false"); err != nil {
		b.Fatal(err)
	}

	seedAnalyticsFacts(b, analytics, analyticsBenchRows(b))

	ctx := context.Background()
	selfSince := time.Now().Add(-30 * 24 * time.Hour)
	operatorSince := time.Now().Add(-365 * 24 * time.Hour)

	b.Run("self-30d", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			points, err := analytics.UserHourly(ctx, "principal-0", selfSince)
			if err != nil {
				b.Fatal(err)
			}
			if len(points) == 0 {
				b.Fatal("self query returned no points")
			}
		}
	})

	b.Run("operator-1y", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ranking, err := analytics.PrincipalRanking(ctx, operatorSince)
			if err != nil {
				b.Fatal(err)
			}
			if len(ranking) == 0 {
				b.Fatal("operator ranking returned no rows")
			}
		}
	})
}

func analyticsBenchRows(b *testing.B) int {
	raw := os.Getenv("ANALYTICS_BENCH_ROWS")
	if raw == "" {
		return 50_000
	}
	rows, err := strconv.Atoi(raw)
	if err != nil || rows <= 0 {
		b.Fatalf("ANALYTICS_BENCH_ROWS=%q is not a positive integer", raw)
	}
	return rows
}

// seedAnalyticsFacts writes representative facts straight into DuckDB using the
// same column order the outbox drain uses. Routing millions of rows through the
// Bolt outbox would measure the outbox rather than the query shapes under test.
// Inserts run in batches to stay within the DuckDB memory budget.
func seedAnalyticsFacts(b *testing.B, a *DuckAnalytics, rows int) {
	b.Helper()
	const (
		principals = 50
		batchSize  = 10000
	)
	providers := []string{"codex", "claude", "gemini", "kimi", "minimax"}
	models := []string{"gpt-5.6", "claude-opus-5", "gemini-3-pro", "kimi-k2", "minimax-m2"}
	spread := 365 * 24 * time.Hour

	now := time.Now().UTC()
	for start := 0; start < rows; start += batchSize {
		end := start + batchSize
		if end > rows {
			end = rows
		}
		tx, err := a.db.Begin()
		if err != nil {
			b.Fatal(err)
		}
		stmt, err := tx.Prepare(`INSERT OR IGNORE INTO usage_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			_ = tx.Rollback()
			b.Fatal(err)
		}
		for i := start; i < end; i++ {
			principal := fmt.Sprintf("principal-%d", i%principals)
			provider := providers[i%len(providers)]
			observed := now.Add(-time.Duration(float64(spread) * float64(i) / float64(rows)))
			if _, err := stmt.Exec(
				fmt.Sprintf("event-%d", i), fmt.Sprintf("request-%d", i), 1, fmt.Sprintf("upstream-%d", i), 1, observed,
				principal, fmt.Sprintf("%s-c-%d", principal, i%3), fmt.Sprintf("origin-%d", i%97),
				fmt.Sprintf("account-%d", i%9), provider, "pro", models[i%len(models)], models[i%len(models)],
				"model-id-v1", int64(1200+i%800), int64(i%5000), int64(i%300), int64(400+i%600), int64(i%200),
				int64(1600+i%1400), 0.0042, analyticsPricingVersion, "complete", "bench", "request",
			); err != nil {
				_ = stmt.Close()
				_ = tx.Rollback()
				b.Fatal(err)
			}
		}
		if err := stmt.Close(); err != nil {
			_ = tx.Rollback()
			b.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			b.Fatal(err)
		}
	}
}
