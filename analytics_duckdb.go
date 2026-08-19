package main

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
	"github.com/google/uuid"
	"go.etcd.io/bbolt"
)

const (
	bucketAnalyticsOutbox = "analytics_outbox"
	bucketAnalyticsState  = "analytics_state"
	analyticsAckKey       = "acknowledged_sequence"
)

type AnalyticsFact struct {
	EventID              string    `json:"event_id"`
	ProxyRequestID       string    `json:"proxy_request_id"`
	UsageSequence        int       `json:"usage_sequence"`
	AttemptNumber        int       `json:"attempt_number"`
	ObservedAt           time.Time `json:"observed_at"`
	PrincipalID          string    `json:"principal_id"`
	ClientCredentialID   string    `json:"client_credential_id"`
	OriginID             string    `json:"origin_id,omitempty"`
	UpstreamRequestID    string    `json:"upstream_request_id,omitempty"`
	AccountID            string    `json:"account_id"`
	AccountType          string    `json:"account_type"`
	PlanType             string    `json:"plan_type,omitempty"`
	ModelReported        string    `json:"model_reported,omitempty"`
	ModelNormalized      string    `json:"model_normalized,omitempty"`
	NormalizationVersion string    `json:"normalization_version"`
	InputTokens          int64     `json:"input_tokens"`
	CacheReadTokens      int64     `json:"cache_read_tokens"`
	CacheCreationTokens  int64     `json:"cache_creation_tokens"`
	OutputTokens         int64     `json:"output_tokens"`
	ReasoningTokens      int64     `json:"reasoning_tokens"`
	BillableTokens       int64     `json:"billable_tokens"`
	APIEquivalentCostUSD float64   `json:"api_equivalent_cost_usd"`
	PricingVersion       string    `json:"pricing_version"`
	UsageCompleteness    string    `json:"usage_completeness"`
	Source               string    `json:"source"`
	SourceGrain          string    `json:"source_grain"`
}

func analyticsFactFromUsage(ru RequestUsage, cost float64) AnalyticsFact {
	clientID := ru.ClientCredentialID
	if clientID == "" && ru.UserID != "" {
		clientID = "legacy-default"
	}
	proxyID := ru.ProxyRequestID
	if proxyID == "" {
		proxyID = ru.RequestID
	}
	if proxyID == "" {
		proxyID = uuid.NewString()
	}
	completeness := ru.UsageCompleteness
	if completeness == "" {
		completeness = "complete"
	}
	return AnalyticsFact{
		EventID: uuid.NewString(), ProxyRequestID: proxyID, UsageSequence: ru.UsageSequence,
		AttemptNumber: ru.AttemptNumber, ObservedAt: ru.Timestamp.UTC(), PrincipalID: ru.UserID,
		ClientCredentialID: clientID, OriginID: ru.OriginID, UpstreamRequestID: ru.RequestID,
		AccountID: ru.AccountID, AccountType: string(ru.AccountType), PlanType: ru.PlanType,
		ModelReported: ru.Model, ModelNormalized: ru.Model, NormalizationVersion: "model-id-v1",
		InputTokens: ru.InputTokens, CacheReadTokens: ru.CachedInputTokens,
		CacheCreationTokens: ru.CacheCreationTokens, OutputTokens: ru.OutputTokens,
		ReasoningTokens: ru.ReasoningTokens, BillableTokens: ru.BillableTokens,
		APIEquivalentCostUSD: cost, PricingVersion: analyticsPricingVersion, UsageCompleteness: completeness,
		Source: "live", SourceGrain: "request",
	}
}

func putAnalyticsOutbox(tx *bbolt.Tx, fact AnalyticsFact) error {
	b := tx.Bucket([]byte(bucketAnalyticsOutbox))
	if b == nil {
		return errors.New("analytics outbox bucket missing")
	}
	seq, err := b.NextSequence()
	if err != nil {
		return err
	}
	data, err := json.Marshal(fact)
	if err != nil {
		return err
	}
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], seq)
	return b.Put(key[:], data)
}

type DuckAnalytics struct {
	db             *sql.DB
	bolt           *bbolt.DB
	stop           chan struct{}
	done           chan struct{}
	wake           chan struct{}
	lag            atomic.Int64
	fault          atomic.Value
	reconciliation atomic.Value
	closeOnce      sync.Once
}

func newDuckAnalytics(path string, bolt *bbolt.DB) (*DuckAnalytics, error) {
	if bolt == nil {
		return nil, errors.New("bolt store required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("duckdb", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if memLimit := os.Getenv("DUCKDB_MEMORY_LIMIT"); memLimit != "" {
		if _, err := db.Exec("SET memory_limit='" + memLimit + "'"); err != nil {
			db.Close()
			return nil, fmt.Errorf("set duckdb memory limit: %w", err)
		}
	}
	schema := `
CREATE TABLE IF NOT EXISTS usage_events (
 event_id VARCHAR PRIMARY KEY, proxy_request_id VARCHAR NOT NULL, usage_sequence INTEGER NOT NULL,
 upstream_request_id VARCHAR, attempt_number INTEGER NOT NULL, observed_at TIMESTAMPTZ NOT NULL,
 principal_id VARCHAR NOT NULL, client_credential_id VARCHAR NOT NULL, origin_id VARCHAR,
 account_id VARCHAR NOT NULL, account_type VARCHAR NOT NULL, plan_type VARCHAR,
 model_reported VARCHAR, model_normalized VARCHAR, normalization_version VARCHAR NOT NULL,
 input_tokens BIGINT NOT NULL, cache_read_tokens BIGINT NOT NULL, cache_creation_tokens BIGINT NOT NULL,
 output_tokens BIGINT NOT NULL, reasoning_tokens BIGINT NOT NULL, billable_tokens BIGINT NOT NULL,
 api_equivalent_cost_usd DECIMAL(18,9) NOT NULL, pricing_version VARCHAR NOT NULL,
 usage_completeness VARCHAR NOT NULL, source VARCHAR NOT NULL, source_grain VARCHAR NOT NULL
);`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create duckdb schema: %w", err)
	}
	a := &DuckAnalytics{db: db, bolt: bolt, stop: make(chan struct{}), done: make(chan struct{}), wake: make(chan struct{}, 1)}
	if err := a.importLegacyBolt(); err != nil {
		db.Close()
		return nil, fmt.Errorf("import legacy analytics: %w", err)
	}
	go a.run()
	return a, nil
}

func (a *DuckAnalytics) importLegacyBolt() error {
	const markerKey = "legacy_bolt_import_v1"
	alreadyImported := false
	if err := a.bolt.View(func(tx *bbolt.Tx) error {
		alreadyImported = tx.Bucket([]byte(bucketAnalyticsState)).Get([]byte(markerKey)) != nil
		return nil
	}); err != nil || alreadyImported {
		return err
	}

	duckTx, err := a.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := duckTx.Prepare(`INSERT OR IGNORE INTO usage_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = duckTx.Rollback()
		return err
	}
	defer stmt.Close()
	insert := func(f AnalyticsFact) error {
		_, err := stmt.Exec(f.EventID, f.ProxyRequestID, f.UsageSequence, f.UpstreamRequestID, f.AttemptNumber, f.ObservedAt,
			f.PrincipalID, f.ClientCredentialID, f.OriginID, f.AccountID, f.AccountType, f.PlanType, f.ModelReported,
			f.ModelNormalized, f.NormalizationVersion, f.InputTokens, f.CacheReadTokens, f.CacheCreationTokens,
			f.OutputTokens, f.ReasoningTokens, f.BillableTokens, f.APIEquivalentCostUSD, f.PricingVersion,
			f.UsageCompleteness, f.Source, f.SourceGrain)
		return err
	}

	earliestRaw := map[string]time.Time{}
	rawCount, hourlyCount := 0, 0
	err = a.bolt.View(func(tx *bbolt.Tx) error {
		raw := tx.Bucket([]byte(bucketUsageRequests))
		if raw != nil {
			if err := raw.ForEach(func(key, value []byte) error {
				var usage RequestUsage
				if json.Unmarshal(value, &usage) != nil || usage.UserID == "" {
					return nil
				}
				principalID, clientID := splitClientIdentity(usage.UserID)
				if first, ok := earliestRaw[principalID]; !ok || usage.Timestamp.Before(first) {
					earliestRaw[principalID] = usage.Timestamp
				}
				proxyID := usage.ProxyRequestID
				if proxyID == "" {
					proxyID = usage.RequestID
				}
				if proxyID == "" {
					proxyID = "bolt:" + string(key)
				}
				completeness := usage.UsageCompleteness
				if completeness == "" {
					completeness = "complete"
				}
				fact := AnalyticsFact{EventID: uuid.NewSHA1(uuid.NameSpaceOID, append([]byte("bolt|"), key...)).String(), ProxyRequestID: proxyID, UsageSequence: usage.UsageSequence, AttemptNumber: usage.AttemptNumber, ObservedAt: usage.Timestamp.UTC(), PrincipalID: principalID, ClientCredentialID: clientID, OriginID: usage.OriginID, UpstreamRequestID: usage.RequestID, AccountID: usage.AccountID, AccountType: string(usage.AccountType), PlanType: usage.PlanType, ModelReported: usage.Model, ModelNormalized: usage.Model, NormalizationVersion: "legacy-v1", InputTokens: usage.InputTokens, CacheReadTokens: usage.CachedInputTokens, CacheCreationTokens: usage.CacheCreationTokens, OutputTokens: usage.OutputTokens, ReasoningTokens: usage.ReasoningTokens, BillableTokens: usage.BillableTokens, PricingVersion: "legacy-unavailable", UsageCompleteness: completeness, Source: "bolt_import", SourceGrain: "request"}
				if err := insert(fact); err != nil {
					return err
				}
				rawCount++
				return nil
			}); err != nil {
				return err
			}
		}
		hourly := tx.Bucket([]byte(bucketUserHourlyUsage))
		if hourly == nil {
			return nil
		}
		return hourly.ForEach(func(key, value []byte) error {
			parts := strings.Split(string(key), "|")
			if len(parts) != 3 {
				return nil
			}
			hour, err := time.Parse("2006-01-02T15", parts[1])
			if err != nil {
				return nil
			}
			if first, ok := earliestRaw[parts[0]]; ok && !hour.Before(first.UTC().Truncate(time.Hour)) {
				return nil
			}
			var aggregate UserHourlyUsage
			if json.Unmarshal(value, &aggregate) != nil {
				return nil
			}
			fact := AnalyticsFact{EventID: uuid.NewSHA1(uuid.NameSpaceOID, append([]byte("bolt-hour|"), key...)).String(), ProxyRequestID: "legacy-hour:" + string(key), ObservedAt: hour.UTC(), PrincipalID: parts[0], ClientCredentialID: "legacy-" + parts[0], AccountID: "legacy-aggregate", AccountType: parts[2], NormalizationVersion: "legacy-v1", InputTokens: aggregate.InputTokens, CacheReadTokens: aggregate.CachedTokens, OutputTokens: aggregate.OutputTokens, ReasoningTokens: aggregate.ReasoningTokens, BillableTokens: aggregate.BillableTokens, PricingVersion: "legacy-unavailable", UsageCompleteness: "estimated", Source: "bolt_import", SourceGrain: "hour"}
			if err := insert(fact); err != nil {
				return err
			}
			hourlyCount++
			return nil
		})
	})
	if err != nil {
		_ = duckTx.Rollback()
		return err
	}
	if err := duckTx.Commit(); err != nil {
		return err
	}
	report, _ := json.Marshal(map[string]any{"completed_at": time.Now().UTC(), "request_facts": rawCount, "hour_facts": hourlyCount, "sqlite_policy": "SQLite overlaps retained Bolt request facts and is not imported independently; historical cost remains unavailable where Bolt did not store it."})
	return a.bolt.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketAnalyticsState)).Put([]byte(markerKey), report)
	})
}

func (a *DuckAnalytics) Notify() {
	if a == nil {
		return
	}
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (a *DuckAnalytics) Close() error {
	if a == nil {
		return nil
	}
	a.closeOnce.Do(func() { close(a.stop); <-a.done })
	return a.db.Close()
}

func (a *DuckAnalytics) run() {
	defer close(a.done)
	t := time.NewTicker(250 * time.Millisecond)
	reconcileTicker := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	defer reconcileTicker.Stop()
	for {
		select {
		case <-a.stop:
			_ = a.drain(4096)
			return
		case <-a.wake:
			_ = a.drain(512)
		case <-t.C:
			_ = a.drain(512)
		case <-reconcileTicker.C:
			now := time.Now().UTC().Truncate(time.Hour)
			_, _ = a.Reconcile(now.Add(-time.Hour), now)
		}
	}
}

type outboxRow struct {
	seq  uint64
	fact AnalyticsFact
}

func (a *DuckAnalytics) drain(limit int) error {
	rows := make([]outboxRow, 0, limit)
	err := a.bolt.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketAnalyticsOutbox))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil && len(rows) < limit; k, v = c.Next() {
			var f AnalyticsFact
			if err := json.Unmarshal(v, &f); err != nil {
				return err
			}
			rows = append(rows, outboxRow{binary.BigEndian.Uint64(k), f})
		}
		return nil
	})
	if err != nil || len(rows) == 0 {
		return err
	}
	tx, err := a.db.Begin()
	if err != nil {
		a.setFault(err)
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO usage_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		a.setFault(err)
		return err
	}
	for _, r := range rows {
		f := r.fact
		_, err = stmt.Exec(f.EventID, f.ProxyRequestID, f.UsageSequence, f.UpstreamRequestID, f.AttemptNumber, f.ObservedAt,
			f.PrincipalID, f.ClientCredentialID, f.OriginID, f.AccountID, f.AccountType, f.PlanType, f.ModelReported,
			f.ModelNormalized, f.NormalizationVersion, f.InputTokens, f.CacheReadTokens, f.CacheCreationTokens,
			f.OutputTokens, f.ReasoningTokens, f.BillableTokens, f.APIEquivalentCostUSD, f.PricingVersion,
			f.UsageCompleteness, f.Source, f.SourceGrain)
		if err != nil {
			break
		}
	}
	_ = stmt.Close()
	if err == nil {
		err = tx.Commit()
	} else {
		_ = tx.Rollback()
	}
	if err != nil {
		a.setFault(err)
		return err
	}
	last := rows[len(rows)-1].seq
	err = a.bolt.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketAnalyticsOutbox))
		state := tx.Bucket([]byte(bucketAnalyticsState))
		c := b.Cursor()
		for k, _ := c.First(); k != nil && binary.BigEndian.Uint64(k) <= last; k, _ = c.Next() {
			if err := c.Delete(); err != nil {
				return err
			}
		}
		var v [8]byte
		binary.BigEndian.PutUint64(v[:], last)
		return state.Put([]byte(analyticsAckKey), v[:])
	})
	if err != nil {
		a.setFault(err)
		return err
	}
	a.fault.Store("")
	return nil
}

func (a *DuckAnalytics) setFault(err error) {
	if err != nil {
		a.fault.Store(err.Error())
		log.Printf("analytics duckdb: %v", err)
	}
}

type analyticsTotals struct {
	Events        int64 `json:"events"`
	Input         int64 `json:"input_tokens"`
	CacheRead     int64 `json:"cache_read_tokens"`
	CacheCreation int64 `json:"cache_creation_tokens"`
	Output        int64 `json:"output_tokens"`
	Reasoning     int64 `json:"reasoning_tokens"`
	Billable      int64 `json:"billable_tokens"`
}

type AnalyticsReconciliation struct {
	StartedAt time.Time       `json:"started_at"`
	EndedAt   time.Time       `json:"ended_at"`
	CheckedAt time.Time       `json:"checked_at"`
	Bolt      analyticsTotals `json:"bolt"`
	Ledger    analyticsTotals `json:"ledger_and_outbox"`
	Clean     bool            `json:"clean"`
	Detail    string          `json:"detail,omitempty"`
}

type AnalyticsHealth struct {
	State              string                   `json:"state"`
	OutboxDepth        int                      `json:"outbox_depth"`
	OldestOutboxAt     *time.Time               `json:"oldest_outbox_at,omitempty"`
	Fault              string                   `json:"fault,omitempty"`
	LastReconciliation *AnalyticsReconciliation `json:"last_reconciliation,omitempty"`
}

func addFactTotals(total *analyticsTotals, fact AnalyticsFact) {
	total.Events++
	total.Input += fact.InputTokens
	total.CacheRead += fact.CacheReadTokens
	total.CacheCreation += fact.CacheCreationTokens
	total.Output += fact.OutputTokens
	total.Reasoning += fact.ReasoningTokens
	total.Billable += fact.BillableTokens
}

func totalsEqual(a, b analyticsTotals) bool {
	return a == b
}

func (a *DuckAnalytics) Reconcile(start, end time.Time) (*AnalyticsReconciliation, error) {
	result := &AnalyticsReconciliation{StartedAt: start.UTC(), EndedAt: end.UTC(), CheckedAt: time.Now().UTC()}
	duckEvents := map[string]struct{}{}
	rows, err := a.db.Query(`SELECT event_id,input_tokens,cache_read_tokens,cache_creation_tokens,output_tokens,reasoning_tokens,billable_tokens
 FROM usage_events WHERE observed_at>=? AND observed_at<?`, start.UTC(), end.UTC())
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		var fact AnalyticsFact
		if err := rows.Scan(&id, &fact.InputTokens, &fact.CacheReadTokens, &fact.CacheCreationTokens, &fact.OutputTokens, &fact.ReasoningTokens, &fact.BillableTokens); err != nil {
			rows.Close()
			return nil, err
		}
		fact.EventID = id
		duckEvents[id] = struct{}{}
		addFactTotals(&result.Ledger, fact)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	err = a.bolt.View(func(tx *bbolt.Tx) error {
		if bucket := tx.Bucket([]byte(bucketUsageRequests)); bucket != nil {
			if err := bucket.ForEach(func(_, value []byte) error {
				var usage RequestUsage
				if json.Unmarshal(value, &usage) != nil || usage.UserID == "" || usage.Timestamp.Before(start) || !usage.Timestamp.Before(end) {
					return nil
				}
				result.Bolt.Events++
				result.Bolt.Input += usage.InputTokens
				result.Bolt.CacheRead += usage.CachedInputTokens
				result.Bolt.CacheCreation += usage.CacheCreationTokens
				result.Bolt.Output += usage.OutputTokens
				result.Bolt.Reasoning += usage.ReasoningTokens
				result.Bolt.Billable += usage.BillableTokens
				return nil
			}); err != nil {
				return err
			}
		}
		if bucket := tx.Bucket([]byte(bucketAnalyticsOutbox)); bucket != nil {
			return bucket.ForEach(func(_, value []byte) error {
				var fact AnalyticsFact
				if json.Unmarshal(value, &fact) != nil || fact.ObservedAt.Before(start) || !fact.ObservedAt.Before(end) {
					return nil
				}
				if _, alreadyCommitted := duckEvents[fact.EventID]; !alreadyCommitted {
					addFactTotals(&result.Ledger, fact)
				}
				return nil
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	result.Clean = totalsEqual(result.Bolt, result.Ledger)
	if !result.Clean {
		result.Detail = "closed-hour Bolt totals do not match DuckDB plus the durable outbox"
	}
	encoded, _ := json.Marshal(result)
	_ = a.bolt.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketAnalyticsState)).Put([]byte("last_reconciliation"), encoded)
	})
	a.reconciliation.Store(*result)
	return result, nil
}

func (a *DuckAnalytics) Health() AnalyticsHealth {
	health := AnalyticsHealth{State: "CURRENT"}
	_ = a.bolt.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketAnalyticsOutbox))
		if bucket == nil {
			return nil
		}
		health.OutboxDepth = bucket.Stats().KeyN
		_, value := bucket.Cursor().First()
		if value != nil {
			var fact AnalyticsFact
			if json.Unmarshal(value, &fact) == nil {
				observed := fact.ObservedAt.UTC()
				health.OldestOutboxAt = &observed
			}
		}
		return nil
	})
	if value := a.fault.Load(); value != nil {
		health.Fault, _ = value.(string)
	}
	if value := a.reconciliation.Load(); value != nil {
		if reconciliation, ok := value.(AnalyticsReconciliation); ok {
			health.LastReconciliation = &reconciliation
		}
	} else {
		_ = a.bolt.View(func(tx *bbolt.Tx) error {
			if raw := tx.Bucket([]byte(bucketAnalyticsState)).Get([]byte("last_reconciliation")); raw != nil {
				var reconciliation AnalyticsReconciliation
				if json.Unmarshal(raw, &reconciliation) == nil {
					health.LastReconciliation = &reconciliation
				}
			}
			return nil
		})
	}
	switch {
	case health.Fault != "" || (health.LastReconciliation != nil && !health.LastReconciliation.Clean):
		health.State = "FAULTED"
	case health.OutboxDepth > 0 && health.OldestOutboxAt != nil && time.Since(*health.OldestOutboxAt) > 30*time.Second:
		health.State = "LAGGING"
	}
	return health
}

type AnalyticsPoint struct {
	Hour                 string  `json:"hour"`
	AccountType          string  `json:"account_type"`
	ClientCredentialID   string  `json:"client_credential_id"`
	InputTokens          int64   `json:"input_tokens"`
	CachedTokens         int64   `json:"cached_tokens"`
	OutputTokens         int64   `json:"output_tokens"`
	ReasoningTokens      int64   `json:"reasoning_tokens"`
	BillableTokens       int64   `json:"billable_tokens"`
	RequestCount         int64   `json:"request_count"`
	APIEquivalentCostUSD float64 `json:"api_equivalent_cost_usd"`
}

type PrincipalUsageSummary struct {
	PrincipalID          string    `json:"principal_id"`
	BillableTokens       int64     `json:"billable_tokens"`
	RequestCount         int64     `json:"request_count"`
	APIEquivalentCostUSD float64   `json:"api_equivalent_cost_usd"`
	LastUsedAt           time.Time `json:"last_used_at,omitempty"`
}

func (a *DuckAnalytics) PrincipalRanking(ctx context.Context, since time.Time) ([]PrincipalUsageSummary, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT principal_id, SUM(billable_tokens), COUNT(DISTINCT proxy_request_id),
 CAST(SUM(api_equivalent_cost_usd) AS DOUBLE), MAX(observed_at)
 FROM usage_events WHERE observed_at>=? GROUP BY principal_id ORDER BY SUM(billable_tokens) DESC`, since.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PrincipalUsageSummary
	for rows.Next() {
		var item PrincipalUsageSummary
		if err := rows.Scan(&item.PrincipalID, &item.BillableTokens, &item.RequestCount, &item.APIEquivalentCostUSD, &item.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (a *DuckAnalytics) UserHourly(ctx context.Context, principalID string, since time.Time) ([]AnalyticsPoint, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT strftime(observed_at, '%Y-%m-%dT%H'), account_type, client_credential_id,
 SUM(input_tokens),SUM(cache_read_tokens),SUM(output_tokens),SUM(reasoning_tokens),SUM(billable_tokens),
 COUNT(DISTINCT proxy_request_id),CAST(SUM(api_equivalent_cost_usd) AS DOUBLE)
 FROM usage_events WHERE principal_id=? AND observed_at>=? GROUP BY 1,2,3 ORDER BY 1,2,3`, principalID, since.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AnalyticsPoint, 0)
	for rows.Next() {
		var p AnalyticsPoint
		if err := rows.Scan(&p.Hour, &p.AccountType, &p.ClientCredentialID, &p.InputTokens, &p.CachedTokens, &p.OutputTokens, &p.ReasoningTokens, &p.BillableTokens, &p.RequestCount, &p.APIEquivalentCostUSD); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
