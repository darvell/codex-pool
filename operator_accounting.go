package main

import (
	"context"
	"strings"
	"time"
)

type OperatorAccountingRequest struct {
	EventID              string    `json:"event_id"`
	ProxyRequestID       string    `json:"proxy_request_id"`
	ObservedAt           time.Time `json:"observed_at"`
	PrincipalID          string    `json:"principal_id"`
	ClientCredentialID   string    `json:"client_credential_id"`
	OriginID             string    `json:"origin_id,omitempty"`
	AccountPublicID      string    `json:"account_public_id"`
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
	PricingProvenance    string    `json:"pricing_provenance"`
	UsageCompleteness    string    `json:"usage_completeness"`
	Source               string    `json:"source"`
	SourceGrain          string    `json:"source_grain"`
}

func (a *DuckAnalytics) AccountingRequests(ctx context.Context, from, to time.Time, limit int, cursor *accountingCursor, principal, provider, model string) ([]OperatorAccountingRequest, string, error) {
	where := []string{"observed_at >= ?", "observed_at < ?", "source_grain = 'request'"}
	args := []any{from.UTC(), to.UTC()}
	if cursor != nil {
		where = append(where, "(observed_at < ? OR (observed_at = ? AND event_id < ?))")
		args = append(args, cursor.At.UTC(), cursor.At.UTC(), cursor.ID)
	}
	if principal = strings.TrimSpace(principal); principal != "" {
		where = append(where, "principal_id = ?")
		args = append(args, principal)
	}
	if provider = strings.TrimSpace(provider); provider != "" {
		where = append(where, "account_type = ?")
		args = append(args, provider)
	}
	if model = strings.TrimSpace(model); model != "" {
		where = append(where, "model_normalized = ?")
		args = append(args, model)
	}
	args = append(args, limit+1)
	query := `SELECT event_id, proxy_request_id, observed_at, principal_id, client_credential_id,
 COALESCE(origin_id,''), account_id, account_type, COALESCE(plan_type,''), COALESCE(model_reported,''),
 COALESCE(model_normalized,''), normalization_version, input_tokens, cache_read_tokens,
 cache_creation_tokens, output_tokens, reasoning_tokens, billable_tokens,
 CAST(api_equivalent_cost_usd AS DOUBLE), pricing_version, usage_completeness, source, source_grain
 FROM usage_events WHERE ` + strings.Join(where, " AND ") + ` ORDER BY observed_at DESC, event_id DESC LIMIT ?`
	rows, err := a.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := make([]OperatorAccountingRequest, 0, limit+1)
	for rows.Next() {
		var item OperatorAccountingRequest
		var accountID string
		if err := rows.Scan(&item.EventID, &item.ProxyRequestID, &item.ObservedAt, &item.PrincipalID, &item.ClientCredentialID,
			&item.OriginID, &accountID, &item.AccountType, &item.PlanType, &item.ModelReported, &item.ModelNormalized,
			&item.NormalizationVersion, &item.InputTokens, &item.CacheReadTokens, &item.CacheCreationTokens,
			&item.OutputTokens, &item.ReasoningTokens, &item.BillableTokens, &item.APIEquivalentCostUSD,
			&item.PricingVersion, &item.UsageCompleteness, &item.Source, &item.SourceGrain); err != nil {
			return nil, "", err
		}
		item.AccountPublicID = hashAccountID(accountID)
		item.PricingProvenance = "version_only"
		if item.PricingVersion == "" || item.PricingVersion == "legacy-unavailable" {
			item.PricingProvenance = "unavailable"
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = encodeAccountingCursor(last.ObservedAt, last.EventID)
	}
	return out, next, nil
}
