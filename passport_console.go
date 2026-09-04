package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

type ConsolePrincipal struct {
	ID                   string          `json:"id"`
	Kind                 PrincipalKind   `json:"kind"`
	Status               PrincipalStatus `json:"status"`
	Note                 string          `json:"note"`
	DisplayName          string          `json:"display_name,omitempty"`
	Username             string          `json:"username,omitempty"`
	Email                string          `json:"email,omitempty"`
	AvatarURL            string          `json:"avatar_url,omitempty"`
	ExpiresAt            *time.Time      `json:"expires_at,omitempty"`
	CreatedAt            time.Time       `json:"created_at"`
	LastSeenAt           *time.Time      `json:"last_seen_at,omitempty"`
	BillableTokens       int64           `json:"billable_tokens"`
	RequestCount         int64           `json:"request_count"`
	APIEquivalentCostUSD float64         `json:"api_equivalent_cost_usd"`
}

func (p *PassportStore) consolePrincipals(usage []PrincipalUsageSummary) []ConsolePrincipal {
	usageByID := make(map[string]PrincipalUsageSummary, len(usage))
	for _, item := range usage {
		usageByID[item.PrincipalID] = item
	}
	p.mu.RLock()
	out := make([]ConsolePrincipal, 0, len(p.principals))
	for _, principal := range p.principals {
		item := usageByID[principal.ID]
		avatar := ""
		if principal.AvatarUpdatedAt != nil {
			avatar = "/api/avatars/" + principal.ID + "?v=" + principal.AvatarUpdatedAt.UTC().Format("20060102T150405.000000000")
		}
		lastSeen := principal.LastSeenAt
		if item.LastUsedAt.After(lastSeen) {
			lastSeen = item.LastUsedAt
		}
		var lastSeenAt *time.Time
		if !lastSeen.IsZero() {
			lastSeenCopy := lastSeen
			lastSeenAt = &lastSeenCopy
		}
		out = append(out, ConsolePrincipal{ID: principal.ID, Kind: principal.Kind, Status: principal.Status, Note: principal.Note, DisplayName: principal.DisplayName, Username: principal.Username, Email: principal.Email, AvatarURL: avatar, ExpiresAt: principal.ExpiresAt, CreatedAt: principal.CreatedAt, LastSeenAt: lastSeenAt, BillableTokens: item.BillableTokens, RequestCount: item.RequestCount, APIEquivalentCostUSD: item.APIEquivalentCostUSD})
	}
	p.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].BillableTokens == out[j].BillableTokens {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].BillableTokens > out[j].BillableTokens
	})
	return out
}

func (p *PassportStore) recentAudit(limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	out := make([]AuditEntry, 0, limit)
	err := p.db.View(func(tx *bbolt.Tx) error {
		cursor := tx.Bucket([]byte(bucketPassportAudit)).Cursor()
		for key, value := cursor.Last(); key != nil && len(out) < limit; key, value = cursor.Prev() {
			var entry AuditEntry
			if json.Unmarshal(value, &entry) == nil {
				out = append(out, entry)
			}
		}
		return nil
	})
	return out, err
}

func (h *proxyHandler) handleConsolePrincipals(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if _, _, ok := h.requireMember(w, r); !ok {
		return
	}
	if h.duckAnalytics == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "analytics unavailable")
		return
	}
	hours := 168
	if value, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && value > 0 && value <= 24*366 {
		hours = value
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	usage, err := h.duckAnalytics.PrincipalRanking(ctx, time.Now().Add(-time.Duration(hours)*time.Hour))
	if err != nil {
		respondJSONError(w, 500, "analytics query failed")
		return
	}
	respondJSON(w, map[string]any{"principals": h.passport.consolePrincipals(usage), "hours": hours, "excludes_passthrough": true})
}

func consoleUsageHours(r *http.Request) int {
	const defaultHours = 30 * 24
	const maxHours = 24 * 366

	hours, err := strconv.Atoi(r.URL.Query().Get("hours"))
	if err != nil || hours <= 0 || hours > maxHours {
		return defaultHours
	}

	return hours
}

func (h *proxyHandler) handleConsolePrincipalUsage(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if _, _, ok := h.requireMember(w, r); !ok {
		return
	}
	principalID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/console/principals/"), "/")
	principalID = strings.TrimSuffix(principalID, "/usage")
	if principalID == "" || h.passport.principal(principalID) == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	rows, err := h.duckAnalytics.UserHourly(ctx, principalID, time.Now().Add(-time.Duration(consoleUsageHours(r))*time.Hour))
	if err != nil {
		respondJSONError(w, 500, "analytics query failed")
		return
	}
	respondJSON(w, map[string]any{"principal": publicPrincipal(h.passport.principal(principalID)), "hourly": rows, "excludes_passthrough": true})
}

func (h *proxyHandler) handleConsoleAnalyticsHealth(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if _, _, ok := h.requireMember(w, r); !ok {
		return
	}
	if h.duckAnalytics == nil || h.store == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "analytics unavailable")
		return
	}
	health := h.duckAnalytics.Health()
	gaps, active, err := h.store.accountingGaps()
	if err != nil {
		respondJSONError(w, 500, "analytics state unavailable")
		return
	}
	if active != nil {
		health.State = "GAP"
	}
	respondJSON(w, map[string]any{"health": health, "accounting_gaps": gaps, "active_gap": active})
}

func (h *proxyHandler) handleConsoleAudit(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if _, _, ok := h.requireMember(w, r); !ok {
		return
	}
	entries, err := h.passport.recentAudit(200)
	if err != nil {
		respondJSONError(w, 500, "audit unavailable")
		return
	}
	respondJSON(w, entries)
}
