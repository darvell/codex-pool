package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type AntigravityQuotaInfo struct {
	RemainingFraction *float64  `json:"remaining_fraction,omitempty"`
	ResetTime         time.Time `json:"reset_time,omitempty"`
}

type AntigravityModelInfo struct {
	ID                 string                     `json:"id"`
	DisplayName        string                     `json:"display_name,omitempty"`
	MaxTokens          int                        `json:"max_tokens,omitempty"`
	MaxOutputTokens    int                        `json:"max_output_tokens,omitempty"`
	SupportsImages     bool                       `json:"supports_images,omitempty"`
	SupportsThinking   bool                       `json:"supports_thinking,omitempty"`
	ThinkingBudget     int                        `json:"thinking_budget,omitempty"`
	Recommended        bool                       `json:"recommended,omitempty"`
	SupportedMimeTypes []string                   `json:"supported_mime_types,omitempty"`
	WebSearch          bool                       `json:"web_search,omitempty"`
	Quota              AntigravityQuotaInfo       `json:"quota,omitempty"`
	Raw                map[string]json.RawMessage `json:"raw,omitempty"`
}

type AntigravityAccountSnapshot struct {
	FetchedAt  time.Time                       `json:"fetched_at"`
	Models     map[string]AntigravityModelInfo `json:"models"`
	Deprecated map[string]string               `json:"deprecated_model_ids,omitempty"`
	Raw        map[string]json.RawMessage      `json:"raw,omitempty"`
}

type AntigravityCatalogModel struct {
	AntigravityModelInfo
	Aliases            []string  `json:"aliases,omitempty"`
	Replacement        string    `json:"replacement,omitempty"`
	SupportingAccounts int       `json:"supporting_accounts"`
	AvailableAccounts  int       `json:"available_accounts"`
	AvailableNow       bool      `json:"available_now"`
	Stale              bool      `json:"stale"`
	NextResetAt        time.Time `json:"next_reset_at,omitempty"`
}

type antigravityModelRegistry struct {
	mu       sync.RWMutex
	accounts map[string]AntigravityAccountSnapshot
	known    map[string]bool
}

var antigravityModels = &antigravityModelRegistry{accounts: make(map[string]AntigravityAccountSnapshot), known: make(map[string]bool)}

func (r *antigravityModelRegistry) Reset() {
	r.mu.Lock()
	r.accounts = make(map[string]AntigravityAccountSnapshot)
	r.known = make(map[string]bool)
	r.mu.Unlock()
}

func (r *antigravityModelRegistry) MarkAccount(accountID string) {
	if strings.TrimSpace(accountID) == "" {
		return
	}
	r.mu.Lock()
	if r.known == nil {
		r.known = make(map[string]bool)
	}
	r.known[accountID] = true
	r.mu.Unlock()
}

func (r *antigravityModelRegistry) ReplaceAccount(accountID string, snapshot AntigravityAccountSnapshot) {
	if strings.TrimSpace(accountID) == "" || len(snapshot.Models) == 0 {
		return
	}
	if snapshot.FetchedAt.IsZero() {
		snapshot.FetchedAt = time.Now().UTC()
	}
	r.mu.Lock()
	if r.known == nil {
		r.known = make(map[string]bool)
	}
	r.known[accountID] = true
	r.accounts[accountID] = snapshot
	r.mu.Unlock()
}

func (r *antigravityModelRegistry) AccountSnapshot(accountID string) (AntigravityAccountSnapshot, bool) {
	r.mu.RLock()
	snapshot, ok := r.accounts[accountID]
	r.mu.RUnlock()
	return snapshot, ok
}

func (r *antigravityModelRegistry) Supports(accountID, model string) bool {
	model, _ = r.Canonical(model)
	r.mu.RLock()
	snapshot, ok := r.accounts[accountID]
	r.mu.RUnlock()
	if !ok {
		return true // allow cold-start discovery/fallback accounts to be tried
	}
	_, ok = snapshot.Models[model]
	return ok
}

func (r *antigravityModelRegistry) DiscoveryAvailability(accountID, model string, now time.Time) (bool, time.Time) {
	model, _ = r.Canonical(model)
	r.mu.RLock()
	snapshot, ok := r.accounts[accountID]
	r.mu.RUnlock()
	if !ok {
		return true, time.Time{}
	}
	info, ok := snapshot.Models[model]
	if !ok {
		return false, time.Time{}
	}
	if info.Quota.RemainingFraction != nil && *info.Quota.RemainingFraction <= 0 && info.Quota.ResetTime.After(now) {
		return false, info.Quota.ResetTime
	}
	return true, time.Time{}
}

func (r *antigravityModelRegistry) Canonical(model string) (string, bool) {
	model = strings.TrimSpace(strings.TrimPrefix(model, "antigravity/"))
	if model == "" {
		return "", false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	found := false
	for _, snapshot := range r.accounts {
		if replacement, ok := snapshot.Deprecated[model]; ok {
			return replacement, true
		}
		if _, ok := snapshot.Models[model]; ok {
			found = true
		}
	}
	if found {
		return model, true
	}
	for _, fallback := range antigravityFallbackModels {
		if fallback.ID == model {
			return model, true
		}
	}
	return model, false
}

func (r *antigravityModelRegistry) Models(pool *poolState) []AntigravityCatalogModel {
	r.mu.RLock()
	snapshots := make(map[string]AntigravityAccountSnapshot, len(r.accounts))
	for id, snapshot := range r.accounts {
		snapshots[id] = snapshot
	}
	knownAccounts := len(r.known)
	r.mu.RUnlock()

	merged := make(map[string]*AntigravityCatalogModel)
	aliases := make(map[string]map[string]bool)
	deprecatedIDs := make(map[string]bool)
	fresh := make(map[string]bool)
	metadataTime := make(map[string]time.Time)
	accountIDs := make([]string, 0, len(snapshots))
	for accountID := range snapshots {
		accountIDs = append(accountIDs, accountID)
		for oldID := range snapshots[accountID].Deprecated {
			deprecatedIDs[oldID] = true
		}
	}
	sort.Strings(accountIDs)
	for _, accountID := range accountIDs {
		snapshot := snapshots[accountID]
		for oldID, replacement := range snapshot.Deprecated {
			if aliases[replacement] == nil {
				aliases[replacement] = make(map[string]bool)
			}
			aliases[replacement][oldID] = true
		}
		for id, model := range snapshot.Models {
			if deprecatedIDs[id] {
				continue
			}
			entry := merged[id]
			if entry == nil {
				copy := AntigravityCatalogModel{AntigravityModelInfo: model}
				entry = &copy
				merged[id] = entry
				metadataTime[id] = snapshot.FetchedAt
			} else if snapshot.FetchedAt.After(metadataTime[id]) {
				entry.AntigravityModelInfo = model
				metadataTime[id] = snapshot.FetchedAt
			}
			entry.SupportingAccounts++
			available, reset := antigravityAccountModelAvailable(pool, accountID, id)
			if available {
				entry.AvailableAccounts++
				entry.AvailableNow = true
			} else if !reset.IsZero() && (entry.NextResetAt.IsZero() || reset.Before(entry.NextResetAt)) {
				entry.NextResetAt = reset
			}
			if time.Since(snapshot.FetchedAt) <= 24*time.Hour {
				fresh[id] = true
			}
		}
	}
	if len(merged) == 0 && knownAccounts > 0 {
		for _, fallback := range antigravityFallbackModels {
			copy := fallback
			copy.Stale = true
			merged[copy.ID] = &copy
		}
	}
	result := make([]AntigravityCatalogModel, 0, len(merged))
	for id, entry := range merged {
		entry.Stale = !fresh[id]
		entry.Aliases = []string{"antigravity/" + id}
		for alias := range aliases[id] {
			entry.Aliases = append(entry.Aliases, alias)
		}
		sort.Strings(entry.Aliases)
		result = append(result, *entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func antigravityAccountModelAvailable(pool *poolState, accountID, model string) (bool, time.Time) {
	if pool == nil {
		return false, time.Time{}
	}
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	for _, account := range pool.accounts {
		if account.Type != AccountTypeAntigravity || account.ID != accountID {
			continue
		}
		account.mu.Lock()
		defer account.mu.Unlock()
		if account.Dead || account.Disabled || account.NeedsVerification {
			return false, time.Time{}
		}
		now := time.Now()
		until := account.ModelRateLimits[model]
		discoveryAvailable, discoveryReset := antigravityModels.DiscoveryAvailability(accountID, model, now)
		if discoveryReset.After(until) {
			until = discoveryReset
		}
		return !until.After(now) && discoveryAvailable, until
	}
	return false, time.Time{}
}

var antigravityFallbackModels = []AntigravityCatalogModel{
	{AntigravityModelInfo: AntigravityModelInfo{ID: "claude-opus-4-6-thinking", DisplayName: "Claude Opus 4.6 Thinking", SupportsThinking: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "claude-sonnet-4-6", DisplayName: "Claude Sonnet 4.6"}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3-flash", DisplayName: "Gemini 3 Flash"}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3-flash-agent", DisplayName: "Gemini 3 Flash Agent"}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.1-flash-image", DisplayName: "Gemini 3.1 Flash Image", SupportsImages: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-pro-agent", DisplayName: "Gemini Pro Agent"}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.1-pro-low", DisplayName: "Gemini 3.1 Pro Low", SupportsThinking: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gpt-oss-120b-medium", DisplayName: "GPT OSS 120B Medium"}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.1-flash-lite", DisplayName: "Gemini 3.1 Flash Lite"}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.5-flash-low", DisplayName: "Gemini 3.5 Flash Low"}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.5-flash-extra-low", DisplayName: "Gemini 3.5 Flash Extra Low"}},
}

func parseAntigravityModelSnapshot(body []byte, fetchedAt time.Time) (AntigravityAccountSnapshot, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return AntigravityAccountSnapshot{}, err
	}
	var models map[string]map[string]json.RawMessage
	if err := json.Unmarshal(root["models"], &models); err != nil || len(models) == 0 {
		return AntigravityAccountSnapshot{}, fmt.Errorf("fetchAvailableModels returned no models")
	}
	webSearch := make(map[string]bool)
	var webSearchIDs []string
	_ = json.Unmarshal(root["webSearchModelIds"], &webSearchIDs)
	for _, id := range webSearchIDs {
		webSearch[id] = true
	}
	var webSearchMap map[string]bool
	if json.Unmarshal(root["webSearchModelIds"], &webSearchMap) == nil {
		for id, enabled := range webSearchMap {
			if enabled {
				webSearch[id] = true
			}
		}
	}
	snapshot := AntigravityAccountSnapshot{
		FetchedAt:  fetchedAt.UTC(),
		Models:     make(map[string]AntigravityModelInfo, len(models)),
		Deprecated: make(map[string]string),
		Raw:        root,
	}
	for id, raw := range models {
		id = strings.TrimSpace(id)
		if id == "" || strings.ContainsAny(id, " \t\r\n") {
			continue
		}
		if antigravityHiddenModelIDs[id] {
			continue
		}
		model := AntigravityModelInfo{ID: id, Raw: raw, WebSearch: webSearch[id]}
		decodeRaw(raw, "displayName", &model.DisplayName)
		if displayName := antigravityCorrectedDisplayNames[id]; displayName != "" {
			model.DisplayName = displayName
		}
		decodeRaw(raw, "maxTokens", &model.MaxTokens)
		decodeRaw(raw, "maxOutputTokens", &model.MaxOutputTokens)
		decodeRaw(raw, "supportsImages", &model.SupportsImages)
		decodeRaw(raw, "supportsThinking", &model.SupportsThinking)
		decodeRaw(raw, "thinkingBudget", &model.ThinkingBudget)
		decodeRaw(raw, "recommended", &model.Recommended)
		var mimeMap map[string]bool
		if json.Unmarshal(raw["supportedMimeTypes"], &mimeMap) == nil {
			for mime, enabled := range mimeMap {
				if enabled {
					model.SupportedMimeTypes = append(model.SupportedMimeTypes, mime)
				}
			}
			sort.Strings(model.SupportedMimeTypes)
		}
		if len(model.SupportedMimeTypes) == 0 {
			_ = json.Unmarshal(raw["supportedMimeTypes"], &model.SupportedMimeTypes)
			sort.Strings(model.SupportedMimeTypes)
		}
		var quota struct {
			RemainingFraction *float64 `json:"remainingFraction"`
			ResetTime         string   `json:"resetTime"`
		}
		if json.Unmarshal(raw["quotaInfo"], &quota) == nil {
			model.Quota.RemainingFraction = quota.RemainingFraction
			model.Quota.ResetTime, _ = time.Parse(time.RFC3339Nano, quota.ResetTime)
		}
		snapshot.Models[id] = model
	}
	var deprecated map[string]struct {
		NewModelID string `json:"newModelId"`
	}
	_ = json.Unmarshal(root["deprecatedModelIds"], &deprecated)
	for oldID, replacement := range deprecated {
		if replacement.NewModelID != "" {
			snapshot.Deprecated[oldID] = replacement.NewModelID
		}
	}
	var deprecatedStrings map[string]string
	if json.Unmarshal(root["deprecatedModelIds"], &deprecatedStrings) == nil {
		for oldID, replacement := range deprecatedStrings {
			if replacement != "" {
				snapshot.Deprecated[oldID] = replacement
			}
		}
	}
	return snapshot, nil
}

var antigravityHiddenModelIDs = map[string]bool{
	"chat_20706":                  true,
	"chat_23310":                  true,
	"tab_flash_lite_preview":      true,
	"tab_jump_flash_lite_preview": true,
	"gemini-2.5-flash-thinking":   true,
	"gemini-2.5-pro":              true,
}

var antigravityCorrectedDisplayNames = map[string]string{
	"gemini-2.5-flash":      "Gemini 2.5 Flash",
	"gemini-2.5-flash-lite": "Gemini 2.5 Flash Lite",
}

func decodeRaw(raw map[string]json.RawMessage, key string, target any) {
	if value, ok := raw[key]; ok {
		_ = json.Unmarshal(value, target)
	}
}

func fetchAntigravityModels(ctx context.Context, transport http.RoundTripper, account *Account, bases ...*url.URL) (AntigravityAccountSnapshot, error) {
	body := []byte(`{}`)
	var lastErr error
	for _, base := range bases {
		if base == nil {
			continue
		}
		u := *base
		u.Path = singleJoin(u.Path, "/v1internal:fetchAvailableModels")
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
		if err != nil {
			return AntigravityAccountSnapshot{}, err
		}
		req.Header.Set("Authorization", "Bearer "+account.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", antigravityUserAgent())
		resp, err := transport.RoundTrip(req)
		if err != nil {
			lastErr = err
			continue
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("fetchAvailableModels failed: %s: %s", resp.Status, safeText(responseBody))
			continue
		}
		return parseAntigravityModelSnapshot(responseBody, time.Now())
	}
	if lastErr == nil {
		lastErr = errors.New("fetchAvailableModels has no configured upstream")
	}
	return AntigravityAccountSnapshot{}, lastErr
}

func syncAntigravityModels(ctx context.Context, transport http.RoundTripper, account *Account, bases ...*url.URL) error {
	snapshot, err := fetchAntigravityModels(ctx, transport, account, bases...)
	if err != nil {
		return err
	}
	previous, hadPrevious := antigravityModels.AccountSnapshot(account.ID)
	antigravityModels.ReplaceAccount(account.ID, snapshot)
	if hadPrevious && antigravitySnapshotsEquivalent(previous, snapshot) {
		return nil
	}
	return saveAccount(account)
}

func antigravitySnapshotsEquivalent(left, right AntigravityAccountSnapshot) bool {
	left.FetchedAt, right.FetchedAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(left, right)
}

func isAntigravityModel(model string) bool {
	_, ok := antigravityModels.Canonical(model)
	return ok
}

func antigravityCanonicalModel(model string) string {
	canonical, _ := antigravityModels.Canonical(model)
	return canonical
}

func (p *poolState) candidateForAntigravityModel(conversationID string, exclude map[string]bool, model, clientIP string) *Account {
	p.mu.Lock()
	defer p.mu.Unlock()
	model = antigravityCanonicalModel(model)
	now := time.Now()
	pinKey := "antigravity:" + model + ":" + conversationID
	if conversationID != "" {
		if pinnedID := p.convPin[pinKey]; pinnedID != "" && (exclude == nil || !exclude[pinnedID]) {
			for _, account := range p.accounts {
				if account.ID != pinnedID || account.Type != AccountTypeAntigravity || !antigravityModels.Supports(account.ID, model) {
					continue
				}
				account.mu.Lock()
				until := account.ModelRateLimits[model]
				discoveryAvailable, _ := antigravityModels.DiscoveryAvailability(account.ID, model, now)
				eligible := !account.Dead && !account.Disabled && !account.NeedsVerification && accountAllowsClientIPLocked(account, clientIP) && !until.After(now) && discoveryAvailable
				account.mu.Unlock()
				if eligible {
					return account
				}
			}
			delete(p.convPin, pinKey)
		}
	}
	var best *Account
	bestScore := -1e9
	for _, account := range p.accounts {
		if account.Type != AccountTypeAntigravity || (exclude != nil && exclude[account.ID]) || !antigravityModels.Supports(account.ID, model) {
			continue
		}
		account.mu.Lock()
		until := account.ModelRateLimits[model]
		discoveryAvailable, _ := antigravityModels.DiscoveryAvailability(account.ID, model, now)
		eligible := !account.Dead && !account.Disabled && !account.NeedsVerification && accountAllowsClientIPLocked(account, clientIP) && !until.After(now) && discoveryAvailable
		score := scoreAccountLocked(account, now) - float64(atomic.LoadInt64(&account.Inflight))*0.02
		account.mu.Unlock()
		if eligible && (best == nil || score > bestScore) {
			best, bestScore = account, score
		}
	}
	if best != nil && conversationID != "" {
		p.convPin[pinKey] = best.ID
	}
	return best
}

func setAntigravityModelCooldown(account *Account, model string, until time.Time) {
	if account == nil || until.IsZero() {
		return
	}
	account.mu.Lock()
	if account.ModelRateLimits == nil {
		account.ModelRateLimits = make(map[string]time.Time)
	}
	model = antigravityCanonicalModel(model)
	if until.After(account.ModelRateLimits[model]) {
		account.ModelRateLimits[model] = until
	}
	account.mu.Unlock()
	_ = saveAccount(account)
}

func clearAntigravityModelCooldown(account *Account, model string) {
	if account == nil {
		return
	}
	account.mu.Lock()
	canonical := antigravityCanonicalModel(model)
	_, existed := account.ModelRateLimits[canonical]
	delete(account.ModelRateLimits, canonical)
	account.mu.Unlock()
	if existed {
		_ = saveAccount(account)
	}
}

func (h *proxyHandler) startAntigravityModelPoller() {
	if h == nil {
		return
	}
	syncAll := func() {
		provider, _ := h.registry.ForType(AccountTypeAntigravity).(*AntigravityProvider)
		if provider == nil {
			return
		}
		for _, account := range h.pool.allAccounts() {
			if account.Type != AccountTypeAntigravity {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if h.needsRefresh(account) {
				_ = h.refreshAccount(ctx, account)
			}
			_ = syncAntigravityModels(ctx, h.transport, account, provider.DailyURL(), provider.ProductionURL())
			cancel()
		}
	}
	go func() {
		syncAll()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			syncAll()
		}
	}()
}
