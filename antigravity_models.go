package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
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
	SupportsTools      bool                       `json:"supports_tools,omitempty"`
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
	Quota      *AntigravityQuotaSummary        `json:"quota_summary,omitempty"`
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

type antigravityRegistryState struct {
	accounts map[string]AntigravityAccountSnapshot
	known    map[string]bool
}

func antigravityRegistryStateFromAccounts(accounts []*Account) antigravityRegistryState {
	state := antigravityRegistryState{accounts: make(map[string]AntigravityAccountSnapshot), known: make(map[string]bool)}
	for _, account := range accounts {
		if account == nil || account.Type != AccountTypeAntigravity {
			continue
		}
		state.known[account.ID] = true
		if account.antigravitySnapshot != nil && len(account.antigravitySnapshot.Models) > 0 {
			state.accounts[account.ID] = *account.antigravitySnapshot
		}
	}
	return state
}

func (r *antigravityModelRegistry) ReplaceAll(state antigravityRegistryState) {
	accounts := make(map[string]AntigravityAccountSnapshot, len(state.accounts))
	known := make(map[string]bool, len(state.known))
	for id, snapshot := range state.accounts {
		accounts[id] = snapshot
	}
	for id, value := range state.known {
		known[id] = value
	}
	r.mu.Lock()
	r.accounts, r.known = accounts, known
	r.mu.Unlock()
}

func (r *antigravityModelRegistry) Snapshots() map[string]AntigravityAccountSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]AntigravityAccountSnapshot, len(r.accounts))
	for id, snapshot := range r.accounts {
		out[id] = snapshot
	}
	return out
}

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
	var reset time.Time
	if info.Quota.RemainingFraction != nil && *info.Quota.RemainingFraction <= 0 {
		reset = info.Quota.ResetTime
	}
	if groupReset := snapshot.Quota.exhaustedUntil(model, now); groupReset.After(reset) {
		reset = groupReset
	}
	if reset.After(now) {
		return false, reset
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
	if pool != nil {
		pool.stateMu.RLock()
		defer pool.stateMu.RUnlock()
	}
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
			available, reset := antigravityAccountModelAvailable(pool, accountID, id, snapshot)
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

func antigravityAccountModelAvailable(pool *poolState, accountID, model string, snapshot AntigravityAccountSnapshot) (bool, time.Time) {
	if pool == nil {
		return false, time.Time{}
	}
	model = antigravityCanonicalModel(model)
	now := time.Now()
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	for _, account := range pool.accounts {
		if account.Type != AccountTypeAntigravity || account.ID != accountID {
			continue
		}
		decision := antigravityEvaluateAccount(account, snapshot, true, model, "", false, now)
		return decision.eligible, decision.retryAt
	}
	return false, time.Time{}
}

var antigravityFallbackModels = []AntigravityCatalogModel{
	{AntigravityModelInfo: AntigravityModelInfo{ID: "claude-opus-4-6-thinking", DisplayName: "Claude Opus 4.6 Thinking", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "claude-sonnet-4-6", DisplayName: "Claude Sonnet 4.6", SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3-flash", DisplayName: "Gemini 3 Flash", SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3-flash-agent", DisplayName: "Gemini 3.5 Flash (High)", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.1-flash-image", DisplayName: "Gemini 3.1 Flash Image", MaxTokens: 131072, MaxOutputTokens: 32768, SupportsImages: true, SupportsThinking: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-pro-agent", DisplayName: "Gemini 3.1 Pro (High)", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.1-pro-low", DisplayName: "Gemini 3.1 Pro (Low)", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gpt-oss-120b-medium", DisplayName: "GPT OSS 120B (Medium)", SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.1-flash-lite", DisplayName: "Gemini 3.1 Flash Lite", SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.5-flash-low", DisplayName: "Gemini 3.5 Flash (Medium)", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.5-flash-extra-low", DisplayName: "Gemini 3.5 Flash (Low)", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.6-flash-high", DisplayName: "Gemini 3.6 Flash (High)", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.6-flash-medium", DisplayName: "Gemini 3.6 Flash (Medium)", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.6-flash-low", DisplayName: "Gemini 3.6 Flash (Low)", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.6-flash-tiered", DisplayName: "Gemini 3.6 Flash (Tiered)", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.7-flash-high", DisplayName: "Gemini 3.7 Flash (High)", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.7-flash-medium", DisplayName: "Gemini 3.7 Flash (Medium)", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.7-flash-low", DisplayName: "Gemini 3.7 Flash (Low)", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.7-flash-tiered", DisplayName: "Gemini 3.7 Flash (Tiered)", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.8-flash-high", DisplayName: "Gemini 3.8 Flash (High)", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.8-flash-medium", DisplayName: "Gemini 3.8 Flash (Medium)", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.8-flash-low", DisplayName: "Gemini 3.8 Flash (Low)", SupportsThinking: true, SupportsTools: true}},
	{AntigravityModelInfo: AntigravityModelInfo{ID: "gemini-3.8-flash-tiered", DisplayName: "Gemini 3.8 Flash (Tiered)", SupportsThinking: true, SupportsTools: true}},
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
		model := AntigravityModelInfo{ID: id, Raw: raw, WebSearch: webSearch[id], SupportsTools: true}
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
		applyAntigravityModelCorrections(&model)
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
			if quota.RemainingFraction == nil && !model.Quota.ResetTime.IsZero() {
				model.Quota.RemainingFraction = new(float64)
			}
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
	"gemini-2.5-flash":        "Gemini 2.5 Flash",
	"gemini-2.5-flash-lite":   "Gemini 2.5 Flash Lite",
	"gemini-3.6-flash-tiered": "Gemini 3.6 Flash (Tiered)",
	"gemini-3.7-flash-tiered": "Gemini 3.7 Flash (Tiered)",
	"gemini-3.8-flash-tiered": "Gemini 3.8 Flash (Tiered)",
}

func applyAntigravityModelCorrections(model *AntigravityModelInfo) {
	if model == nil {
		return
	}
	if displayName := antigravityCorrectedDisplayNames[model.ID]; displayName != "" {
		model.DisplayName = displayName
	}
	if model.ID == "gemini-3.1-flash-image" {
		model.MaxTokens = 131072
		model.MaxOutputTokens = 32768
		model.SupportsImages = true
		model.SupportsThinking = true
		model.SupportsTools = false
	}
}

func decodeRaw(raw map[string]json.RawMessage, key string, target any) {
	if value, ok := raw[key]; ok {
		_ = json.Unmarshal(value, target)
	}
}

func fetchAntigravityModels(ctx context.Context, transport http.RoundTripper, account *Account, bases ...*url.URL) (AntigravityAccountSnapshot, error) {
	var lastErr error
	for _, base := range bases {
		if base == nil {
			continue
		}
		status, responseBody, err := postAntigravityInternal(ctx, transport, account, base, "fetchAvailableModels", []byte(`{}`))
		if err != nil {
			lastErr = err
			continue
		}
		if status < 200 || status >= 300 {
			lastErr = fmt.Errorf("fetchAvailableModels failed: %d: %s", status, safeText(responseBody))
			continue
		}
		return parseAntigravityModelSnapshot(responseBody, time.Now())
	}
	if lastErr == nil {
		lastErr = errors.New("fetchAvailableModels has no configured upstream")
	}
	return AntigravityAccountSnapshot{}, lastErr
}

func postAntigravityInternal(ctx context.Context, transport http.RoundTripper, account *Account, base *url.URL, operation string, body []byte) (int, []byte, error) {
	u := *base
	u.Path = singleJoin(u.Path, "/v1internal:"+operation)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	account.mu.Lock()
	accessToken := account.AccessToken
	account.mu.Unlock()
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", antigravityUserAgent())
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, responseBody, nil
}

type antigravitySyncResult struct {
	snapshot AntigravityAccountSnapshot
	quota    *AntigravityQuotaSummary
	quotaErr error
}

func fetchAntigravitySync(ctx context.Context, transport http.RoundTripper, account *Account, daily, production *url.URL) (antigravitySyncResult, error) {
	snapshot, err := fetchAntigravityModels(ctx, transport, account, daily, production)
	if err != nil {
		return antigravitySyncResult{}, err
	}
	quota, quotaErr := fetchAntigravityQuota(ctx, transport, account, daily, production)
	result := antigravitySyncResult{snapshot: snapshot, quotaErr: quotaErr}
	if quotaErr == nil {
		result.quota = &quota
	}
	return result, nil
}

// commitAntigravitySync contains all mutation after the network-only fetch.
func commitAntigravitySync(account *Account, result antigravitySyncResult) error {
	previous, hadPrevious := antigravityModels.AccountSnapshot(account.ID)
	result.snapshot.Quota = previous.Quota
	var forbidden *antigravityForbiddenError
	switch {
	case result.quotaErr == nil:
		result.snapshot.Quota = result.quota
		clearAntigravityHealth(account)
	case errors.As(result.quotaErr, &forbidden):
		if needsVerification, banned, _ := classifyAntigravityForbidden(forbidden.body); needsVerification || banned {
			recordAntigravityForbidden(account, forbidden.body)
		}
	}
	account.mu.Lock()
	account.antigravitySnapshot = &result.snapshot
	account.mu.Unlock()
	antigravityModels.ReplaceAccount(account.ID, result.snapshot)
	if !hadPrevious || !antigravitySnapshotsEquivalent(previous, result.snapshot) {
		if err := saveAccount(account); err != nil {
			return err
		}
	}
	if result.quotaErr != nil {
		return fmt.Errorf("quota summary: %w", result.quotaErr)
	}
	return nil
}

// syncAntigravityModels is retained for direct/admin tests. Background and
// request-driven syncs use the generation-guarded handler method below.
func syncAntigravityModels(ctx context.Context, transport http.RoundTripper, account *Account, daily, production *url.URL) error {
	result, err := fetchAntigravitySync(ctx, transport, account, daily, production)
	if err != nil {
		return err
	}
	return commitAntigravitySync(account, result)
}

var errStaleAntigravityAccount = errors.New("stale Antigravity account generation")

func (h *proxyHandler) syncAntigravityModelsGuarded(ctx context.Context, generation uint64, account *Account, daily, production *url.URL) error {
	result, err := fetchAntigravitySync(ctx, h.transport, account, daily, production)
	if err != nil {
		return err
	}
	// stateMu prevents a reload between validation and persistence. No account
	// or registry lock is held while saveAccount writes the atomic JSON file.
	h.pool.stateMu.Lock()
	defer h.pool.stateMu.Unlock()
	if !h.pool.currentAccount(generation, account) {
		return errStaleAntigravityAccount
	}
	return commitAntigravitySync(account, result)
}

func antigravitySnapshotsEquivalent(left, right AntigravityAccountSnapshot) bool {
	left.FetchedAt, right.FetchedAt = time.Time{}, time.Time{}
	left.Quota, right.Quota = withoutQuotaFetchTime(left.Quota), withoutQuotaFetchTime(right.Quota)
	return reflect.DeepEqual(left, right)
}

func withoutQuotaFetchTime(summary *AntigravityQuotaSummary) *AntigravityQuotaSummary {
	if summary == nil {
		return nil
	}
	copy := *summary
	copy.FetchedAt = time.Time{}
	return &copy
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
	reservation, _ := p.reserveAntigravityModel(conversationID, exclude, model, clientIP)
	if reservation == nil {
		return nil
	}
	account := reservation.Account
	reservation.Release()
	return account
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
	clearAntigravityRuntimeState(account, model)
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
		generation, accounts := h.pool.generationAndAccounts()
		for _, account := range accounts {
			if account.Type != AccountTypeAntigravity {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			// Proactive refresh is owned by the generic usage poller, which is
			// serialized with reloadAccounts. Keeping it out of this independent
			// poller prevents a stale generation from persisting credentials.
			if err := h.syncAntigravityModelsGuarded(ctx, generation, account, provider.DailyURL(), provider.ProductionURL()); err != nil && !errors.Is(err, errStaleAntigravityAccount) {
				log.Printf("antigravity sync %s failed: %v", account.ID, err)
			}
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
