package main

import (
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
	"time"
)

const (
	providerModelPollInterval = 15 * time.Minute
)

type DiscoveredModel struct {
	ID              string   `json:"id"`
	DisplayName     string   `json:"display_name,omitempty"`
	Description     string   `json:"description,omitempty"`
	ContextWindow   int      `json:"context_window,omitempty"`
	MaxOutputTokens int      `json:"max_output_tokens,omitempty"`
	Reasoning       bool     `json:"reasoning,omitempty"`
	WebSearch       bool     `json:"web_search,omitempty"`
	Modalities      []string `json:"modalities,omitempty"`
}

type providerModelSnapshot struct {
	FetchedAt time.Time                  `json:"fetched_at"`
	Models    map[string]DiscoveredModel `json:"models"`
}

func parseProviderModels(body []byte) (map[string]DiscoveredModel, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, err
	}

	var rows []map[string]json.RawMessage
	for _, key := range []string{"models", "data"} {
		if json.Unmarshal(root[key], &rows) == nil && len(rows) > 0 {
			break
		}
	}
	if len(rows) == 0 {
		return nil, errors.New("model endpoint returned no models")
	}

	models := make(map[string]DiscoveredModel, len(rows))
	for _, row := range rows {
		model := DiscoveredModel{}
		decodeFirstString(row, &model.ID, "id", "slug", "model")
		model.ID = strings.TrimSpace(model.ID)
		if model.ID == "" {
			continue
		}
		decodeFirstString(row, &model.DisplayName, "display_name", "name")
		decodeFirstString(row, &model.Description, "description")
		decodeFirstInt(row, &model.ContextWindow, "context_window", "context_length", "inputTokenLimit", "max_input_tokens")
		decodeFirstInt(row, &model.MaxOutputTokens, "max_output_tokens", "outputTokenLimit", "max_tokens")
		decodeFirstBool(row, &model.Reasoning, "supports_reasoning", "supports_thinking", "supports_reasoning_effort", "reasoning")
		if !model.Reasoning {
			model.Reasoning = hasNonEmptyArray(row, "supported_reasoning_levels", "reasoning_efforts")
		}
		decodeFirstBool(row, &model.WebSearch, "supports_backend_search", "supports_search_tool", "web_search")

		model.Modalities = decodeStringArray(row, "input_modalities", "modalities")
		if len(model.Modalities) == 0 {
			model.Modalities = []string{"text"}
		}
		appendBoolModality(row, &model.Modalities, "supports_image_in", "image")
		appendBoolModality(row, &model.Modalities, "supports_video_in", "video")
		appendBoolModality(row, &model.Modalities, "supports_audio_in", "audio")
		applyDiscoveredModelDefaults(&model)
		if model.DisplayName == "" {
			model.DisplayName = model.ID
		}
		models[model.ID] = model
	}
	if len(models) == 0 {
		return nil, errors.New("model endpoint returned no usable models")
	}
	return models, nil
}

func applyDiscoveredModelDefaults(model *DiscoveredModel) {
	if model == nil {
		return
	}
	switch model.ID {
	case "gpt-daybreak-blue-latest":
		if model.DisplayName == "" {
			model.DisplayName = "GPT Daybreak Blue"
		}
		if model.ContextWindow == 0 {
			model.ContextWindow = 372000
		}
		if model.MaxOutputTokens == 0 {
			model.MaxOutputTokens = 128000
		}
		model.Reasoning = true
		model.WebSearch = true
		if len(model.Modalities) == 1 {
			model.Modalities = []string{"text", "image"}
		}
	case "codex-auto-review":
		if model.MaxOutputTokens == 0 {
			model.MaxOutputTokens = 128000
		}
		model.Reasoning = true
	}
}

func decodeFirstString(row map[string]json.RawMessage, target *string, keys ...string) {
	for _, key := range keys {
		if raw, ok := row[key]; ok && json.Unmarshal(raw, target) == nil && *target != "" {
			return
		}
	}
}

func decodeFirstInt(row map[string]json.RawMessage, target *int, keys ...string) {
	for _, key := range keys {
		if raw, ok := row[key]; ok && json.Unmarshal(raw, target) == nil && *target > 0 {
			return
		}
	}
}

func decodeFirstBool(row map[string]json.RawMessage, target *bool, keys ...string) {
	for _, key := range keys {
		if raw, ok := row[key]; ok && json.Unmarshal(raw, target) == nil {
			return
		}
	}
}

func hasNonEmptyArray(row map[string]json.RawMessage, keys ...string) bool {
	for _, key := range keys {
		var values []json.RawMessage
		if raw, ok := row[key]; ok && json.Unmarshal(raw, &values) == nil && len(values) > 0 {
			return true
		}
	}
	return false
}

func decodeStringArray(row map[string]json.RawMessage, keys ...string) []string {
	for _, key := range keys {
		var values []string
		if raw, ok := row[key]; ok && json.Unmarshal(raw, &values) == nil && len(values) > 0 {
			return values
		}
	}
	return nil
}

func appendBoolModality(row map[string]json.RawMessage, modalities *[]string, key, modality string) {
	var supported bool
	if raw, ok := row[key]; !ok || json.Unmarshal(raw, &supported) != nil || !supported {
		return
	}
	*modalities = append(*modalities, modality)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func providerModelsURL(provider Provider) (*url.URL, bool) {
	var target url.URL
	switch typed := provider.(type) {
	case *CodexProvider:
		if typed.whamBase == nil {
			return nil, false
		}
		target = *typed.whamBase
		target.Path = singleJoin(target.Path, "/codex/models")
		query := target.Query()
		query.Set("client_version", currentCodexFingerprint().AppVersion)
		target.RawQuery = query.Encode()
	case *ClaudeProvider:
		base := typed.UpstreamURL("/v1/models")
		if base == nil {
			return nil, false
		}
		target = *base
		target.Path = singleJoin(target.Path, "/v1/models")
	case *GrokProvider:
		base := typed.UpstreamURL("/v1/models")
		if base == nil {
			return nil, false
		}
		target = *base
		target.Path = singleJoin(target.Path, "/models")
	case *KimiProvider, *MinimaxProvider, *ZAIProvider:
		base := provider.UpstreamURL("/v1/models")
		if base == nil {
			return nil, false
		}
		target = *base
		target.Path = singleJoin(target.Path, "/v1/models")
	case *OpencodeGoProvider:
		base := provider.UpstreamURL("/models")
		if base == nil {
			return nil, false
		}
		target = *base
		target.Path = singleJoin(target.Path, "/models")
	default:
		return nil, false
	}
	return &target, true
}

func fetchProviderModels(ctx context.Context, transport http.RoundTripper, provider Provider, account *Account) (providerModelSnapshot, error) {
	target, ok := providerModelsURL(provider)
	if !ok {
		return providerModelSnapshot{}, errors.New("provider has no model discovery endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return providerModelSnapshot{}, err
	}
	provider.SetAuthHeaders(req, account)
	req.Header.Set("Accept", "application/json")
	if provider.Type() == AccountTypeClaude {
		req.Header.Set("Anthropic-Version", "2023-06-01")
		req.Header.Set("Anthropic-Beta", "oauth-2025-04-20")
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		return providerModelSnapshot{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return providerModelSnapshot{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return providerModelSnapshot{}, fmt.Errorf("model discovery failed: %s: %s", resp.Status, safeText(body))
	}
	models, err := parseProviderModels(body)
	if err != nil {
		return providerModelSnapshot{}, err
	}
	return providerModelSnapshot{FetchedAt: time.Now().UTC(), Models: models}, nil
}

func syncProviderModels(ctx context.Context, transport http.RoundTripper, registry *ProviderRegistry, account *Account) error {
	if registry == nil || account == nil {
		return errors.New("missing provider model discovery dependency")
	}
	provider := registry.ForType(account.Type)
	if provider == nil {
		return errors.New("provider not registered")
	}
	snapshot, err := fetchProviderModels(ctx, transport, provider, account)
	if err != nil {
		return err
	}
	account.mu.Lock()
	changed := !reflect.DeepEqual(account.Models, snapshot.Models)
	account.Models = snapshot.Models
	account.ModelsFetchedAt = snapshot.FetchedAt
	if account.Type == AccountTypeCodex {
		hasDaybreak := accountHasDaybreak(snapshot.Models)
		if account.CyberAccess != hasDaybreak {
			account.CyberAccess = hasDaybreak
			changed = true
		}
	}
	account.mu.Unlock()
	if !changed {
		return nil
	}
	return saveAccount(account)
}

func accountHasDaybreak(models map[string]DiscoveredModel) bool {
	for id := range models {
		if strings.Contains(strings.ToLower(id), "daybreak") {
			return true
		}
	}
	return false
}

func (h *proxyHandler) startProviderModelPoller() {
	if h == nil {
		return
	}
	syncAll := func() {
		for _, account := range h.pool.allAccounts() {
			if _, ok := providerModelsURL(h.registry.ForType(account.Type)); !ok {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if h.needsRefresh(account) {
				_ = h.refreshAccount(ctx, account)
			}
			_ = syncProviderModels(ctx, h.transport, h.registry, account)
			cancel()
		}
	}
	go func() {
		syncAll()
		ticker := time.NewTicker(providerModelPollInterval)
		defer ticker.Stop()
		for range ticker.C {
			syncAll()
		}
	}()
}

func discoveredModelsForPool(pool *poolState) []poolModelDescriptor {
	if pool == nil {
		return nil
	}
	type aggregate struct {
		model      DiscoveredModel
		provider   AccountType
		supporting int
		available  int
	}
	aggregates := make(map[string]*aggregate)
	now := time.Now()
	for _, account := range pool.allAccounts() {
		account.mu.Lock()
		for id, model := range account.Models {
			if poolModelIDExists(id) {
				continue
			}
			key := string(account.Type) + "\x00" + strings.ToLower(id)
			entry := aggregates[key]
			if entry == nil {
				entry = &aggregate{model: model, provider: account.Type}
				aggregates[key] = entry
			}
			entry.supporting++
			if accountAvailableForRoutingLocked(account, now) && !account.NeedsVerification {
				entry.available++
			}
		}
		account.mu.Unlock()
	}

	keys := make([]string, 0, len(aggregates))
	for key := range aggregates {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	descriptors := make([]poolModelDescriptor, 0, len(keys))
	for _, key := range keys {
		entry := aggregates[key]
		protocol := "anthropic"
		if entry.provider == AccountTypeCodex || entry.provider == AccountTypeGrok {
			protocol = "openai"
		}
		capabilities := map[string]bool{"reasoning": entry.model.Reasoning, "tools": true}
		if entry.model.WebSearch {
			capabilities["web_search"] = true
		}
		descriptors = append(descriptors, poolModelDescriptor{
			ID: entry.model.ID, Name: entry.model.DisplayName, Description: entry.model.Description,
			Protocol: protocol, Protocols: []string{protocol}, Provider: string(entry.provider), UpstreamID: entry.model.ID,
			ContextWindow: entry.model.ContextWindow, MaxOutputTokens: entry.model.MaxOutputTokens,
			Modalities: append([]string(nil), entry.model.Modalities...), Capabilities: capabilities,
			NativeTools:        nativeWebSearchTools(entry.provider, entry.model.WebSearch),
			SupportingAccounts: entry.supporting, AvailableAccounts: entry.available, AvailableNow: entry.available > 0,
		})
	}
	return descriptors
}
