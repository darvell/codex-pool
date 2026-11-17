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
	ID              string             `json:"id"`
	DisplayName     string             `json:"display_name,omitempty"`
	Description     string             `json:"description,omitempty"`
	ContextWindow   int                `json:"context_window,omitempty"`
	MaxOutputTokens int                `json:"max_output_tokens,omitempty"`
	Reasoning       bool               `json:"reasoning,omitempty"`
	Tools           bool               `json:"tools,omitempty"`
	CompletionChat  bool               `json:"completion_chat,omitempty"`
	WebSearch       bool               `json:"web_search,omitempty"`
	Modalities      []string           `json:"modalities,omitempty"`
	ServiceTiers    []modelServiceTier `json:"service_tiers,omitempty"`
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
		decodeFirstInt(row, &model.ContextWindow, "context_window", "context_length", "max_context_length", "inputTokenLimit", "max_input_tokens")
		decodeFirstInt(row, &model.MaxOutputTokens, "max_output_tokens", "outputTokenLimit", "max_tokens")
		decodeFirstBool(row, &model.Reasoning, "supports_reasoning", "supports_thinking", "supports_reasoning_effort", "reasoning")
		if !model.Reasoning {
			model.Reasoning = hasNonEmptyArray(row, "supported_reasoning_levels", "reasoning_efforts")
		}
		decodeFirstBool(row, &model.WebSearch, "supports_backend_search", "supports_search_tool", "web_search")
		if raw, ok := row["service_tiers"]; ok {
			if err := json.Unmarshal(raw, &model.ServiceTiers); err != nil {
				return nil, fmt.Errorf("invalid service tiers for model %q: %w", model.ID, err)
			}
		}

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

func parseMistralModels(body []byte) (map[string]DiscoveredModel, error) {
	var response struct {
		Data []struct {
			ID               string `json:"id"`
			Name             string `json:"name"`
			Description      string `json:"description"`
			MaxContextLength int    `json:"max_context_length"`
			Capabilities     struct {
				CompletionChat  bool `json:"completion_chat"`
				FunctionCalling bool `json:"function_calling"`
				Reasoning       bool `json:"reasoning"`
				Vision          bool `json:"vision"`
			} `json:"capabilities"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	models := make(map[string]DiscoveredModel)
	for _, row := range response.Data {
		id := strings.TrimSpace(row.ID)
		if id == "" || !row.Capabilities.CompletionChat {
			continue
		}
		modalities := []string{"text"}
		if row.Capabilities.Vision {
			modalities = append(modalities, "image")
		}
		name := strings.TrimSpace(row.Name)
		if name == "" {
			name = id
		}
		models[id] = DiscoveredModel{
			ID: id, DisplayName: name, Description: row.Description,
			ContextWindow: row.MaxContextLength, Reasoning: row.Capabilities.Reasoning,
			Tools: row.Capabilities.FunctionCalling, CompletionChat: true, Modalities: modalities,
		}
	}
	if len(models) == 0 {
		return nil, errors.New("Mistral model endpoint returned no chat-completion models")
	}
	return models, nil
}

func providerModelsURL(provider Provider) (*url.URL, bool) {
	catalog, err := catalogFor(provider)
	if err != nil {
		return nil, false
	}
	return catalog.endpoint()
}

func fetchProviderModels(ctx context.Context, transport http.RoundTripper, provider Provider, account *Account) (providerModelSnapshot, error) {
	catalog, err := catalogFor(provider)
	if err != nil {
		return providerModelSnapshot{}, err
	}
	req, err := catalog.request(ctx, provider, account)
	if err != nil {
		return providerModelSnapshot{}, err
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
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return providerModelSnapshot{}, fmt.Errorf("model discovery failed: %s: %s", resp.Status, safeText(body))
	}
	models, err := catalog.parse(body)
	if err != nil {
		return providerModelSnapshot{}, err
	}
	return providerModelSnapshot{FetchedAt: time.Now().UTC(), Models: models}, nil
}

func fetchOpencodeGoFreeModels(ctx context.Context, transport http.RoundTripper, provider *OpencodeGoProvider) (map[string]DiscoveredModel, error) {
	if provider == nil || provider.opencodeZenBase == nil {
		return nil, errors.New("OpenCode Zen catalog is not configured")
	}
	target := *provider.opencodeZenBase
	target.Path = singleJoin(target.Path, "/models")
	target.RawQuery = ""
	target.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("OpenCode Zen model discovery failed: %s: %s", resp.Status, safeText(body))
	}
	models, err := parseProviderModels(body)
	if err != nil {
		return nil, err
	}
	free := make(map[string]DiscoveredModel)
	for id, model := range models {
		if strings.HasSuffix(strings.ToLower(id), "-free") {
			free[id] = model
		}
	}
	return free, nil
}

func syncProviderModels(ctx context.Context, transport http.RoundTripper, registry *ProviderRegistry, account *Account) error {
	if registry == nil || account == nil {
		return errors.New("missing provider model discovery dependency")
	}
	account.mu.Lock()
	unavailable := account.Dead || account.Disabled
	account.mu.Unlock()
	if unavailable {
		return nil
	}
	provider := registry.ForType(account.Type)
	if provider == nil {
		return errors.New("provider not registered")
	}
	snapshot, err := fetchProviderModels(ctx, transport, provider, account)
	if err != nil {
		return err
	}
	if goProvider, ok := provider.(*OpencodeGoProvider); ok {
		if freeModels, freeErr := fetchOpencodeGoFreeModels(ctx, transport, goProvider); freeErr == nil {
			for id, model := range freeModels {
				if _, exists := snapshot.Models[id]; exists {
					continue
				}
				snapshot.Models["opencode/"+id] = model
			}
		}
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
			account.mu.Lock()
			unavailable := account.Dead || account.Disabled
			account.mu.Unlock()
			if unavailable {
				continue
			}
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
		sourceID   string
		provider   AccountType
		supporting int
		available  int
	}
	aggregates := make(map[string]*aggregate)
	now := time.Now()
	for _, account := range pool.allAccounts() {
		account.mu.Lock()
		for id, model := range account.Models {
			publicID := id
			if isMistralType(account.Type) {
				publicID = mistralPublicID(account.Type, id)
			}
			if poolModelIDExists(publicID) {
				continue
			}
			key := string(account.Type) + "\x00" + strings.ToLower(id)
			entry := aggregates[key]
			if entry == nil {
				entry = &aggregate{model: model, sourceID: id, provider: account.Type}
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
		publicID := entry.model.ID
		if entry.provider == AccountTypeOpencodeGo && strings.HasPrefix(strings.ToLower(entry.sourceID), "opencode/") {
			publicID = entry.sourceID
		}
		metadata := entry.model
		if isMistralType(entry.provider) {
			publicID = mistralPublicID(entry.provider, entry.model.ID)
		} else {
			metadata.Tools = true
		}
		descriptor := projectModel(entry.provider, publicID, entry.model.ID, metadata)
		descriptor.SupportingAccounts = entry.supporting
		descriptor.AvailableAccounts = entry.available
		descriptor.AvailableNow = entry.available > 0
		descriptors = append(descriptors, descriptor)
	}
	return descriptors
}
