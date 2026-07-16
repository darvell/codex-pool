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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	grokOAuthClientID    = "b1a00492-073a-47ea-816f-4c329264a828"
	grokDefaultTokenURL  = "https://auth.x.ai/oauth2/token"
	grokClientIdentifier = "grok-cli"
	// Matches current Grok Build CLI (0.2.93 as of 2026-07-09).
	grokDefaultClientVersion = "0.2.93"
)

// GrokProvider handles xAI Grok Code OAuth accounts through Grok's OpenAI-compatible Responses API.
type GrokProvider struct {
	grokBase      *url.URL
	clientVersion string
}

func NewGrokProvider(grokBase *url.URL) *GrokProvider {
	return &GrokProvider{grokBase: grokBase, clientVersion: grokClientVersion()}
}

func (p *GrokProvider) Type() AccountType {
	return AccountTypeGrok
}

type grokCLIAuthEntry struct {
	Key          string `json:"key"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    string `json:"expires_at"`
	OIDCIssuer   string `json:"oidc_issuer"`
	OIDCClientID string `json:"oidc_client_id"`
	TeamID       string `json:"team_id"`
	Disabled     bool   `json:"disabled"`
	Dead         bool   `json:"dead"`
}

type grokSimpleAuthJSON struct {
	AccessToken   string `json:"access_token"`
	RefreshToken  string `json:"refresh_token"`
	ExpiresAt     string `json:"expires_at"`
	TokenEndpoint string `json:"token_endpoint"`
	PlanType      string `json:"plan_type"`
	Disabled      bool   `json:"disabled"`
	Dead          bool   `json:"dead"`

	PiAccess        string        `json:"access"`
	PiRefresh       string        `json:"refresh"`
	PiExpires       json.Number   `json:"expires"`
	PiTokenEndpoint string        `json:"tokenEndpoint"`
	PiBaseURL       string        `json:"baseUrl"`
	PiDiscovery     grokDiscovery `json:"discovery"`
}

type grokDiscovery struct {
	TokenEndpoint string `json:"token_endpoint"`
}

type grokBillingMoney struct {
	Value float64 `json:"val"`
}

type grokBillingPeriod struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type grokBillingConfig struct {
	CurrentPeriod      *grokBillingPeriod `json:"currentPeriod"`
	CreditUsagePercent *float64           `json:"creditUsagePercent"`
	MonthlyLimit       *grokBillingMoney  `json:"monthlyLimit"`
	Used               *grokBillingMoney  `json:"used"`
	BillingPeriodStart string             `json:"billingPeriodStart"`
	BillingPeriodEnd   string             `json:"billingPeriodEnd"`
}

type grokBillingResponse struct {
	Config *grokBillingConfig `json:"config"`
}

func (p *GrokProvider) LoadAccount(name, path string, data []byte) (*Account, error) {
	if acc, err := loadGrokSimpleAccount(name, path, data); err != nil || acc != nil {
		return acc, err
	}
	return loadGrokCLIAccount(name, path, data)
}

func loadGrokSimpleAccount(name, path string, data []byte) (*Account, error) {
	var gj grokSimpleAuthJSON
	if err := json.Unmarshal(data, &gj); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	accessToken := firstNonEmpty(gj.AccessToken, gj.PiAccess)
	refreshToken := firstNonEmpty(gj.RefreshToken, gj.PiRefresh)
	if accessToken == "" && refreshToken == "" {
		return nil, nil
	}
	acc := &Account{
		Type:         AccountTypeGrok,
		ID:           strings.TrimSuffix(name, filepath.Ext(name)),
		File:         path,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		PlanType:     firstNonEmpty(strings.TrimSpace(gj.PlanType), "grok"),
		Disabled:     gj.Disabled,
		Dead:         gj.Dead,
	}
	acc.ExpiresAt = parseGrokTime(gj.ExpiresAt)
	if acc.ExpiresAt.IsZero() {
		acc.ExpiresAt = parseGrokUnixMillis(gj.PiExpires)
	}
	if endpoint := firstNonEmpty(gj.TokenEndpoint, gj.PiTokenEndpoint, gj.PiDiscovery.TokenEndpoint); endpoint != "" {
		acc.AccountID = endpoint
	}
	return acc, nil
}

func loadGrokCLIAccount(name, path string, data []byte) (*Account, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	keys := make([]string, 0, len(root))
	for k := range root {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var entryKey string
	var entry grokCLIAuthEntry
	for _, k := range keys {
		var v grokCLIAuthEntry
		if err := json.Unmarshal(root[k], &v); err != nil {
			// Common account metadata such as added_at is stored beside the
			// keyed CLI credential object. Scalar metadata is not a credential.
			continue
		}
		if strings.TrimSpace(v.Key) != "" || strings.TrimSpace(v.RefreshToken) != "" {
			entryKey = k
			entry = v
			break
		}
	}
	if entryKey == "" {
		return nil, nil
	}
	id := strings.TrimSuffix(name, filepath.Ext(name))
	if id == "auth" && entry.TeamID != "" {
		id = "grok-" + entry.TeamID[:min(len(entry.TeamID), 8)]
	}
	acc := &Account{
		Type:         AccountTypeGrok,
		ID:           id,
		File:         path,
		AccessToken:  strings.TrimSpace(entry.Key),
		RefreshToken: strings.TrimSpace(entry.RefreshToken),
		PlanType:     "grok",
		AccountID:    grokTokenEndpointFromIssuer(entry.OIDCIssuer),
		Disabled:     entry.Disabled,
		Dead:         entry.Dead,
	}
	acc.ExpiresAt = parseGrokTime(entry.ExpiresAt)
	return acc, nil
}

func (p *GrokProvider) SetAuthHeaders(req *http.Request, acc *Account) {
	req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
	req.Header.Set("X-XAI-Token-Auth", "xai-grok-cli")
	req.Header.Set("x-grok-client-identifier", grokClientIdentifier)
	req.Header.Set("x-grok-client-version", p.clientVersion)
	req.Header.Del("X-Api-Key")
}

func (p *GrokProvider) RefreshToken(ctx context.Context, acc *Account, transport http.RoundTripper) error {
	acc.mu.Lock()
	refreshTok := strings.TrimSpace(acc.RefreshToken)
	tokenEndpoint := strings.TrimSpace(acc.AccountID)
	acc.mu.Unlock()

	if refreshTok == "" {
		return errors.New("no refresh token")
	}
	if tokenEndpoint == "" {
		tokenEndpoint = grokDefaultTokenURL
	}
	if err := validateGrokOAuthURL(tokenEndpoint); err != nil {
		return err
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", grokOAuthClientID)
	form.Set("refresh_token", refreshTok)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "codex-pool-proxy")

	resp, err := transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		if len(bytes.TrimSpace(msg)) > 0 {
			return fmt.Errorf("grok refresh failed: %s: %s", resp.Status, safeText(msg))
		}
		return fmt.Errorf("grok refresh failed: %s", resp.Status)
	}

	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if strings.TrimSpace(payload.AccessToken) == "" {
		return errors.New("empty access token after grok refresh")
	}

	now := time.Now().UTC()
	acc.mu.Lock()
	acc.AccessToken = strings.TrimSpace(payload.AccessToken)
	if strings.TrimSpace(payload.RefreshToken) != "" {
		acc.RefreshToken = strings.TrimSpace(payload.RefreshToken)
	}
	if payload.ExpiresIn > 0 {
		acc.ExpiresAt = now.Add(time.Duration(payload.ExpiresIn) * time.Second)
	} else if claims := parseCodexClaims(payload.AccessToken); !claims.ExpiresAt.IsZero() {
		acc.ExpiresAt = claims.ExpiresAt
	}
	acc.LastRefresh = now
	acc.Dead = false
	acc.mu.Unlock()

	return saveAccount(acc)
}

func (p *GrokProvider) ParseUsage(obj map[string]any) *RequestUsage {
	if usageMap, ok := obj["usage"].(map[string]any); ok {
		return grokUsageFromMap(obj, usageMap)
	}
	if resp, ok := obj["response"].(map[string]any); ok {
		if usageMap, ok := resp["usage"].(map[string]any); ok {
			return grokUsageFromMap(resp, usageMap)
		}
	}
	return nil
}

func grokUsageFromMap(obj map[string]any, usageMap map[string]any) *RequestUsage {
	ru := &RequestUsage{Timestamp: time.Now()}
	ru.InputTokens = readInt64(usageMap, "input_tokens")
	if ru.InputTokens == 0 {
		ru.InputTokens = readInt64(usageMap, "prompt_tokens")
	}
	ru.OutputTokens = readInt64(usageMap, "output_tokens")
	if ru.OutputTokens == 0 {
		ru.OutputTokens = readInt64(usageMap, "completion_tokens")
	}
	ru.CachedInputTokens = readInt64(usageMap, "cached_tokens")
	if ru.CachedInputTokens == 0 {
		ru.CachedInputTokens = readInt64(usageMap, "cache_read_input_tokens")
	}
	if details, ok := usageMap["input_tokens_details"].(map[string]any); ok && ru.CachedInputTokens == 0 {
		ru.CachedInputTokens = readInt64(details, "cached_tokens")
	}
	if ru.InputTokens == 0 && ru.OutputTokens == 0 {
		return nil
	}
	ru.BillableTokens = clampNonNegative(ru.InputTokens - ru.CachedInputTokens + ru.OutputTokens)
	if model, ok := obj["model"].(string); ok {
		ru.Model = model
	}
	return ru
}

func (p *GrokProvider) ParseUsageHeaders(acc *Account, headers http.Header) {
	if acc == nil || headers == nil {
		return
	}

	now := time.Now()
	snap := UsageSnapshot{RetrievedAt: now, Source: "headers"}
	if used, ok := parseRateLimitUsageFromRemainingLimit(headers, "x-ratelimit-remaining-requests", "x-ratelimit-limit-requests"); ok {
		snap.PrimaryUsed = used
		snap.PrimaryUsedPercent = used
		snap.primarySet = true
	}
	if used, ok := parseRateLimitUsageFromRemainingLimit(headers, "x-ratelimit-remaining-tokens", "x-ratelimit-limit-tokens"); ok {
		snap.SecondaryUsed = used
		snap.SecondaryUsedPercent = used
		snap.secondarySet = true
	}
	if resetAt, ok := parseRateLimitReset(headers.Get("x-ratelimit-reset-requests")); ok {
		snap.PrimaryResetAt = resetAt
		snap.PrimaryWindowMinutes = rateLimitWindowMinutes(now, resetAt)
	}
	if resetAt, ok := parseRateLimitReset(headers.Get("x-ratelimit-reset-tokens")); ok {
		snap.SecondaryResetAt = resetAt
		snap.SecondaryWindowMinutes = rateLimitWindowMinutes(now, resetAt)
	}
	if !snap.primarySet && !snap.secondarySet {
		return
	}

	acc.mu.Lock()
	acc.Usage = mergeUsage(acc.Usage, snap)
	acc.mu.Unlock()
}

func rateLimitWindowMinutes(now, resetAt time.Time) int {
	if !resetAt.After(now) {
		return 0
	}
	minutes := int(resetAt.Sub(now).Minutes())
	if minutes < 1 {
		return 1
	}
	return minutes
}

func parseGrokBillingUsage(monthlyBody, weeklyBody []byte, now time.Time) (UsageSnapshot, bool) {
	snap := UsageSnapshot{RetrievedAt: now, Source: "grok_billing"}

	var monthly grokBillingResponse
	if json.Unmarshal(monthlyBody, &monthly) == nil && monthly.Config != nil && monthly.Config.MonthlyLimit != nil && monthly.Config.MonthlyLimit.Value > 0 && monthly.Config.Used != nil {
		used := monthly.Config.Used.Value / monthly.Config.MonthlyLimit.Value
		snap.PrimaryUsed = clampRateLimitPercent(used)
		snap.PrimaryUsedPercent = snap.PrimaryUsed
		snap.primarySet = true
		applyGrokBillingPeriod(&snap.PrimaryResetAt, &snap.PrimaryWindowMinutes, monthly.Config.BillingPeriodStart, monthly.Config.BillingPeriodEnd, now)
	}

	var weekly grokBillingResponse
	if json.Unmarshal(weeklyBody, &weekly) == nil && weekly.Config != nil && weekly.Config.CreditUsagePercent != nil {
		used := *weekly.Config.CreditUsagePercent
		if used > 1 {
			used /= 100
		}
		snap.SecondaryUsed = clampRateLimitPercent(used)
		snap.SecondaryUsedPercent = snap.SecondaryUsed
		snap.secondarySet = true
		if weekly.Config.CurrentPeriod != nil {
			applyGrokBillingPeriod(&snap.SecondaryResetAt, &snap.SecondaryWindowMinutes, weekly.Config.CurrentPeriod.Start, weekly.Config.CurrentPeriod.End, now)
		}
	}

	return snap, snap.primarySet || snap.secondarySet
}

func applyGrokBillingPeriod(resetAt *time.Time, windowMinutes *int, startRaw, endRaw string, now time.Time) {
	end, ok := parseGrokTimeValue(endRaw)
	if !ok {
		return
	}
	*resetAt = end
	start, startOK := parseGrokTimeValue(startRaw)
	if startOK && end.After(start) {
		*windowMinutes = int(end.Sub(start).Minutes())
		return
	}
	*windowMinutes = rateLimitWindowMinutes(now, end)
}

func parseGrokTimeValue(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func (p *GrokProvider) UpstreamURL(path string) *url.URL {
	return p.grokBase
}

func (p *GrokProvider) MatchesPath(path string) bool {
	return false
}

func (p *GrokProvider) NormalizePath(path string) string {
	if strings.HasPrefix(path, "/v1/") {
		return strings.TrimPrefix(path, "/v1")
	}
	return path
}

func (p *GrokProvider) DetectsSSE(path string, contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/event-stream")
}

type grokModelInfo struct {
	ID            string
	Name          string
	Reasoning     bool
	ContextWindow int
	MaxTokens     int
	Aliases       []string
}

type grokClientModel struct {
	ID                          string                `json:"id"`
	Object                      string                `json:"object"`
	OwnedBy                     string                `json:"owned_by"`
	Model                       string                `json:"model"`
	Name                        string                `json:"name"`
	Description                 string                `json:"description"`
	ContextWindow               int                   `json:"context_window"`
	AutoCompactThresholdPercent int                   `json:"auto_compact_threshold_percent"`
	SystemPromptLabel           string                `json:"system_prompt_label,omitempty"`
	APIBackend                  string                `json:"api_backend"`
	ReasoningEffort             string                `json:"reasoning_effort,omitempty"`
	SupportsReasoningEffort     bool                  `json:"supports_reasoning_effort,omitempty"`
	ReasoningEfforts            []grokReasoningEffort `json:"reasoning_efforts,omitempty"`
	SupportsBackendSearch       bool                  `json:"supports_backend_search,omitempty"`
	CompactionAtTokens          bool                  `json:"compaction_at_tokens,omitempty"`
	ShowModelFingerprint        bool                  `json:"show_model_fingerprint,omitempty"`
	AgentType                   string                `json:"agent_type,omitempty"`
}

type grokReasoningEffort struct {
	ID          string `json:"id"`
	Value       string `json:"value"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Default     bool   `json:"default"`
}

// grokCLIModelCatalog mirrors the model-discovery payload shipped to Grok Build
// 0.2.101 by cli-chat-proxy. grok-build itself remains a CLI built-in.
var grokCLIModelCatalog = []grokClientModel{
	{
		ID:                          "grok-4.5",
		Object:                      "model",
		OwnedBy:                     "xAI",
		Model:                       "grok-4.5",
		Name:                        "Grok 4.5",
		Description:                 "SpaceXAI's new frontier model",
		ContextWindow:               500000,
		AutoCompactThresholdPercent: 80,
		SystemPromptLabel:           "Grok 4.5",
		APIBackend:                  "responses",
		ReasoningEffort:             "high",
		SupportsReasoningEffort:     true,
		ReasoningEfforts: []grokReasoningEffort{
			{ID: "high", Value: "high", Label: "High Effort", Description: "Highest implementation quality with extensive reasoning", Default: true},
			{ID: "medium", Value: "medium", Label: "Medium Effort", Description: "Balanced effort with standard implementation and testing"},
			{ID: "low", Value: "low", Label: "Low Effort", Description: "Quick, fast implementations"},
		},
		SupportsBackendSearch: true,
		CompactionAtTokens:    true,
		ShowModelFingerprint:  true,
	},
	{
		ID:                          "grok-composer-2.5-fast",
		Object:                      "model",
		OwnedBy:                     "xAI",
		Model:                       "grok-composer-2.5-fast",
		Name:                        "Composer 2.5",
		Description:                 "Cursor's latest coding model",
		ContextWindow:               200000,
		AutoCompactThresholdPercent: 90,
		APIBackend:                  "responses",
		AgentType:                   "cursor",
	},
}

func serveGrokModels(w http.ResponseWriter) {
	respondJSON(w, map[string]any{"object": "list", "data": grokModelsForClient()})
}

func grokModelsForClient() []grokClientModel {
	models := append([]grokClientModel(nil), grokCLIModelCatalog...)
	for _, model := range poolModels {
		apiBackend := "messages"
		if model.AccountType == AccountTypeCodex {
			apiBackend = "chat_completions"
		}
		models = append(models, grokClientModel{
			ID:                          model.ID,
			Object:                      "model",
			OwnedBy:                     "codex-pool",
			Model:                       model.ID,
			Name:                        model.DisplayName,
			Description:                 model.Description,
			ContextWindow:               model.ContextWindow,
			AutoCompactThresholdPercent: 80,
			SystemPromptLabel:           model.DisplayName,
			APIBackend:                  apiBackend,
		})
	}
	return models
}

func grokSetupModelIDs() []string {
	models := grokSetupModels()
	ids := make([]string, 0, len(models)+1)
	seen := make(map[string]struct{}, len(models))
	for _, model := range models {
		if _, ok := seen[model.ID]; ok {
			continue
		}
		seen[model.ID] = struct{}{}
		ids = append(ids, model.ID)
	}
	return ids
}

type grokSetupModel struct {
	ID         string
	APIBackend string
}

func grokSetupModels() []grokSetupModel {
	catalog := grokModelsForClient()
	models := make([]grokSetupModel, 0, len(catalog)+1)
	seen := make(map[string]struct{}, len(catalog)+1)
	for _, model := range catalog {
		if _, ok := seen[model.ID]; ok {
			continue
		}
		seen[model.ID] = struct{}{}
		models = append(models, grokSetupModel{ID: model.ID, APIBackend: model.APIBackend})
	}
	if _, ok := seen["grok-build"]; !ok {
		models = append(models, grokSetupModel{ID: "grok-build", APIBackend: "responses"})
	}
	return models
}

// Catalog sourced from cli-chat-proxy GET /v1/models (Grok Build 0.2.93) plus
// still-routable legacy IDs verified against the same Responses API.
var grokModelCatalog = []grokModelInfo{
	{ID: "grok-4.5", Name: "Grok 4.5", Reasoning: true, ContextWindow: 500000, MaxTokens: 30000, Aliases: []string{"grok-4.5-build"}},
	{ID: "grok-composer-2.5-fast", Name: "Composer 2.5", Reasoning: false, ContextWindow: 200000, MaxTokens: 30000, Aliases: []string{"grok-composer", "grok-code-fast"}},
	{ID: "grok-build", Name: "Grok Build", Reasoning: true, ContextWindow: 512000, MaxTokens: 30000},
	{ID: "grok-4.3", Name: "Grok 4.3", Reasoning: true, ContextWindow: 1000000, MaxTokens: 30000},
	{ID: "grok-4.20-0309-reasoning", Name: "Grok 4.20 Reasoning", Reasoning: true, ContextWindow: 2000000, MaxTokens: 30000},
	{ID: "grok-4.20-0309-non-reasoning", Name: "Grok 4.20 Non-Reasoning", Reasoning: false, ContextWindow: 2000000, MaxTokens: 30000},
	{ID: "grok-4.20-multi-agent-0309", Name: "Grok 4.20 Multi-Agent", Reasoning: true, ContextWindow: 2000000, MaxTokens: 30000},
}

func grokModelByName(model string) (grokModelInfo, bool) {
	name := strings.ToLower(strings.TrimSpace(model))
	for _, info := range grokModelCatalog {
		if strings.EqualFold(info.ID, name) {
			return info, true
		}
		for _, alias := range info.Aliases {
			if strings.EqualFold(alias, name) {
				return info, true
			}
		}
	}
	return grokModelInfo{}, false
}

func isGrokModel(model string) bool {
	_, ok := grokModelByName(model)
	return ok
}

func grokCanonicalModel(model string) string {
	if info, ok := grokModelByName(model); ok {
		return info.ID
	}
	return model
}

func grokClientVersion() string {
	if v := strings.TrimSpace(os.Getenv("GROK_CLIENT_VERSION")); v != "" {
		return v
	}
	return grokDefaultClientVersion
}

func grokModelContextWindow(model string) int {
	if info, ok := grokModelByName(model); ok {
		return info.ContextWindow
	}
	return 1000000
}

func grokModelMaxCompletionTokens(model string) int {
	if info, ok := grokModelByName(model); ok {
		return info.MaxTokens
	}
	return 30000
}

func grokModelSupportsReasoningEffort(model string) bool {
	m := strings.ToLower(grokCanonicalModel(model))
	// Live /v1/models (2026-07-09): grok-4.5 advertises supports_reasoning_effort
	// with high/medium/low. Legacy multi-agent + 4.3 keep the prior allowlist.
	return strings.HasPrefix(m, "grok-4.5") ||
		strings.HasPrefix(m, "grok-4.3") ||
		strings.HasPrefix(m, "grok-4.20-multi-agent")
}

func rewriteAndSanitizeGrokRequestBody(body []byte, model string) []byte {
	if len(body) == 0 {
		return body
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	changed := false
	canonical := grokCanonicalModel(model)
	if current, _ := obj["model"].(string); current != canonical {
		obj["model"] = canonical
		changed = true
	}
	if sanitizeGrokRequestObject(obj, canonical) {
		changed = true
	}
	if !changed {
		return body
	}
	rewritten, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return rewritten
}

func sanitizeGrokRequestBody(body []byte, model string) []byte {
	if len(body) == 0 {
		return body
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	if !sanitizeGrokRequestObject(obj, model) {
		return body
	}
	rewritten, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return rewritten
}

func sanitizeGrokRequestObject(obj map[string]any, model string) bool {
	changed := false
	if _, ok := obj["metadata"]; ok {
		delete(obj, "metadata")
		changed = true
	}
	if rf, ok := obj["response_format"]; ok {
		if _, hasText := obj["text"]; !hasText {
			obj["text"] = map[string]any{"format": rf}
		}
		delete(obj, "response_format")
		changed = true
	}
	if sanitizeGrokTools(obj) {
		changed = true
	}
	if sanitizeGrokNestedUnsupportedFields(obj) {
		changed = true
	}
	// Chat Completions uses top-level reasoningEffort; Responses uses reasoning.effort.
	// Always drop the chat-style field; optionally promote it when the model allows effort.
	if effortRaw, ok := obj["reasoningEffort"]; ok {
		if grokModelSupportsReasoningEffort(model) {
			if _, hasReasoning := obj["reasoning"]; !hasReasoning {
				if effort, ok := effortRaw.(string); ok && strings.TrimSpace(effort) != "" {
					obj["reasoning"] = map[string]any{"effort": strings.TrimSpace(effort)}
				}
			}
		}
		delete(obj, "reasoningEffort")
		changed = true
	}
	if !grokModelSupportsReasoningEffort(model) {
		if _, ok := obj["reasoning"]; ok {
			delete(obj, "reasoning")
			changed = true
		}
	}
	return changed
}

func sanitizeGrokTools(obj map[string]any) bool {
	rawTools, ok := obj["tools"].([]any)
	if !ok {
		return false
	}
	changed := false
	tools := make([]any, 0, len(rawTools))
	for _, rawTool := range rawTools {
		tool, ok := rawTool.(map[string]any)
		if !ok {
			tools = append(tools, rawTool)
			continue
		}
		typeName, _ := tool["type"].(string)
		switch typeName {
		case "image_generation":
			changed = true
			continue
		}
		if sanitizeGrokNestedUnsupportedFields(tool) {
			changed = true
		}
		tools = append(tools, tool)
	}
	if len(tools) == 0 {
		delete(obj, "tools")
		if _, ok := obj["tool_choice"]; ok {
			delete(obj, "tool_choice")
		}
		if _, ok := obj["parallel_tool_calls"]; ok {
			delete(obj, "parallel_tool_calls")
		}
		return true
	}
	obj["tools"] = tools
	return changed
}

func sanitizeGrokNestedUnsupportedFields(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		changed := false
		if _, ok := v["external_web_access"]; ok {
			delete(v, "external_web_access")
			changed = true
		}
		for _, child := range v {
			if sanitizeGrokNestedUnsupportedFields(child) {
				changed = true
			}
		}
		return changed
	case []any:
		changed := false
		for _, child := range v {
			if sanitizeGrokNestedUnsupportedFields(child) {
				changed = true
			}
		}
		return changed
	default:
		return false
	}
}

func parseGrokTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t
		}
	}
	return time.Time{}
}

func parseGrokUnixMillis(raw json.Number) time.Time {
	if strings.TrimSpace(raw.String()) == "" {
		return time.Time{}
	}
	ms, err := raw.Int64()
	if err != nil || ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func grokTokenEndpointFromIssuer(issuer string) string {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return grokDefaultTokenURL
	}
	return issuer + "/oauth2/token"
}

func validateGrokOAuthURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || (u.Hostname() != "x.ai" && !strings.HasSuffix(u.Hostname(), ".x.ai")) {
		return fmt.Errorf("refusing grok refresh endpoint outside x.ai: %s", u.Host)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
