package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// OpencodeGoProvider handles OpenCode Go subscription accounts ($10/month,
// pooled open coding models served from https://opencode.ai/zen/go/v1).
//
// Auth is a static API key. Chat-completions and Responses endpoints take
// `Authorization: Bearer`, while the Anthropic-compatible messages endpoint
// takes `x-api-key`, so both headers are always sent (verified against the
// opencode repo's zen route handlers and live probes).
//
// Pool model IDs are namespaced as `opencode-go/<model-id>` (matching
// OpenCode's own `opencode-go/` config convention). Bare IDs route to Go
// only when no other provider claims them; overlapping bare IDs keep their
// existing provider.
type OpencodeGoProvider struct {
	opencodeGoBase *url.URL
}

// NewOpencodeGoProvider creates a new OpenCode Go provider.
func NewOpencodeGoProvider(opencodeGoBase *url.URL) *OpencodeGoProvider {
	return &OpencodeGoProvider{opencodeGoBase: opencodeGoBase}
}

func (p *OpencodeGoProvider) Type() AccountType {
	return AccountTypeOpencodeGo
}

// OpencodeGoAuthJSON is the format for OpenCode Go account files.
type OpencodeGoAuthJSON struct {
	APIKey   string `json:"api_key"`
	Dead     bool   `json:"dead"`
	Disabled bool   `json:"disabled"`
}

func (p *OpencodeGoProvider) LoadAccount(name, path string, data []byte) (*Account, error) {
	var gj OpencodeGoAuthJSON
	if err := json.Unmarshal(data, &gj); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if strings.TrimSpace(gj.APIKey) == "" {
		return nil, nil
	}

	acc := &Account{
		Type:        AccountTypeOpencodeGo,
		ID:          strings.TrimSuffix(name, filepath.Ext(name)),
		File:        path,
		AccessToken: strings.TrimSpace(gj.APIKey),
		PlanType:    "opencode_go",
		Dead:        gj.Dead,
		Disabled:    gj.Disabled,
	}
	return acc, nil
}

func (p *OpencodeGoProvider) SetAuthHeaders(req *http.Request, acc *Account) {
	req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
	req.Header.Set("X-Api-Key", acc.AccessToken)
}

// opencodeGoSessionHeader returns the value for the `x-opencode-session`
// header. Go's router hard-requires this header and rejects every request
// without it (HTTP 400 "MissingSessionID"), so we always send one. Prefer the
// client's own value when present; otherwise derive a stable ID from the
// conversation (or pool user) so routing and prompt caching stay consistent
// across the turns of one conversation.
func opencodeGoSessionHeader(r *http.Request, conversationID, userID string) string {
	if r != nil {
		if v := strings.TrimSpace(r.Header.Get("x-opencode-session")); v != "" {
			return v
		}
	}
	seed := strings.TrimSpace(conversationID)
	if seed == "" {
		seed = strings.TrimSpace(userID)
	}
	return ccDerivedHexID(seed, "opencode-go-session", ccProcessSessionID)
}

func (p *OpencodeGoProvider) RefreshToken(ctx context.Context, acc *Account, transport http.RoundTripper) error {
	// API keys don't need refresh
	return nil
}

func (p *OpencodeGoProvider) ParseUsage(obj map[string]any) *RequestUsage {
	// OpenAI-style usage object (chat completions + responses payloads).
	if usageMap, ok := obj["usage"].(map[string]any); ok {
		if ru := opencodeGoUsageFromOpenAIMap(obj, usageMap); ru != nil {
			return ru
		}
	}
	// Responses API nests usage under the response object.
	if resp, ok := obj["response"].(map[string]any); ok {
		if usageMap, ok := resp["usage"].(map[string]any); ok {
			if ru := opencodeGoUsageFromOpenAIMap(resp, usageMap); ru != nil {
				return ru
			}
		}
	}

	// Anthropic-style: message_start / message_delta.
	eventType, _ := obj["type"].(string)
	if eventType == "message_delta" {
		usageMap, ok := obj["usage"].(map[string]any)
		if !ok {
			return nil
		}
		ru := &RequestUsage{Timestamp: time.Now()}
		ru.OutputTokens = readInt64(usageMap, "output_tokens")
		if ru.OutputTokens == 0 {
			return nil
		}
		ru.BillableTokens = ru.OutputTokens
		return ru
	}
	if eventType == "message_start" {
		msg, ok := obj["message"].(map[string]any)
		if !ok {
			return nil
		}
		usageMap, ok := msg["usage"].(map[string]any)
		if !ok {
			return nil
		}
		ru := &RequestUsage{Timestamp: time.Now()}
		applyAnthropicInputUsage(ru, usageMap)
		if ru.InputTokens == 0 {
			return nil
		}
		if model, ok := msg["model"].(string); ok {
			ru.Model = model
		}
		return ru
	}

	return nil
}

func opencodeGoUsageFromOpenAIMap(obj map[string]any, usageMap map[string]any) *RequestUsage {
	ru := &RequestUsage{Timestamp: time.Now(), InputTokenMode: "inclusive"}
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

func (p *OpencodeGoProvider) ParseUsageHeaders(acc *Account, headers http.Header) {
	// Go quota arrives via the dedicated /usage endpoint, polled proactively.
}

func (p *OpencodeGoProvider) UpstreamURL(path string) *url.URL {
	return p.opencodeGoBase
}

func (p *OpencodeGoProvider) MatchesPath(path string) bool {
	// OpenCode Go is model-routed, like the other static-key providers.
	return false
}

func (p *OpencodeGoProvider) NormalizePath(path string) string {
	// Client paths (/v1/messages, /v1/chat/completions, /v1/responses) map
	// onto the same suffixes under the Go base (/zen/go/v1/...).
	if strings.HasPrefix(path, "/v1/") {
		return strings.TrimPrefix(path, "/v1")
	}
	return path
}

func (p *OpencodeGoProvider) DetectsSSE(path string, contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/event-stream")
}

// opencodeGoEndpoint is the Go server-side route serving a model.
type opencodeGoEndpoint string

const (
	opencodeGoEndpointChat      opencodeGoEndpoint = "chat"
	opencodeGoEndpointMessages  opencodeGoEndpoint = "messages"
	opencodeGoEndpointResponses opencodeGoEndpoint = "responses"
)

// opencodeGoEndpointForModel returns the Go endpoint serving the given bare
// model ID, mirroring the endpoint table in the OpenCode Go docs. Models not
// listed there default to chat completions.
func opencodeGoEndpointForModel(bare string) opencodeGoEndpoint {
	switch strings.ToLower(strings.TrimSpace(bare)) {
	case "grok-4.6", "grok-4.5", "gpt-5.6-luna",
		"muse-spark-1.3-contributor", "muse-spark-1.2-contributor":
		return opencodeGoEndpointResponses
	case "minimax-m3", "minimax-m2.7", "minimax-m2.5",
		"qwen3.8-max", "qwen3.8-flash", "qwen3.7-max", "qwen3.7-plus", "qwen3.6-plus":
		return opencodeGoEndpointMessages
	default:
		return opencodeGoEndpointChat
	}
}

// opencodeGoClientProtocol returns the pool client protocol label for a Go
// pool model ID, based on the endpoint serving it.
func opencodeGoClientProtocol(poolModelID string) string {
	if opencodeGoEndpointForModel(opencodeGoUpstreamModel(poolModelID)) == opencodeGoEndpointMessages {
		return "anthropic"
	}
	return "openai"
}

// opencodeGoBareID splits an `opencode-go/<id>` (or `opencode_go/<id>`)
// reference into its bare upstream ID.
func opencodeGoBareID(model string) (string, bool) {
	trimmed := strings.TrimSpace(model)
	lower := strings.ToLower(trimmed)
	for _, prefix := range []string{"opencode-go/", "opencode_go/", "opencode-go:", "opencode_go:"} {
		if strings.HasPrefix(lower, prefix) {
			bare := strings.TrimSpace(trimmed[len(prefix):])
			if bare == "" {
				return "", false
			}
			return bare, true
		}
	}
	return "", false
}

func opencodeGoCatalogID(bare string) string {
	return "opencode-go/" + strings.TrimSpace(bare)
}

// opencodeGoBareModelTaken reports whether a bare model ID is already claimed
// by another provider, in which case only the prefixed form routes to Go.
func opencodeGoBareModelTaken(model string) bool {
	if isKimiModel(model) || isMinimaxModel(model) || isZAIModel(model) ||
		isXiaomiModel(model) || isAdverserialModel(model) || isGrokModel(model) {
		return true
	}
	if isOpenAIModel(model) || isClaudeModel(model) {
		return true
	}
	if _, ok := modelForProvider(AccountTypeGemini, model); ok {
		return true
	}
	return false
}

// isOpencodeGoModel returns true if the given model name should be routed to
// OpenCode Go: always for `opencode-go/<id>` references, and for bare IDs
// only when no other provider claims them.
func isOpencodeGoModel(model string) bool {
	if bare, ok := opencodeGoBareID(model); ok {
		_, found := modelForProvider(AccountTypeOpencodeGo, opencodeGoCatalogID(bare))
		return found
	}
	trimmed := strings.TrimSpace(model)
	if trimmed == "" || opencodeGoBareModelTaken(trimmed) {
		return false
	}
	_, found := modelForProvider(AccountTypeOpencodeGo, opencodeGoCatalogID(trimmed))
	return found
}

// opencodeGoCanonicalModel maps a model reference to its canonical pool ID
// (`opencode-go/<id>`).
func opencodeGoCanonicalModel(model string) string {
	if bare, ok := opencodeGoBareID(model); ok {
		if found, ok := modelForProvider(AccountTypeOpencodeGo, opencodeGoCatalogID(bare)); ok {
			return found.ID
		}
		return model
	}
	if found, ok := modelForProvider(AccountTypeOpencodeGo, opencodeGoCatalogID(strings.TrimSpace(model))); ok {
		return found.ID
	}
	return model
}

// opencodeGoUpstreamModel maps a model reference to the bare ID the Go
// upstream expects in the request body.
func opencodeGoUpstreamModel(model string) string {
	if bare, ok := opencodeGoBareID(model); ok {
		return bare
	}
	return strings.TrimSpace(model)
}

// opencodeGoUpstreamBody rewrites the model to the bare upstream ID and drops
// request fields the Go router's downstream providers reject. The session must
// travel as the x-opencode-session header: a top-level session_id in the body
// makes the upstream provider fail the whole request with HTTP 400.
func opencodeGoUpstreamBody(body []byte, model string) []byte {
	if len(body) == 0 {
		return body
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	changed := false
	if _, ok := obj["session_id"]; ok {
		delete(obj, "session_id")
		changed = true
	}
	if want := opencodeGoUpstreamModel(opencodeGoCanonicalModel(model)); obj["model"] != want {
		obj["model"] = want
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

// opencodeGoStreamCanonicalModel is the resolveStreamedModelRoute canonical
// function: the spooled/streamed body must carry the bare upstream ID.
func opencodeGoStreamCanonicalModel(model string) string {
	return opencodeGoUpstreamModel(opencodeGoCanonicalModel(model))
}

// --- Go subscription usage polling ---
//
// GET <base>/usage with the account key returns rolling/weekly/monthly
// quota windows: {"usage":{"rolling":{"status","percent","resetsAt"},...}}.
// Percent is 0-100 units. Rolling is the 5-hour window, weekly drives
// routing score via the secondary usage slot.

const opencodeGoUsagePollInterval = 15 * time.Minute

type opencodeGoWindowUsage struct {
	Status   string  `json:"status"`
	Percent  float64 `json:"percent"`
	ResetsAt string  `json:"resetsAt"`
}

type opencodeGoUsageResponse struct {
	Usage struct {
		Rolling opencodeGoWindowUsage `json:"rolling"`
		Weekly  opencodeGoWindowUsage `json:"weekly"`
		Monthly opencodeGoWindowUsage `json:"monthly"`
	} `json:"usage"`
}

type opencodeGoQuotaState struct {
	snapshot     UsageSnapshot
	limited      bool
	limitedUntil time.Time
	monthlyPct   float64
}

func parseOpencodeGoUsage(body []byte, now time.Time) (opencodeGoQuotaState, error) {
	var payload opencodeGoUsageResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return opencodeGoQuotaState{}, err
	}
	var out opencodeGoQuotaState
	out.snapshot = UsageSnapshot{RetrievedAt: now, Source: "opencode-go-usage"}

	applyWindow := func(w opencodeGoWindowUsage, set func(pct float64, reset time.Time)) {
		pct := clampRateLimitPercent(w.Percent / 100)
		var reset time.Time
		if ts := strings.TrimSpace(w.ResetsAt); ts != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				reset = parsed
			} else if parsed, err := time.Parse(time.RFC3339, ts); err == nil {
				reset = parsed
			}
		}
		set(pct, reset)
		if strings.EqualFold(strings.TrimSpace(w.Status), "rate-limited") {
			out.limited = true
			if !reset.IsZero() && reset.After(now) && (out.limitedUntil.IsZero() || reset.Before(out.limitedUntil)) {
				out.limitedUntil = reset
			}
		}
	}

	applyWindow(payload.Usage.Rolling, func(pct float64, reset time.Time) {
		out.snapshot.PrimaryUsed = pct
		out.snapshot.PrimaryUsedPercent = pct
		out.snapshot.PrimaryWindowMinutes = 300
		out.snapshot.PrimaryResetAt = reset
	})
	applyWindow(payload.Usage.Weekly, func(pct float64, reset time.Time) {
		out.snapshot.SecondaryUsed = pct
		out.snapshot.SecondaryUsedPercent = pct
		out.snapshot.SecondaryWindowMinutes = 10080
		out.snapshot.SecondaryResetAt = reset
	})
	out.monthlyPct = clampRateLimitPercent(payload.Usage.Monthly.Percent / 100)
	return out, nil
}

func (h *proxyHandler) fetchOpencodeGoUsage(now time.Time, a *Account) error {
	if h == nil || a == nil || h.cfg.opencodeGoBase == nil {
		return fmt.Errorf("opencode-go usage is not configured")
	}
	a.mu.Lock()
	access := a.AccessToken
	a.mu.Unlock()

	usageURL := strings.TrimRight(h.cfg.opencodeGoBase.String(), "/") + "/usage"
	req, _ := http.NewRequest(http.MethodGet, usageURL, nil)
	req.Header.Set("Authorization", "Bearer "+access)

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		a.mu.Lock()
		a.Dead = true
		a.Penalty += 100.0
		a.mu.Unlock()
		log.Printf("marking opencode-go account %s as dead: usage returned %d", a.ID, resp.StatusCode)
		if err := saveAccount(a); err != nil {
			log.Printf("warning: failed to save dead opencode-go account %s: %v", a.ID, err)
		}
		return fmt.Errorf("opencode-go usage unauthorized: %s", resp.Status)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		h.applyRateLimit(a, resp.Header)
		return fmt.Errorf("opencode-go usage rate limited: %s", resp.Status)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("opencode-go usage bad status: %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return err
	}
	state, err := parseOpencodeGoUsage(body, now)
	if err != nil {
		return err
	}

	a.mu.Lock()
	a.Usage = mergeUsage(a.Usage, state.snapshot)
	if !state.limitedUntil.IsZero() {
		if state.limitedUntil.After(a.RateLimitUntil) {
			a.RateLimitUntil = state.limitedUntil
		}
	}
	a.mu.Unlock()
	log.Printf("opencode-go usage fetch %s: rolling=%.1f%% weekly=%.1f%% monthly=%.1f%% limited=%v",
		a.ID, state.snapshot.PrimaryUsedPercent*100, state.snapshot.SecondaryUsedPercent*100,
		state.monthlyPct*100, state.limited)
	restoreValidatedAccount(a, "OpenCode Go usage API")
	return nil
}
