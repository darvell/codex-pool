package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type modelRouteMode int

const (
	bufferedModelRoute modelRouteMode = iota
	streamedModelRoute
)

type routeDiscovery int

const (
	streamedCatalogOnly routeDiscovery = iota
	catalogModelIdentity
	catalogModelPresence
)

type externalModelRoute struct {
	accountType        AccountType
	matches            func(string) bool
	canonical          func(string) string
	rewrite            func([]byte, string) []byte
	discovery          routeDiscovery
	rewriteChangedOnly bool
	claimsBareModels   bool
}

func externalModelRoutes() []externalModelRoute {
	return []externalModelRoute{
		{accountType: AccountTypeKimi, matches: isKimiModel, rewrite: rewriteModelInBody, discovery: catalogModelIdentity, rewriteChangedOnly: true, claimsBareModels: true},
		{accountType: AccountTypeMinimax, matches: isMinimaxModel, canonical: minimaxCanonicalModel, rewrite: rewriteModelInBody, claimsBareModels: true},
		{accountType: AccountTypeZAI, matches: isZAIModel, canonical: zaiCanonicalModel, rewrite: rewriteModelInBody, claimsBareModels: true},
		{accountType: AccountTypeXiaomi, matches: isXiaomiModel, canonical: xiaomiCanonicalModel, rewrite: rewriteModelInBody, claimsBareModels: true},
		{accountType: AccountTypeGrok, matches: isGrokModel, canonical: grokCanonicalModel, rewrite: rewriteAndSanitizeGrokRequestBody, claimsBareModels: true},
		{accountType: AccountTypeAdverserial, matches: isAdverserialModel, canonical: adverserialCanonicalModel, rewrite: rewriteAndClampAdverserialRequestBody, claimsBareModels: true},
		// Mistral reasoning must be normalized after conversion to its wire format.
		{accountType: AccountTypeMistral, matches: isMistralModel, canonical: mistralCanonicalModel},
		{accountType: AccountTypeMistralVibe, matches: isMistralVibeModel, canonical: mistralCanonicalModel},
		// Discovery establishes entitlement; qualified IDs still select Go/Zen profiles.
		{accountType: AccountTypeOpencodeGo, matches: isOpencodeGoModel, canonical: opencodeGoStreamCanonicalModel, rewrite: opencodeGoUpstreamBody, discovery: catalogModelPresence},
	}
}

func externalModelClaimed(model string) bool {
	for _, route := range externalModelRoutes() {
		if route.claimsBareModels && route.matches(model) {
			return true
		}
	}
	return false
}

func (h *proxyHandler) externalModelRoute(model string, mode modelRouteMode) (externalModelRoute, string, bool) {
	for _, route := range externalModelRoutes() {
		var discoveredModel string
		var discovered bool
		if h.pool != nil && (mode == streamedModelRoute || route.discovery != streamedCatalogOnly) {
			discoveredModel, discovered = h.pool.discoveredCanonicalModel(route.accountType, model)
		}
		if route.accountType == AccountTypeOpencodeGo && !opencodeGoDiscoveryRoutes(model) {
			discovered = false
		}
		if !route.matches(model) && !discovered {
			continue
		}
		canonical := model
		if route.canonical != nil {
			canonical = route.canonical(model)
		}
		if discovered && (mode == streamedModelRoute || route.discovery == catalogModelIdentity) {
			canonical = discoveredModel
		}
		return route, canonical, true
	}
	return externalModelRoute{}, model, false
}

func (h *proxyHandler) resolveStreamedModelRoute(path, model string) (Provider, *url.URL, string) {
	route, canonical, ok := h.externalModelRoute(model, streamedModelRoute)
	if !ok {
		return nil, nil, model
	}
	provider := h.registry.ForType(route.accountType)
	if provider == nil {
		return nil, nil, model
	}
	return provider, opencodeGoTargetURL(provider, model, path), canonical
}

func (h *proxyHandler) modelRouteOverride(path, model string, body []byte) (Provider, *url.URL, []byte) {
	if route, canonical, ok := h.externalModelRoute(model, bufferedModelRoute); ok {
		provider := h.registry.ForType(route.accountType)
		if provider == nil {
			return nil, nil, nil
		}
		var rewritten []byte
		if route.rewrite != nil && (!route.rewriteChangedOnly || canonical != model) {
			rewritten = route.rewrite(body, canonical)
		}
		return provider, opencodeGoTargetURL(provider, model, path), rewritten
	}
	if isOpenAIModel(model) {
		if provider := h.registry.ForType(AccountTypeCodex); provider != nil {
			return provider, provider.UpstreamURL(path), nil
		}
	}
	if isClaudeModel(model) && !isCodexToClaudeModelOverridePath(path) {
		if provider := h.registry.ForType(AccountTypeClaude); provider != nil {
			return provider, provider.UpstreamURL(path), rewriteModelInBody(body, claudeCanonicalModel(model))
		}
	}
	return nil, nil, nil
}

func (h *proxyHandler) pickUpstream(path string, headers http.Header) (Provider, *url.URL) {
	if headers.Get("X-Api-Key") != "" {
		provider := h.registry.ForType(AccountTypeClaude)
		return provider, provider.UpstreamURL(path)
	}
	for key := range headers {
		if strings.HasPrefix(strings.ToLower(key), "anthropic-") {
			provider := h.registry.ForType(AccountTypeClaude)
			return provider, provider.UpstreamURL(path)
		}
	}

	provider := h.registry.ForPath(path)
	if provider == nil {
		provider = h.registry.ForType(AccountTypeCodex)
	}
	return provider, provider.UpstreamURL(path)
}

func extractConversationIDFromJSON(blob []byte) string {
	if len(blob) == 0 {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal(blob, &obj); err != nil {
		return ""
	}
	return extractConversationIDFromObject(obj)
}

func extractConversationIDFromObject(obj map[string]any) string {
	for _, key := range []string{"conversation_id", "conversation", "session_id", "prompt_cache_key"} {
		if v, ok := obj[key].(string); ok && v != "" {
			return v
		}
	}
	for _, containerKey := range []string{"client_metadata", "metadata", "meta"} {
		if sub, ok := obj[containerKey].(map[string]any); ok {
			for _, key := range []string{"conversation_id", "conversation", "session_id", "user_id"} {
				if v, ok := sub[key].(string); ok && v != "" {
					return v
				}
			}
		}
	}
	return ""
}

func extractRequestedModelFromJSON(blob []byte) string {
	if len(blob) == 0 {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal(blob, &obj); err != nil {
		return ""
	}
	if v, ok := obj["model"].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func stripCodexModelSuffixes(model string) (base string, reasoningEffort string, serviceTier string) {
	base = strings.TrimSpace(model)
	lower := strings.ToLower(base)
	for _, tier := range []string{"fast", "flex"} {
		suffix := "-" + tier
		if strings.HasSuffix(lower, suffix) {
			serviceTier = tier
			if serviceTier == "fast" {
				serviceTier = "priority"
			}
			base = strings.TrimSpace(base[:len(base)-len(suffix)])
			lower = strings.ToLower(base)
			break
		}
	}

	// GPT-5.6 adds max (above xhigh). ultra is multi-agent product mode;
	// map suffix to max for single-request routing through the pool.
	for _, effort := range []string{"xhigh", "minimal", "medium", "ultra", "none", "high", "max", "low"} {
		suffix := "-" + effort
		if strings.HasSuffix(lower, suffix) {
			reasoningEffort = effort
			if effort == "ultra" {
				reasoningEffort = "max"
			}
			base = strings.TrimSpace(base[:len(base)-len(suffix)])
			break
		}
	}
	return base, reasoningEffort, serviceTier
}

func applyCodexModelSuffixControls(body []byte, originalModel string) ([]byte, string) {
	base, effort, serviceTier := stripCodexModelSuffixes(originalModel)
	if base == "" || (base == originalModel && effort == "" && serviceTier == "") {
		return body, originalModel
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body, originalModel
	}
	obj["model"] = base
	if effort != "" {
		reasoning, _ := obj["reasoning"].(map[string]any)
		if reasoning == nil {
			reasoning = map[string]any{}
		}
		if _, ok := reasoning["summary"]; !ok {
			reasoning["summary"] = "auto"
		}
		reasoning["effort"] = effort
		obj["reasoning"] = reasoning
	}
	if serviceTier != "" {
		obj["service_tier"] = serviceTier
	}
	rewritten, err := json.Marshal(obj)
	if err != nil {
		return body, originalModel
	}
	return rewritten, base
}

func modelRequiresCodexPro(model string) bool {
	return strings.EqualFold(strings.TrimSpace(model), "gpt-5.3-codex-spark")
}

const requiredPlanClaudePremium = "claude_premium"

func claudeRequestRequiresPremium(r *http.Request, model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	if strings.Contains(model, "opus") || strings.Contains(model, "[1m]") {
		return true
	}
	if r == nil {
		return false
	}
	for _, beta := range r.Header.Values("anthropic-beta") {
		if strings.Contains(strings.ToLower(beta), "context-1m-") {
			return true
		}
	}
	return false
}

func requiredPlanForRequest(accountType AccountType, r *http.Request, requestedModel string) string {
	if accountType == AccountTypeCodex && modelRequiresCodexPro(requestedModel) {
		return "pro"
	}
	if accountType == AccountTypeClaude && claudeRequestRequiresPremium(r, requestedModel) {
		return requiredPlanClaudePremium
	}
	return ""
}

func isCodexToClaudeModelOverridePath(path string) bool {
	if detectRequestFormat(path) == FormatOpenAI {
		return true
	}
	return strings.HasPrefix(path, "/v1/responses") || strings.HasPrefix(path, "/responses")
}

const streamedModelRoutePeekBytes = 64 * 1024

func shouldPeekStreamedModelRoute(r *http.Request) bool {
	if r == nil || r.Method != http.MethodPost || !isStreamedModelRoutePath(r.URL.Path) {
		return false
	}
	// Chunked Responses bodies never advertise a size. Peek anyway so a leading
	// "model" field can divert Grok/Kimi/etc. before Codex streaming fallthrough.
	if r.ContentLength < 0 {
		return isCodexResponsesPath(r.URL.Path)
	}
	return r.ContentLength >= streamedModelRoutePeekBytes
}

func (h *proxyHandler) applyStreamedModelRoute(r *http.Request, provider Provider, targetBase *url.URL, reqID string) (Provider, *url.URL, string, error) {
	if r == nil || r.Body == nil || h == nil || h.registry == nil {
		return provider, targetBase, "", nil
	}
	if r.Method != http.MethodPost || !isStreamedModelRoutePath(r.URL.Path) {
		return provider, targetBase, "", nil
	}
	if strings.TrimSpace(r.Header.Get("Content-Encoding")) != "" {
		return provider, targetBase, "", nil
	}
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if contentType != "" && !strings.Contains(contentType, "json") {
		return provider, targetBase, "", nil
	}

	prefix, err := readBodyPrefix(r.Body, streamedModelRoutePeekBytes)
	if err != nil {
		r.Body = &prefixReadCloser{r: bytes.NewReader(prefix), c: r.Body}
		return provider, targetBase, "", err
	}
	restoreBody := func(replacement []byte) {
		r.Body = &prefixReadCloser{r: io.MultiReader(bytes.NewReader(replacement), r.Body), c: r.Body}
	}

	model, valueStart, valueEnd, ok := findTopLevelJSONStringField(prefix, "model")
	if !ok {
		restoreBody(prefix)
		return provider, targetBase, "", nil
	}

	requestedModel := strings.TrimSpace(model)
	if resolved, aliased := h.aliases.resolve(requestedModel); aliased {
		if h.cfg != nil && h.cfg.debug.Load() {
			log.Printf("[%s] streamed model alias: %s -> %s", reqID, requestedModel, resolved)
		}
		requestedModel = resolved
	}
	routeProvider, routeBase, canonicalModel := h.resolveStreamedModelRoute(r.URL.Path, requestedModel)
	if routeProvider == nil {
		restoreBody(prefix)
		return provider, targetBase, model, nil
	}
	rewrittenPrefix := prefix
	delta := 0
	if canonicalModel != model {
		rewrittenPrefix, delta, err = replaceJSONStringToken(prefix, valueStart, valueEnd, canonicalModel)
	}
	if err != nil {
		restoreBody(prefix)
		return provider, targetBase, "", err
	}
	if r.ContentLength >= 0 && delta != 0 {
		r.ContentLength += int64(delta)
		r.Header.Del("Content-Length")
	}
	restoreBody(rewrittenPrefix)
	return routeProvider, routeBase, canonicalModel, nil
}
