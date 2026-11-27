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
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func (h *proxyHandler) proxyRequest(w http.ResponseWriter, r *http.Request, reqID string) {
	start := time.Now()
	authHeader := r.Header.Get("Authorization")

	// codex_apps MCP and other noop paths must never require a pool token.
	// ServeHTTP already routes these, but keep a guard here in case a future
	// caller reaches proxyRequest with a rewritten / stripped path.
	if shouldNoopCodexPath(r.URL.Path) {
		serveNoopCodexPath(w, r)
		return
	}
	if isCodexResetCreditsPath(r.URL.Path) {
		servePoolCodexResetCredits(w, r)
		return
	}

	userID, _, _, credentialKind, credentialAllowed := h.authorizePoolCredentialRequest(r)
	if credentialKind != "" && !credentialAllowed {
		if isContextRequestPath(r.URL.Path) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":{"message":"Pool credential rejected. Sign in again."}}`)
			return
		}
		http.Error(w, "pool credential revoked, expired, or unknown", http.StatusForbidden)
		return
	}
	if userID != "" && h.cfg.debug.Load() {
		log.Printf("[%s] %s pool user request: user_id=%s", reqID, credentialKind, userID)
	}

	if userID == "" {
		if isProviderCred, providerType := looksLikeProviderCredential(authHeader); isProviderCred {
			if h.cfg.debug.Load() {
				log.Printf("[%s] pass-through request with %s credential", reqID, providerType)
			}
			h.proxyPassthrough(w, r, reqID, providerType, start)
			return
		}
	}

	if userID == "" {
		if isContextRequestPath(r.URL.Path) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":{"message":"Sign in with a valid pool credential."}}`)
			return
		}
		http.Error(w, "unauthorized: valid pool token required", http.StatusUnauthorized)
		return
	}
	if isContextRequestPath(r.URL.Path) {
		h.proxyNativeContext(w, r, userID)
		return
	}
	if r.Method == http.MethodGet && normalizeNoopPath(r.URL.Path) == "/api/pool/models" {
		servePoolModels(w, h.pool)
		return
	}
	if r.Method == http.MethodGet && normalizeNoopPath(r.URL.Path) == "/v1/models" {
		serveUnifiedOpenAIModels(w, h.pool)
		return
	}
	if r.Method == http.MethodGet && normalizeNoopPath(r.URL.Path) == "/v1beta/models" {
		serveUnifiedGeminiModels(w, h.pool)
		return
	}
	originID := hashRequestOrigin(r, h.originHashSalt())
	originIP := getClientIP(r)
	redirectModel := h.modelRedirects.modelFor(originIP)
	forcedTier := h.serviceTierOverride.modelFor(originIP)
	if h.store != nil && originID != "" && originIP != "" {
		h.store.enqueueOriginMetadata(originID, originIP, userID, r.UserAgent(), r.URL.Path, time.Now())
	}

	provider, targetBase := h.pickUpstream(r.URL.Path, r.Header)
	if provider == nil || targetBase == nil {
		http.Error(w, "no upstream for path", http.StatusNotFound)
		return
	}
	accountType := provider.Type()

	if redirectModel != "" && r.Method == http.MethodPost && (strings.HasPrefix(r.URL.Path, "/v1beta/models/") || strings.HasPrefix(r.URL.Path, "/v1/images/")) {
		http.Error(w, "model redirect is unavailable on this endpoint", http.StatusBadRequest)
		return
	}
	if redirectModel != "" && isWebSocketUpgradeRequest(r) && accountType != AccountTypeCodex {
		http.Error(w, "model redirect is unavailable on this endpoint", http.StatusBadRequest)
		return
	}
	if isWebSocketUpgradeRequest(r) {
		h.proxyRequestWebSocket(w, r, reqID, userID, originID, provider, targetBase)
		return
	}

	streamedModel := ""
	streamBody := shouldStreamBody(r, h.cfg.maxInMemoryBodyBytes)
	responsesEncoding := strings.TrimSpace(strings.ToLower(r.Header.Get("Content-Encoding")))
	responsesCompressed := responsesEncoding == "gzip" || responsesEncoding == "zstd"
	responsesCompact := isCodexResponsesPath(r.URL.Path) && strings.HasSuffix(normalizeNoopPath(r.URL.Path), "/compact")
	responsesNeedsSpool := isCodexResponsesPath(r.URL.Path) && !responsesCompact &&
		(responsesCompressed || r.ContentLength < 0 || r.ContentLength > h.cfg.maxInMemoryBodyBytes ||
			(h.responsesWireLimit() > 0 && r.ContentLength > h.responsesWireLimit()))
	// The bounded lexical spool performs Responses model routing itself. Peeking
	// before upload admission could otherwise block forever on a chunked body.
	if redirectModel == "" && forcedTier == "" && !responsesNeedsSpool && (streamBody || shouldPeekStreamedModelRoute(r)) {
		var err error
		provider, targetBase, streamedModel, err = h.applyStreamedModelRoute(r, provider, targetBase, reqID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		accountType = provider.Type()
		streamBody = streamBody || accountType == AccountTypeXiaomi
	}
	// Codex-shaped Responses paths need rewriting and hosted-MCP filtering, but
	// large prompts must not be decoded into map[string]any. Spool token-by-token,
	// then model-route. Codex and Grok have disk-backed normalization; other
	// providers fall back only when decoded bodies fit the bounded RAM path.
	if isCodexResponsesPath(r.URL.Path) {
		// Compact requests still use their dedicated buffered validation and are
		// intentionally outside this narrowly scoped Responses streaming path.
		if !responsesCompact && responsesEncoding != "" && responsesEncoding != "identity" && !responsesCompressed {
			responsesSpoolError(w, "streaming Responses rewrite: ", fmt.Errorf("%w: %q", errResponsesUnsupportedEncoding, responsesEncoding))
			return
		}
		if responsesNeedsSpool {
			// Compressed requests whose wire size is deceptively small still consume
			// the single bounded decompression/spool admission slot.
			releaseSpool, err := h.acquireResponsesSpool(r.Context())
			if err != nil {
				return
			}
			defer releaseSpool()
			rewriteModel := func(model string) string {
				if redirectModel != "" {
					return redirectModel
				}
				model = strings.TrimSpace(model)
				if resolved, ok := h.aliases.resolve(model); ok {
					model = resolved
				}
				if base, _, hasSuffix := parseThinkingSuffix(model); hasSuffix && !isOpenAIModel(base) {
					model = base
				}
				if routed, _, canonical := h.resolveStreamedModelRoute(r.URL.Path, model); routed != nil && canonical != "" {
					return canonical
				}
				return model
			}
			spoolStarted := time.Now()
			spooled, spoolErr := h.spoolHTTPResponsesRequest(w, r, responsesStreamOptions{
				rewriteModel: rewriteModel,
				effortLimit:  h.effortCap.limitFor(userID, originIP),
				forceTier:    forcedTier,
			})
			if spoolErr != nil {
				responsesSpoolError(w, "streaming Responses rewrite: ", spoolErr)
				return
			}
			defer func() { spooled.Close() }()
			if redirectModel != "" && spooled.File != nil && spooled.Model == "" {
				http.Error(w, "model is required for redirect", http.StatusBadRequest)
				return
			}
			if h.handleSpooledPro(w, r, spooled) {
				return
			}
			if spooled.Model != "" {
				if routed, routeBase, _ := h.resolveStreamedModelRoute(r.URL.Path, spooled.Model); routed != nil {
					provider = routed
					targetBase = routeBase
					accountType = routed.Type()
					if h.cfg.debug.Load() {
						log.Printf("[%s] oversized Responses model-route: model=%s provider=%s", reqID, spooled.Model, accountType)
					}
				} else if accountType == AccountTypeCodex && !isOpenAIModel(spooled.Model) {
					http.Error(w, fmt.Sprintf("oversized Responses model %q has no routable provider", spooled.Model), http.StatusBadRequest)
					return
				}
			}
			needsBufferedTransforms := accountType != AccountTypeCodex && accountType != AccountTypeGrok
			canFallbackBuffered := spooled.OriginalSize <= h.cfg.maxInMemoryBodyBytes
			if canFallbackBuffered {
				// Compression and chunking hide decoded size until after admission.
				// Return small bodies to the established whole-object pipeline so every
				// provider transform and non-streaming aggregation remains unchanged.
				decodedBody, readErr := io.ReadAll(io.NewSectionReader(spooled.OriginalFile, 0, spooled.OriginalSize))
				if readErr != nil {
					http.Error(w, readErr.Error(), http.StatusBadRequest)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(decodedBody))
				r.GetBody = nil
				r.ContentLength = int64(len(decodedBody))
				r.Header.Del("Content-Length")
				r.Header.Del("Content-Encoding")
				streamBody = false
				spooled.Close()
				releaseSpool()
			} else if needsBufferedTransforms {
				http.Error(w, fmt.Sprintf("oversized Responses request for %s requires provider-specific buffered transforms", accountType), http.StatusRequestEntityTooLarge)
				return
			} else {
				if spooled.ClientWantsNonStreaming {
					http.Error(w, "oversized pooled Responses requests currently require stream=true", http.StatusRequestEntityTooLarge)
					return
				}
				if accountType == AccountTypeGrok {
					if _, err := spooled.OriginalFile.Seek(0, io.SeekStart); err != nil {
						http.Error(w, "grok request replay error: "+err.Error(), http.StatusBadRequest)
						return
					}
					// The initial routing pass is no longer needed once Grok is known.
					// Remove it before the preserve-fields pass to keep peak disk use bounded.
					closeAndRemoveTemp(spooled.File)
					spooled.File = nil
					grokSpool, err := streamResponsesRequest(spooled.OriginalFile, h.cfg.maxSpoolBodyBytes, responsesStreamOptions{
						ctx:          r.Context(),
						passthrough:  true,
						rewriteModel: rewriteModel,
					})
					if err != nil {
						responsesSpoolError(w, "grok request replay error: ", err)
						return
					}
					grokSpool.OriginalFile = spooled.OriginalFile
					grokSpool.OriginalSize = spooled.OriginalSize
					spooled.File, spooled.OriginalFile = nil, nil
					spooled = grokSpool
					if err := sanitizeSpooledGrokRequest(spooled); err != nil {
						http.Error(w, "grok request sanitizing error: "+err.Error(), http.StatusBadRequest)
						return
					}
					if err := validateResponsesSpoolSize(spooled, h.cfg.maxSpoolBodyBytes); err != nil {
						responsesSpoolError(w, "grok request sanitizing error: ", err)
						return
					}
				}
				closeAndRemoveTemp(spooled.OriginalFile)
				spooled.OriginalFile = nil
				spooled.OriginalSize = 0
				r = r.WithContext(context.WithValue(r.Context(), responsesRequestIntentKey{}, requestIntent{stream: !spooled.ClientWantsNonStreaming}))
				if accountType == AccountTypeCodex {
					r = r.WithContext(context.WithValue(r.Context(), contextSpoolKey{}, spooled))
				}
				r.Body = spooled.File
				r.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(io.NewSectionReader(spooled.File, 0, spooled.Size)), nil
				}
				// Keep admission until the upstream response completes: the transformed
				// file remains live and replayable for authentication recovery.
				r.ContentLength = spooled.Size
				r.Header.Del("Content-Length")
				r.Header.Del("Content-Encoding")
				r.Header.Set("Content-Type", "application/json")
				log.Printf("[%s] disk-streaming Responses request: bytes=%d model=%s provider=%s transform_ms=%d",
					reqID, spooled.Size, spooled.Model, accountType, time.Since(spoolStarted).Milliseconds())
				h.proxyRequestStreamed(w, r, reqID, userID, originID, provider, targetBase, streamedModel)
				return
			}
		}
		if accountType == AccountTypeCodex {
			streamBody = false
		}
	}
	// The streamed-body path only rewrites the model name. These providers also
	// need buffered body transformations: effort normalization for Adverserial
	// and Grok, and Messages-to-Chat translation, reasoning normalization, and
	// usage injection for Mistral. Chunked requests must take the same path.
	if redirectModel != "" || forcedTier != "" || accountType == AccountTypeAdverserial || accountType == AccountTypeGrok || isMistralType(accountType) {
		streamBody = false
	}
	if streamBody {
		if h.cfg.debug.Load() {
			log.Printf("[%s] streaming request body: method=%s path=%s provider=%s content-length=%d",
				reqID, r.Method, r.URL.Path, accountType, r.ContentLength)
		}
		h.proxyRequestStreamed(w, r, reqID, userID, originID, provider, targetBase, streamedModel)
		return
	}

	releaseLargeBody, err := h.acquireLargeReplayBody(r.Context(), r.ContentLength)
	if err != nil {
		return
	}
	defer releaseLargeBody()
	bodyBytes, bodySample, err := readBodyForReplay(r.Body, h.cfg.maxInMemoryBodyBytes, h.cfg.logBodies, h.cfg.bodyLogLimit)
	if err != nil {
		if errors.Is(err, errReplayBodyTooLarge) {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}
	if decoded, changed, err := decodeRequestBody(r.Header.Get("Content-Encoding"), bodyBytes, h.cfg.maxInMemoryBodyBytes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if changed {
		bodyBytes = decoded
		r.Header.Del("Content-Encoding")
		r.Header.Del("Content-Length")
		r.ContentLength = int64(len(bodyBytes))
	}
	if accountType == AccountTypeCodex && isCodexLegacyLivePath(r.URL.Path) {
		bodyBytes, err = rewriteCodexLiveCall(bodyBytes, r.Header.Get("Content-Type"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		r.Header.Set("Content-Type", "application/json")
		r.ContentLength = int64(len(bodyBytes))
	}
	if strings.HasPrefix(r.URL.Path, "/v1/images/generations") {
		if n := imagesGenerationCount(bodyBytes); n > 1 {
			if h.handleImagesGenerationFanout(w, r, bodyBytes, n, reqID) {
				return
			}
		}
	}

	inspect := bodyBytes
	if len(inspect) == 0 {
		inspect = bodySample
	}
	inspect = bodyForInspection(r, inspect)
	var originalObject map[string]any
	originalJSONErr := json.Unmarshal(inspect, &originalObject)
	if originalJSONErr != nil {
		originalObject = nil
	}
	// Capture client intent before normalization forces upstream streaming or
	// removes metadata. Routing and timeout must describe the original request.
	originalModel, _ := originalObject["model"].(string)
	originalModel = strings.TrimSpace(originalModel)
	originalStream, _ := originalObject["stream"].(bool)
	intent := requestIntent{stream: originalStream, image: valueHasImageGenerationTool(originalObject)}
	conversationID := extractConversationIDFromObject(originalObject)
	if conversationID == "" {
		conversationID = extractConversationIDFromHeaders(r.Header)
	}

	if conversationID == "" {
		for _, key := range []string{"X-Claude-Code-Session-Id", "x-claude-code-session-id"} {
			if v := strings.TrimSpace(r.Header.Get(key)); v != "" {
				conversationID = v
				break
			}
		}
	}
	if h.cfg.debug.Load() && conversationID == "" && originalJSONErr == nil {
		keys := make([]string, 0, len(originalObject))
		for key := range originalObject {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if len(keys) > 30 {
			keys = keys[:30]
		}
		log.Printf("[%s] conv_id empty; top-level keys (first %d): %s", reqID, len(keys), strings.Join(keys, ","))
	}
	requestedModel := originalModel
	if redirectModel != "" && requestedModel == "" && r.Method == http.MethodPost && (isCodexResponsesPath(r.URL.Path) || r.URL.Path == "/v1/messages" || r.URL.Path == "/v1/chat/completions") {
		http.Error(w, "model is required for redirect", http.StatusBadRequest)
		return
	}
	if redirectModel != "" && requestedModel != "" {
		rewritten := rewriteModelInBody(bodyBytes, redirectModel)
		if rewritten == nil {
			http.Error(w, "unable to redirect model", http.StatusBadRequest)
			return
		}
		bodyBytes = rewritten
		requestedModel = redirectModel
	}
	if requestedModel == "" {
		requestedModel = antigravityModelFromGeminiPath(r.URL.Path)
	}

	if requestedModel != "" && redirectModel == "" {
		requestedModel, bodyBytes = applyModelAlias(h.aliases, requestedModel, bodyBytes, h.cfg.debug.Load(), reqID)
	}

	if h.handleChatGPTPro(w, r, bodyBytes, requestedModel) {
		return
	}

	// Antigravity owns its complete upstream envelope and protocol conversion.
	// Handle it before the generic provider translator so every public protocol
	// consumes the same model registry and quota scheduler.
	if requestedModel != "" && h.handleAntigravityProxy(w, r, bodyBytes, requestedModel, conversationID, userID, originID, originIP, reqID) {
		return
	}

	if requestedModel != "" && isOpenAIModel(requestedModel) {
		var baseModel string
		bodyBytes, baseModel = applyCodexModelSuffixControls(bodyBytes, requestedModel)
		requestedModel = baseModel

		if limit := h.effortCap.limitFor(userID, originIP); limit != "" {
			capped, previous, changed := capCodexEffortInBody(bodyBytes, limit)
			if changed {
				bodyBytes = capped
				inspect = bodyForInspection(r, capped)
				if json.Unmarshal(inspect, &originalObject) != nil {
					originalObject = nil
				}
				if r.ContentLength >= 0 {
					r.ContentLength = int64(len(bodyBytes))
					r.Header.Del("Content-Length")
				}
				log.Printf("[%s] effort cap: %s -> %s (user=%s origin=%s model=%s)", reqID, previous, limit, userID, originID, requestedModel)
			}
		}
	}

	if forcedTier != "" && isOpenAIModel(requestedModel) {
		var err error
		bodyBytes, err = forceServiceTier(bodyBytes, forcedTier)
		if err != nil {
			http.Error(w, "invalid service tier request", http.StatusBadRequest)
			return
		}
	}

	if requestedModel != "" {
		baseName, _, hasSuffix := parseThinkingSuffix(requestedModel)
		if hasSuffix {
			requestedModel = baseName

			if rewritten := rewriteModelInBody(bodyBytes, baseName); rewritten != nil {
				bodyBytes = rewritten
			}
		}
	}

	if requestedModel != "" {
		if overrideProvider, overrideBase, rewrittenBody := h.modelRouteOverride(r.URL.Path, requestedModel, bodyBytes); overrideProvider != nil {
			provider = overrideProvider
			targetBase = overrideBase
			accountType = overrideProvider.Type()
			if rewrittenBody != nil {
				bodyBytes = rewrittenBody
			}
		}
	}

	// OpenCode Go's router rejects requests missing x-opencode-session (HTTP 400
	// "MissingSessionID"). Stamp it on the incoming request so every outbound
	// attempt — streamed or buffered — carries a stable per-conversation value.
	if accountType == AccountTypeOpencodeGo {
		r.Header.Set("x-opencode-session", opencodeGoSessionHeader(r, conversationID, userID))
	}

	if requestedModel != "" {
		origModel := originalModel
		if origModel != "" {
			_, budget, hasSuffix := parseThinkingSuffix(origModel)
			if hasSuffix && budget > 0 {
				bodyBytes = injectThinkingBudget(bodyBytes, accountType, budget)
				if h.cfg.debug.Load() {
					log.Printf("[%s] thinking suffix: budget=%d provider=%s", reqID, budget, accountType)
				}
			}
		}
	}

	translated, err := translateProxyRequest(r, bodyBytes, accountType, requestedModel)
	if err != nil {
		http.Error(w, "format translation error: "+err.Error(), http.StatusBadRequest)
		return
	}
	bodyBytes = translated.body
	r.URL.Path = translated.path
	translateDir := translated.direction
	sourceFormat, targetFormat := translated.source, translated.target
	imagesResponseFormat := translated.imageFormat
	clientWantsNonStreaming := originalJSONErr == nil && !originalStream || translateDir == TranslateImagesToResponses
	if translateDir != TranslateNone {
		logTranslation(reqID, translateDir, h.cfg.debug.Load())
	}

	imageGenerationRequest := false
	compactRequest := accountType == AccountTypeCodex && r.Method == http.MethodPost && isCompactPath(r.URL.Path)
	if accountType == AccountTypeCodex {
		// Byte-oriented translators retain their contracts. Reuse the original
		// tree only when none of them changed the body; decode changed bytes once.
		upstreamObject := originalObject
		if !bytes.Equal(bodyBytes, inspect) {
			upstreamObject = nil
			if json.Unmarshal(bodyBytes, &upstreamObject) != nil {
				upstreamObject = nil
			}
		}
		if compactRequest && upstreamObject == nil {
			http.Error(w, "compaction request must be a JSON object", http.StatusBadRequest)
			return
		}
		if upstreamObject != nil && isCodexResponsesPath(r.URL.Path) {
			changed := false
			if compactRequest {
				if err := prepareCompactRequest(r, upstreamObject); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				changed = true
			} else if translateDir == TranslateNone && (strings.HasPrefix(r.URL.Path, "/v1/responses") || strings.HasPrefix(r.URL.Path, "/responses")) {
				prepareResponsesObject(upstreamObject)
				changed = true
			} else {
				changed = stripHostedMCPFromResponsesRequest(upstreamObject)
			}
			// Retain the original envelope for revalidation on each account attempt.
			r = r.WithContext(context.WithValue(r.Context(), contextFrameKey{}, upstreamObject))
			if changed {
				bodyBytes, err = json.Marshal(upstreamObject)
				if err != nil {
					http.Error(w, "hosted MCP request filtering error: "+err.Error(), http.StatusBadRequest)
					return
				}
			}
		}
		imageGenerationRequest = valueHasImageGenerationTool(upstreamObject)
	}

	bodyBytes = normalizeResponsesSchemaBody(bodyBytes)
	if accountType == AccountTypeGrok {
		bodyBytes = rewriteAndSanitizeGrokRequestBody(bodyBytes, requestedModel)
	}
	if isMistralType(accountType) {
		bodyBytes = rewriteMistralRequestBody(bodyBytes, requestedModel)
	}

	if h.cfg.debug.Load() {
		log.Printf("[%s] incoming %s %s provider=%s conv_id=%s user_id=%s origin_id=%s authZ_len=%d chatgpt-id=%q content-type=%q content-encoding=%q body_bytes=%d",
			reqID,
			r.Method,
			r.URL.Path,
			accountType,
			conversationID,
			userID,
			originID,
			len(r.Header.Get("Authorization")),
			r.Header.Get("ChatGPT-Account-ID"),
			r.Header.Get("Content-Type"),
			r.Header.Get("Content-Encoding"),
			len(bodyBytes),
		)
		if requestedModel != "" {
			log.Printf("[%s] requested model=%s", reqID, requestedModel)
		}
	}
	if h.cfg.logBodies && len(bodySample) > 0 && !(accountType == AccountTypeCodex && mayHaveContext(bodyBytes)) {
		logSample := bodySample
		if accountType == AccountTypeCodex && isCodexResponsesPath(r.URL.Path) {
			logSample = bodyBytes
			if h.cfg.bodyLogLimit > 0 && int64(len(logSample)) > h.cfg.bodyLogLimit {
				logSample = logSample[:h.cfg.bodyLogLimit]
			}
		}
		log.Printf("[%s] request body sample (%d bytes): %s", reqID, len(logSample), safeText(logSample))
	}

	timeout := timeoutForRequestIntent(r, h.cfg.requestTimeout, h.cfg.streamTimeout, intent)

	ctx := r.Context()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	var prelude *claudePrelude
	if r.Method == http.MethodPost && r.URL.Path == "/v1/messages" && accountType == AccountTypeClaude && translateDir == TranslateNone && originalStream {
		prelude = newClaudePrelude(w, cancel)
		defer prelude.stopWait()
	}

	attempts := h.cfg.maxAttempts
	if attempts <= 0 {
		attempts = 1
	}

	if n := h.pool.countByType(accountType); n > attempts {
		attempts = n
	}

	if n := h.pool.count(); n > 0 && attempts > n {
		attempts = n
	}

	exclude := map[string]bool{}
	var lastErr error
	var lastStatus int
	cyberAccessRetry := false
	requiredPlan := requiredPlanForRequest(accountType, r, requestedModel)
	requestedTier := serviceTierFromJSON(bodyBytes)

	const maxCooldownWait = 10 * time.Second
	const preferredImageCodexAccountID = "neon"
	const maxServerOverloadRetries = 6
	serverOverloadRetries := 0
	sameAccountOverloads := map[string]int{}
	var overloadRetryAccount *Account
	firstByteFailedOver := false

	// Retry a shed once on the same account, then move and cool it down.
	retryOverload := func(acc *Account, header http.Header, body []byte) bool {
		if serverOverloadRetries >= maxServerOverloadRetries {
			return false
		}
		serverOverloadRetries++
		waitOverload := func(delay time.Duration) bool {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
			}
			return ctx.Err() == nil
		}
		if sameAccountOverloads[acc.ID] < maxSameAccountOverloadRetries {
			sameAccountOverloads[acc.ID]++
			delay := serverOverloadRetryDelay(header, body, sameAccountOverloads[acc.ID])
			if h.cfg.debug.Load() {
				log.Printf("[%s] upstream overloaded on account %s; retrying same account in %s (%d/%d)", reqID, acc.ID, delay, serverOverloadRetries, maxServerOverloadRetries)
			}
			overloadRetryAccount = acc
			return waitOverload(delay)
		}
		if h.pool.candidateForTier(conversationID, exclude, accountType, requiredPlan, originIP, requestedModel, requestedTier) != nil {
			applyServerOverloadCooldown(acc)
			if h.cfg.debug.Load() {
				log.Printf("[%s] upstream overloaded on account %s; failing over (%d/%d)", reqID, acc.ID, serverOverloadRetries, maxServerOverloadRetries)
			}
			return true
		}
		exclude = map[string]bool{}
		delay := serverOverloadRetryDelay(header, body, serverOverloadRetries)
		if h.cfg.debug.Load() {
			log.Printf("[%s] upstream overloaded with no alternate account; retrying in %s (%d/%d)", reqID, delay, serverOverloadRetries, maxServerOverloadRetries)
		}
		return waitOverload(delay)
	}
	imageFanoutChild := r.Header.Get("X-Codex-Pool-Image-Fanout") != ""
	imageFanoutIndex, _ := strconv.Atoi(r.Header.Get("X-Codex-Pool-Image-Fanout-Index"))

	for attempt := 1; attempt <= attempts; attempt++ {
		acc := overloadRetryAccount
		overloadRetryAccount = nil
		candidateExclude := h.pool.tierExclusions(exclude, accountType, requestedModel, requestedTier)
		if imageGenerationRequest {
			candidateExclude = make(map[string]bool, len(exclude)+h.pool.countByType(accountType))
			for id, excluded := range h.pool.tierExclusions(exclude, accountType, requestedModel, requestedTier) {
				candidateExclude[id] = excluded
			}
			h.pool.excludeImageIncapable(candidateExclude)
			if imageFanoutChild && attempt == 1 {
				h.pool.excludeInflightWhenIdleAvailable(accountType, candidateExclude)
			}
		}
		if imageGenerationRequest && attempt == 1 && !imageFanoutChild {
			if !candidateExclude[preferredImageCodexAccountID] {
				acc = h.pool.candidateByID(preferredImageCodexAccountID, accountType, requiredPlan, originIP)
			}
			if acc != nil && h.cfg.debug.Load() {
				log.Printf("[%s] routing image generation request to codex account %s", reqID, acc.ID)
			}
		}
		if imageGenerationRequest && imageFanoutChild && attempt == 1 {
			acc = h.pool.imageFanoutCandidate(imageFanoutIndex, candidateExclude, requiredPlan, originIP)
		}
		if acc == nil && cyberAccessRetry {
			acc = h.pool.candidateWithCyberAccess(candidateExclude, accountType, requiredPlan, originIP)
			if acc != nil && h.cfg.debug.Load() {
				log.Printf("[%s] routing cyber_policy retry to %s account %s", reqID, accountType, acc.ID)
			}
		}
		if acc == nil && !cyberAccessRetry {
			candidateConversationID := conversationID
			if imageGenerationRequest {
				candidateConversationID = ""
			}
			acc = h.pool.candidateForModel(candidateConversationID, candidateExclude, accountType, requiredPlan, originIP, requestedModel)
		}
		if acc == nil {
			if cooldown := h.pool.nearestCooldown(accountType, h.pool.tierExclusions(nil, accountType, requestedModel, requestedTier)); cooldown > 0 {
				wait := cooldown
				if wait > maxCooldownWait {
					wait = maxCooldownWait
				}
				if h.cfg.debug.Load() {
					log.Printf("[%s] all %s accounts exhausted, waiting %s for cooldown", reqID, accountType, wait)
				}
				select {
				case <-time.After(wait):

					exclude = map[string]bool{}
					continue
				case <-ctx.Done():
				}
			}
			if lastErr != nil {
				h.recordFailureEvent(failureEvent(reqID, nil, string(accountType), requestedModel, attempt, 0, lastErr, "terminal_failure"))
				prelude.httpError(w, lastErr.Error(), http.StatusServiceUnavailable)
			} else {
				if accountType == AccountTypeCodex && tierNeedsDiscovery(requestedTier) {
					prelude.httpError(w, fmt.Sprintf("no live Codex accounts for model %q with service tier %q", requestedModel, requestedTier), http.StatusServiceUnavailable)
				} else if requiredPlan != "" {
					prelude.httpError(w, fmt.Sprintf("no live %s %s accounts for model %s", accountType, requiredPlan, requestedModel), http.StatusServiceUnavailable)
				} else {
					prelude.httpError(w, fmt.Sprintf("no live %s accounts", accountType), http.StatusServiceUnavailable)
				}
			}
			return
		}
		exclude[acc.ID] = true

		atomic.AddInt64(&acc.Inflight, 1)
		atomic.AddInt64(&h.inflight, 1)

		prelude.startWait()
		attemptStart := time.Now()
		resp, sampleBuf, refreshFailed, err := h.tryOnce(ctx, r, bodyBytes, targetBase, provider, acc, reqID, translateDir, requestedModel, userID, originID, conversationID)
		firstResponseLatency := time.Since(attemptStart)
		prelude.stopWait()

		atomic.AddInt64(&acc.Inflight, -1)
		atomic.AddInt64(&h.inflight, -1)

		if err != nil {
			if !isContextError(err) {
				acc.observeHealth(healthFailure, 0)
			}
			if errors.Is(err, errUpstreamFirstByteTimeout) {
				h.recordFailureEvent(failureEvent(reqID, acc, string(accountType), requestedModel, attempt, http.StatusGatewayTimeout, err, "upstream_first_byte_timeout"))
				// A silent upstream is usually one stuck account. One more
				// deadline on another account still answers well before the
				// upstream's own proxy timeout would.
				if !firstByteFailedOver && ctx.Err() == nil && h.pool.candidateForTier(conversationID, exclude, accountType, requiredPlan, originIP, requestedModel, requestedTier) != nil {
					firstByteFailedOver = true
					lastErr = err
					log.Printf("[%s] account %s sent nothing before the first-byte deadline; failing over", reqID, acc.ID)
					if attempt >= attempts {
						attempts++
					}
					continue
				}
				writeUpstreamFirstByteTimeout(w)
				return
			}
			if !isContextError(err) {
				h.recordFailureEvent(failureEvent(reqID, acc, string(accountType), requestedModel, attempt, 0, err, "attempt_failed"))
			}
			if isContextError(err) {
				if prelude.started() {
					prelude.writeError(w, contextErrorStatus(err), contextErrorBody(err))
				} else {
					writeContextError(w, err)
				}
				return
			}
			lastErr = err
			// Don't retry if client already disconnected — context is dead,
			// every subsequent tryOnce will also fail instantly.
			if ctx.Err() != nil {
				log.Printf("[%s] account %s: request ended after %dms due to context error: %v", reqID, acc.ID, time.Since(start).Milliseconds(), ctx.Err())
				break
			}
			h.recent.add(err.Error())
			if h.cfg.debug.Load() {
				log.Printf("[%s] attempt %d/%d account=%s failed: %v", reqID, attempt, attempts, acc.ID, err)
			}
			continue
		}
		lastStatus = resp.StatusCode
		cyberPinned := false

		errClass := classifyStatus(resp.StatusCode)

		if errClass != ErrorClassNone {
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			resp.Body.Close()
			errBody = bodyForInspection(nil, errBody)
			errBodyStr := string(errBody)
			serverOverloaded := accountType == AccountTypeCodex && isServerOverloadedError(errBody)
			if serverOverloaded {
				errClass = ErrorClassTransient
			}

			if accountType == AccountTypeCodex && isCyberPolicyError(errBody) && !acc.CyberAccess {
				cyberAccessRetry = true
				lastErr = fmt.Errorf("upstream %s from non-cyber-access account %s: %s", resp.Status, acc.ID, errBodyStr)
				h.recent.add(lastErr.Error())
				if h.metrics != nil {
					h.metrics.incCyberPolicy(acc.ID, "retry_4xx")
				}
				if h.cfg.debug.Load() {
					log.Printf("[%s] retrying cyber_policy response from account %s on a cyber_access account", reqID, acc.ID)
				}
				h.recordFailureEvent(failureEvent(reqID, acc, string(accountType), requestedModel, attempt, resp.StatusCode, nil, "attempt_failed"))
				continue
			}

			if acc.Type == AccountTypeCodex && errClass == ErrorClassInvalid && isCodexModelUnavailableError(errBody) {
				errClass = ErrorClassNotFound
				if h.cfg.debug.Load() {
					log.Printf("[%s] reclassified codex 400 as model/account mismatch for account %s", reqID, acc.ID)
				}
			}
			if acc.Type == AccountTypeClaude && isClaudeOrganizationDisabled(errBody) {
				h.disableAccountPermanently(acc, reqID, safeText(errBody))
				lastErr = fmt.Errorf("claude organization disabled for account %s", acc.ID)
				h.recent.add(lastErr.Error())
				h.recordFailureEvent(failureEvent(reqID, acc, string(accountType), requestedModel, attempt, resp.StatusCode, nil, "terminal_failure"))
				continue
			}

			if acc.Type == AccountTypeCodex && isCodexVoiceAccessDenied(errBody) {
				// AVAS voice entitlement is account-independent for this pool. Retrying
				// every account only delays the same terminal response and leaves the
				// caller holding a Location header without a valid SDP answer.
				errClass = ErrorClassInvalid
			}

			// Cloudflare bot challenges return 403 with HTML — not an auth failure.
			// Reclassify as transient so accounts don't accumulate auth penalties.
			if errClass == ErrorClassAuth && isCloudflareChallenge(errBody, resp.Header) {
				errClass = ErrorClassTransient
				if h.cfg.debug.Load() {
					log.Printf("[%s] reclassified 403 as cloudflare challenge for account %s", reqID, acc.ID)
				}
			}

			if errClass == ErrorClassPayment && isDeactivatedWorkspace(errBody) {
				acc.mu.Lock()
				acc.Dead = true
				acc.Penalty += 100.0
				acc.mu.Unlock()
				log.Printf("[%s] marking account %s as DEAD: %s", reqID, acc.ID, errBodyStr)
				if err := saveAccount(acc); err != nil {
					log.Printf("[%s] warning: failed to save dead account %s: %v", reqID, acc.ID, err)
				}
				lastErr = fmt.Errorf("account deactivated: %s", errBodyStr)
				h.recent.add(lastErr.Error())
				h.recordFailureEvent(failureEvent(reqID, acc, string(accountType), requestedModel, attempt, resp.StatusCode, nil, "terminal_failure"))
				continue
			}

			switch errClass {
			case ErrorClassRateLimit:
				h.applyRateLimitResponse(acc, resp.Header, errBody)
				acc.mu.Lock()
				acc.Penalty += 0.2
				acc.mu.Unlock()

			case ErrorClassAuth:
				markedDead, penaltyNow := applyProxyAuthFailure(acc, refreshFailed)
				if markedDead {
					log.Printf("[%s] account %s DEAD: %d refresh failed, body=%s", reqID, acc.ID, resp.StatusCode, errBodyStr)
					if err := saveAccount(acc); err != nil {
						log.Printf("[%s] warning: failed to save dead account %s: %v", reqID, acc.ID, err)
					}
				} else {
					var respHdrs []string
					for k, v := range resp.Header {
						respHdrs = append(respHdrs, fmt.Sprintf("%s=%s", k, v[0]))
					}
					log.Printf("[%s] account %s got %d, penalty now %.1f, body=%s, resp_headers=%v", reqID, acc.ID, resp.StatusCode, penaltyNow, errBodyStr, respHdrs)
				}

			case ErrorClassPayment:

				acc.mu.Lock()
				acc.Penalty += 50.0
				acc.mu.Unlock()

			case ErrorClassTransient:
				acc.mu.Lock()
				acc.Penalty += 0.3
				acc.mu.Unlock()
				acc.observeHealth(healthFailure, 0)

			case ErrorClassNotFound:
				acc.mu.Lock()
				acc.Penalty += 0.1
				acc.mu.Unlock()
			}

			h.recordFailureEvent(failureEvent(reqID, acc, string(accountType), requestedModel, attempt, resp.StatusCode, nil, func() string {
				if errClass.Retryable() {
					return "attempt_failed"
				}
				return "terminal_failure"
			}()))
			if errClass.Retryable() {
				if len(errBody) > 0 {
					lastErr = fmt.Errorf("upstream %s: %s", resp.Status, errBodyStr)
				} else {
					lastErr = fmt.Errorf("upstream %s", resp.Status)
				}
				h.recent.add(lastErr.Error())
				if serverOverloaded {
					if retryOverload(acc, resp.Header, errBody) {
						if attempt >= attempts {
							attempts++
						}
						continue
					}
					if ctx.Err() != nil {
						return
					}
				}
				if h.cfg.debug.Load() && serverOverloaded {
					log.Printf("[%s] upstream overload retry budget exhausted", reqID)
				}
				if h.cfg.debug.Load() {
					log.Printf("[%s] attempt %d/%d account=%s status=%d class=%s refreshFailed=%v",
						reqID, attempt, attempts, acc.ID, resp.StatusCode, errClass, refreshFailed)
				}
				continue
			}

			if prelude.started() {
				prelude.writeError(w, resp.StatusCode, errBody)
				h.metrics.inc(strconv.Itoa(resp.StatusCode), acc.ID)
				return
			}

			if translateDir != TranslateNone {
				translated := translateErrorBody(errBody, targetFormat, sourceFormat)
				resp.Body = io.NopCloser(bytes.NewReader(translated))
			} else {
				resp.Body = io.NopCloser(strings.NewReader(errBodyStr))
			}
		}

		if compactRequest {
			if err := compactHTTPResponse(resp, cancel); err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
		}

		acc.mu.Lock()
		acc.BackoffLevel = 0
		acc.mu.Unlock()
		if resp.StatusCode < http.StatusBadRequest {
			acc.observeHealth(healthSuccess, firstResponseLatency)
		}

		provider.ParseUsageHeaders(acc, resp.Header)
		h.logRateLimitResponseHeaders(reqID, acc.Type, resp.Header)

		// Snapshot rate limits from headers for use in SSE callback
		// (Claude SSE events carry 0% — real data comes from headers)
		acc.mu.Lock()
		headerPrimaryPct := acc.Usage.PrimaryUsedPercent
		headerSecondaryPct := acc.Usage.SecondaryUsedPercent
		acc.mu.Unlock()

		if !prelude.started() {
			copyHeader(w.Header(), resp.Header)
			removeHopByHopHeaders(w.Header())
			h.replaceUsageHeaders(w.Header())
		}

		if strings.Contains(r.URL.Path, "codex/models") && resp.StatusCode == 200 {
			w.Header().Del("Content-Length")
			w.Header().Del("Content-Encoding")
			respBody, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr == nil {
				modified := mergeCodexServiceTiers(injectClaudeModels(respBody, antigravityCatalog(h.pool)), h.pool)
				w.WriteHeader(resp.StatusCode)
				w.Write(modified)
			} else {
				w.WriteHeader(http.StatusBadGateway)
			}
			return
		}

		flusher, _ := w.(http.Flusher)
		respContentType := resp.Header.Get("Content-Type")
		isSSE := provider.DetectsSSE(r.URL.Path, respContentType)
		// When translating to Responses API, the path-based SSE detection may
		// incorrectly flag non-SSE error responses (plain JSON 4xx/5xx) as SSE.
		// Check the actual content-type on error responses to avoid feeding
		// plain JSON through the SSE translator (which would silently drop it).
		if isSSE && resp.StatusCode >= 400 {
			if !strings.Contains(strings.ToLower(respContentType), "text/event-stream") {
				isSSE = false
			}
		}
		if accountType == AccountTypeCodex && isCodexResponsesPath(r.URL.Path) && !isSSE {
			if err := filterHostedMCPNonStreamingResponse(resp); err != nil {
				resp.Body.Close()
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			w.Header().Set("Content-Length", resp.Header.Get("Content-Length"))
		}
		if prelude.started() && !isSSE {
			resp.Body.Close()
			prelude.httpError(w, "upstream did not return an event stream", http.StatusBadGateway)
			return
		}
		if isSSE && !prelude.started() {
			applyStreamingResponseHeaders(w.Header())
		}
		if h.cfg.debug.Load() {
			log.Printf("[%s] response: isSSE=%v content-type=%s translateDir=%d status=%d", reqID, isSSE, respContentType, translateDir, resp.StatusCode)
		}

		// Client wanted non-streaming but Codex requires streaming:
		// buffer SSE events and assemble a non-streaming response.
		if clientWantsNonStreaming && isSSE && translateDir == TranslateNone && accountType == AccountTypeCodex && strings.HasPrefix(r.URL.Path, "/v1/responses") {
			w.Header().Del("Content-Length")
			w.Header().Set("Content-Type", "application/json")

			bufWriter := &responsesBufferingWriter{model: requestedModel}
			inspectWriter := h.wrapBufferedSSEWithCyberDetector(bufWriter, accountType, acc, conversationID, requiredPlan, originIP, reqID, &cyberPinned)
			inspectWriter = &hostedMCPResponseFilterWriter{w: inspectWriter}
			if _, err := io.Copy(inspectWriter, resp.Body); err != nil {
				if h.cfg.debug.Load() {
					log.Printf("[%s] buffering Responses SSE error: %v", reqID, err)
				}
			}
			resp.Body.Close()

			if h.shouldRetryBufferedSSEForCyberPolicy(cyberPinned, attempt, attempts, acc, reqID, "responses") {
				cyberAccessRetry = true
				continue
			}
			// An overload delivered inside an HTTP 200 stream has not reached the
			// client yet, so recover exactly like a pre-stream overload.
			if bufWriter.overloaded {
				acc.observeHealth(healthFailure, 0)
				lastErr = fmt.Errorf("upstream overloaded in stream on account %s", acc.ID)
				h.recent.add(lastErr.Error())
				if retryOverload(acc, resp.Header, nil) {
					if attempt >= attempts {
						attempts++
					}
					continue
				}
				if ctx.Err() != nil {
					return
				}
			}

			w.WriteHeader(resp.StatusCode)
			result := bufWriter.Result()
			if bufWriter.status == "failed" {
				// Failures reach the client as HTTP 200 bodies; record the upstream
				// reason so a reported failure can be traced after the fact.
				log.Printf("[%s] responses failed account=%s model=%s overloaded=%v error=%s", reqID, acc.ID, requestedModel, bufWriter.overloaded, safeText(mustJSON(bufWriter.failure)))
			}
			w.Write(result)
		} else if clientWantsNonStreaming && isSSE && translateDir == TranslateClaudeToResponses {
			w.Header().Del("Content-Length")
			w.Header().Set("Content-Type", "application/json")

			usageCallback := func(data []byte) {
				if sampleBuf != nil {
					sampleBuf.Write(data)
				}
				if accountType == AccountTypeCodex && !acc.CyberAccess && isCyberPolicyError(data) {
					if h.pinConversationToCyberAccess(conversationID, accountType, requiredPlan, originIP, acc.ID, reqID) {
						cyberPinned = true
					}
					return
				}
				var obj map[string]any
				if json.Unmarshal(data, &obj) == nil {
					if ru := provider.ParseUsage(obj); ru != nil {
						if ru.PrimaryUsedPct == 0 && headerPrimaryPct > 0 {
							ru.PrimaryUsedPct = headerPrimaryPct
						}
						if ru.SecondaryUsedPct == 0 && headerSecondaryPct > 0 {
							ru.SecondaryUsedPct = headerSecondaryPct
						}
						ru.UserID = userID
						ru.OriginID = originID
						ru.AccountType = acc.Type
						h.recordUsage(acc, *ru)
					}
				}
			}

			bufWriter := &responsesToClaudeBufferingWriter{
				callback: usageCallback,
				debug:    h.cfg.debug.Load(),
				reqID:    reqID,
				model:    requestedModel,
			}
			var responseWriter io.Writer = bufWriter
			if accountType == AccountTypeCodex {
				responseWriter = &hostedMCPResponseFilterWriter{w: responseWriter}
			}

			if _, err := io.Copy(responseWriter, resp.Body); err != nil {
				if h.cfg.debug.Load() {
					log.Printf("[%s] buffering Claude SSE error: %v", reqID, err)
				}
			}
			resp.Body.Close()

			if h.shouldRetryBufferedSSEForCyberPolicy(cyberPinned, attempt, attempts, acc, reqID, "claude") {
				cyberAccessRetry = true
				continue
			}

			result := bufWriter.Result()
			w.WriteHeader(resp.StatusCode)
			w.Write(result)
		} else if clientWantsNonStreaming && isSSE && translateDir == TranslateImagesToResponses {
			w.Header().Del("Content-Length")
			w.Header().Set("Content-Type", "application/json")

			bufWriter := &responsesBufferingWriter{model: requestedModel}
			inspectWriter := h.wrapBufferedSSEWithCyberDetector(bufWriter, accountType, acc, conversationID, requiredPlan, originIP, reqID, &cyberPinned)
			var rawImageStream bytes.Buffer
			if accountType == AccountTypeCodex {
				inspectWriter = &hostedMCPResponseFilterWriter{w: io.MultiWriter(inspectWriter, &rawImageStream)}
			} else {
				inspectWriter = io.MultiWriter(inspectWriter, &rawImageStream)
			}
			if _, err := io.Copy(inspectWriter, resp.Body); err != nil {
				if h.cfg.debug.Load() {
					log.Printf("[%s] buffering Images SSE error: %v", reqID, err)
				}
			}
			resp.Body.Close()
			if h.shouldRetryBufferedSSEForCyberPolicy(cyberPinned, attempt, attempts, acc, reqID, "images") {
				cyberAccessRetry = true
				continue
			}
			result := bufWriter.Result()
			translated, err := translateResponsesToImagesGeneration(result, imagesResponseFormat)
			if err != nil {
				recordImageGenerationResult(acc, false)
				h.writeImageGenerationTrace(reqID, acc, rawImageStream.Bytes(), result, err)
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			recordImageGenerationResult(acc, true)
			w.WriteHeader(resp.StatusCode)
			w.Write(translated)
		} else if clientWantsNonStreaming && isSSE && translateDir == TranslateCompletionsToResponses {
			w.Header().Del("Content-Length")
			w.Header().Set("Content-Type", "application/json")

			usageCallback := func(data []byte) {
				if sampleBuf != nil {
					sampleBuf.Write(data)
				}
				if accountType == AccountTypeCodex && !acc.CyberAccess && isCyberPolicyError(data) {
					if h.pinConversationToCyberAccess(conversationID, accountType, requiredPlan, originIP, acc.ID, reqID) {
						cyberPinned = true
					}
					return
				}
				var obj map[string]any
				if json.Unmarshal(data, &obj) == nil {
					if ru := provider.ParseUsage(obj); ru != nil {
						if ru.PrimaryUsedPct == 0 && headerPrimaryPct > 0 {
							ru.PrimaryUsedPct = headerPrimaryPct
						}
						if ru.SecondaryUsedPct == 0 && headerSecondaryPct > 0 {
							ru.SecondaryUsedPct = headerSecondaryPct
						}
						ru.UserID = userID
						ru.OriginID = originID
						ru.AccountType = acc.Type
						h.recordUsage(acc, *ru)
					}
				}
			}

			bufWriter := &responsesToCompletionsBufferingWriter{
				callback: usageCallback,
				debug:    h.cfg.debug.Load(),
				reqID:    reqID,
			}
			var responseWriter io.Writer = bufWriter
			if accountType == AccountTypeCodex {
				responseWriter = &hostedMCPResponseFilterWriter{w: responseWriter}
			}

			if _, err := io.Copy(responseWriter, resp.Body); err != nil {
				if h.cfg.debug.Load() {
					log.Printf("[%s] buffering completions SSE error: %v", reqID, err)
				}
			}
			resp.Body.Close()

			if h.shouldRetryBufferedSSEForCyberPolicy(cyberPinned, attempt, attempts, acc, reqID, "completions") {
				cyberAccessRetry = true
				continue
			}

			result := bufWriter.Result()
			w.WriteHeader(resp.StatusCode)
			w.Write(result)
		} else if clientWantsNonStreaming && isSSE && translateDir == TranslateChatToResponses {
			w.Header().Del("Content-Length")
			w.Header().Set("Content-Type", "application/json")

			usageCallback := func(data []byte) {
				if sampleBuf != nil {
					sampleBuf.Write(data)
				}
				if accountType == AccountTypeCodex && !acc.CyberAccess && isCyberPolicyError(data) {
					if h.pinConversationToCyberAccess(conversationID, accountType, requiredPlan, originIP, acc.ID, reqID) {
						cyberPinned = true
					}
					return
				}
				var obj map[string]any
				if json.Unmarshal(data, &obj) == nil {
					if ru := provider.ParseUsage(obj); ru != nil {
						if ru.PrimaryUsedPct == 0 && headerPrimaryPct > 0 {
							ru.PrimaryUsedPct = headerPrimaryPct
						}
						if ru.SecondaryUsedPct == 0 && headerSecondaryPct > 0 {
							ru.SecondaryUsedPct = headerSecondaryPct
						}
						ru.UserID = userID
						ru.OriginID = originID
						ru.AccountType = acc.Type
						h.recordUsage(acc, *ru)
					}
				}
			}

			bufWriter := &responsesToChatCompletionsBufferingWriter{
				callback: usageCallback,
				debug:    h.cfg.debug.Load(),
				reqID:    reqID,
			}
			var responseWriter io.Writer = bufWriter
			if accountType == AccountTypeCodex {
				responseWriter = &hostedMCPResponseFilterWriter{w: responseWriter}
			}

			if _, err := io.Copy(responseWriter, resp.Body); err != nil {
				if h.cfg.debug.Load() {
					log.Printf("[%s] buffering SSE error: %v", reqID, err)
				}
			}
			resp.Body.Close()

			if h.shouldRetryBufferedSSEForCyberPolicy(cyberPinned, attempt, attempts, acc, reqID, "chat") {
				cyberAccessRetry = true
				continue
			}

			result := bufWriter.Result()
			w.WriteHeader(resp.StatusCode)
			w.Write(result)
		} else if !isSSE && translateDir != TranslateNone {
			w.Header().Del("Content-Length")
			w.Header().Set("Content-Type", "application/json")

			respBody, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				h.recent.add(readErr.Error())
				h.metrics.inc("error", acc.ID)
				return
			}

			if sampleBuf != nil {
				sampleBuf.Write(respBody)
			}
			h.updateUsageFromBody(acc, respBody, userID, originID)

			var translated []byte
			if resp.StatusCode >= 400 {
				if translateDir == TranslateClaudeToResponses {
					translated = translateErrorToClaudeFormat(respBody, resp.StatusCode)
				} else if translateDir == TranslateChatToResponses || translateDir == TranslateCompletionsToResponses || translateDir == TranslateImagesToResponses || translateDir == TranslateResponsesToClaude {
					translated = respBody
				} else {
					translated = translateErrorBody(respBody, targetFormat, sourceFormat)
				}
			} else if translateDir == TranslateResponsesToClaude {
				var trErr error
				translated, trErr = translateClaudeRespToResponses(respBody)
				if trErr != nil {
					if h.cfg.debug.Load() {
						log.Printf("[%s] claude->responses translation error: %v", reqID, trErr)
					}
					translated = respBody
				}
			} else if translateDir == TranslateChatToResponses {
				var trErr error
				translated, trErr = translateResponsesToChatCompletions(respBody)
				if trErr != nil {
					if h.cfg.debug.Load() {
						log.Printf("[%s] responses->chat translation error: %v", reqID, trErr)
					}
					translated = respBody
				}
			} else if translateDir == TranslateCompletionsToResponses {
				var trErr error
				translated, trErr = translateResponsesToCompletions(respBody)
				if trErr != nil {
					if h.cfg.debug.Load() {
						log.Printf("[%s] responses->completions translation error: %v", reqID, trErr)
					}
					translated = respBody
				}
			} else if translateDir == TranslateImagesToResponses {
				var trErr error
				translated, trErr = translateResponsesToImagesGeneration(respBody, imagesResponseFormat)
				if trErr != nil {
					recordImageGenerationResult(acc, false)
					if h.cfg.debug.Load() {
						log.Printf("[%s] responses->images translation error: %v", reqID, trErr)
					}
					translated = respBody
				} else {
					recordImageGenerationResult(acc, true)
				}
			} else {
				var trErr error
				translated, trErr = translateResponseBody(respBody, targetFormat, sourceFormat, requestedModel)
				if trErr != nil {
					if h.cfg.debug.Load() {
						log.Printf("[%s] response translation error: %v", reqID, trErr)
					}
					translated = respBody
				}
			}
			w.WriteHeader(resp.StatusCode)
			w.Write(translated)
		} else {
			if isSSE && translateDir != TranslateNone {
				w.Header().Del("Content-Length")
				w.Header().Set("Content-Type", "text/event-stream")
			}
			if !prelude.started() {
				w.WriteHeader(resp.StatusCode)
			}

			var writer io.Writer = w
			var fw *flushWriter
			var hw *heartbeatWriter
			if isSSE && flusher != nil {
				fw = &flushWriter{w: w, f: flusher, flushInterval: h.cfg.flushInterval}
				hw = newHeartbeatWriter(fw, flusher)
				writer = hw
			}

			var claudeAccum *RequestUsage

			usageCallback := func(data []byte, add func(RequestUsage)) {
				if accountType == AccountTypeCodex && !acc.CyberAccess && isCyberPolicyError(data) {
					if h.pinConversationToCyberAccess(conversationID, accountType, requiredPlan, originIP, acc.ID, reqID) {
						cyberPinned = true
						cancel()
					}
					return
				}
				var obj map[string]any
				if err := json.Unmarshal(data, &obj); err != nil {
					var arr []map[string]any
					if err2 := json.Unmarshal(data, &arr); err2 != nil || len(arr) == 0 {
						if h.cfg.debug.Load() {
							log.Printf("[%s] SSE callback: failed to parse JSON: %v", reqID, err)
						}
						return
					}
					obj = arr[0]
				}
				ru := provider.ParseUsage(obj)
				if ru == nil {
					return
				}

				if acc.Type == AccountTypeClaude {
					if claudeAccum == nil {
						claudeAccum = ru
					} else {
						claudeAccum.OutputTokens = ru.OutputTokens
						claudeAccum.BillableTokens = clampNonNegative(
							claudeAccum.InputTokens - claudeAccum.CachedInputTokens - claudeAccum.CacheCreationTokens + ru.OutputTokens)
						ru = claudeAccum
						claudeAccum = nil
						ru.AccountID = acc.ID
						ru.UserID = userID
						ru.OriginID = originID
						ru.AccountType = acc.Type
						acc.mu.Lock()
						ru.PlanType = acc.PlanType
						acc.mu.Unlock()
						if ru.PrimaryUsedPct == 0 && headerPrimaryPct > 0 {
							ru.PrimaryUsedPct = headerPrimaryPct
						}
						if ru.SecondaryUsedPct == 0 && headerSecondaryPct > 0 {
							ru.SecondaryUsedPct = headerSecondaryPct
						}
						if ru.Model == "" {
							ru.Model = requestedModel
						}
						add(*ru)
					}
					return
				}
				ru.AccountID = acc.ID
				ru.UserID = userID
				ru.OriginID = originID
				ru.AccountType = acc.Type
				acc.mu.Lock()
				ru.PlanType = acc.PlanType
				acc.mu.Unlock()
				if ru.Model == "" {
					ru.Model = requestedModel
				}
				add(*ru)
			}

			if isSSE {
				if translateDir == TranslateCompletionsToResponses {
					writer = &responsesToCompletionsWriter{
						w:     writer,
						debug: h.cfg.debug.Load(),
						reqID: reqID,
					}
				} else if translateDir == TranslateChatToResponses {
					writer = &responsesToChatCompletionsWriter{
						w:     writer,
						debug: h.cfg.debug.Load(),
						reqID: reqID,
					}
				} else if translateDir == TranslateResponsesToClaude {
					writer = &claudeToResponsesWriter{
						w:     writer,
						debug: h.cfg.debug.Load(),
						reqID: reqID,
					}
				} else if translateDir == TranslateClaudeToResponses {
					writer = &responsesToClaudeWriter{
						w:     writer,
						debug: h.cfg.debug.Load(),
						reqID: reqID,
					}
				} else if translateDir != TranslateNone {
					responseDir := TranslateClaudeToOAI
					if translateDir == TranslateClaudeToOAI {
						responseDir = TranslateOAIToClaude
					}
					writer = &sseTranslateWriter{
						w:              writer,
						direction:      responseDir,
						finishOnReason: isMistralType(accountType),
						debug:          h.cfg.debug.Load(),
						reqID:          reqID,
					}
				} else if accountType == AccountTypeCodex && !acc.CyberAccess {
					suppressor := &cyberPolicyHTTPSuppressor{
						h: h, reqID: reqID, conversationID: conversationID,
						requiredPlan: requiredPlan, clientIP: originIP, accountID: acc.ID, pinned: &cyberPinned,
					}
					writer = &sseInterceptWriter{w: writer, onEvent: suppressor.onEvent}
				}
				if accountType == AccountTypeCodex {
					writer = &hostedMCPResponseFilterWriter{w: writer}
				}
				if isMistralType(accountType) {
					writer = &mistralSSEWriter{w: writer}
				}
				writer = newUsageStream(writer, usageCallback, func(usage RequestUsage) { h.recordUsage(acc, usage) })
			}

			var idleReader *idleTimeoutReader
			if isSSE && h.cfg.streamIdleTimeout > 0 {
				idleReader = newIdleTimeoutReader(resp.Body, h.cfg.streamIdleTimeout, cancel)
				resp.Body = idleReader
			}

			_, copyErr := io.Copy(writer, resp.Body)
			resp.Body.Close()
			if hw != nil {
				if err := hw.Stop(); copyErr == nil {
					copyErr = err
				}
			}
			if fw != nil {
				if err := fw.stop(); copyErr == nil {
					copyErr = err
				}
			}

			if claudeAccum != nil {
				claudeAccum.AccountID = acc.ID
				claudeAccum.UserID = userID
				claudeAccum.OriginID = originID
				claudeAccum.AccountType = acc.Type
				acc.mu.Lock()
				claudeAccum.PlanType = acc.PlanType
				acc.mu.Unlock()
				if claudeAccum.PrimaryUsedPct == 0 && headerPrimaryPct > 0 {
					claudeAccum.PrimaryUsedPct = headerPrimaryPct
				}
				if claudeAccum.SecondaryUsedPct == 0 && headerSecondaryPct > 0 {
					claudeAccum.SecondaryUsedPct = headerSecondaryPct
				}
				if claudeAccum.Model == "" {
					claudeAccum.Model = requestedModel
				}
				h.recordUsage(acc, *claudeAccum)
			}

			if copyErr != nil {
				if ctx.Err() == nil {
					h.recent.add(copyErr.Error())
					h.metrics.inc("error", acc.ID)
				}
				if idleReader != nil {
					log.Printf("[%s] SSE stream error (account=%s): %v", reqID, acc.ID, copyErr)
				}
				return
			}

			respSample := []byte(nil)
			if sampleBuf != nil {
				respSample = sampleBuf.Bytes()
			}
			if h.cfg.logBodies && len(respSample) > 0 {
				if accountType == AccountTypeCodex {
					respSample = filterHostedMCPResponseSample(respSample, isSSE)
				}
				log.Printf("[%s] response body sample (%d bytes): %s", reqID, len(respSample), safeText(respSample))
			}
			if !isSSE && len(respSample) > 0 {
				h.updateUsageFromBody(acc, respSample, userID, originID)
			}
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if conversationID == "" {
				if sampleBuf != nil && sampleBuf.Len() > 0 {
					conversationID = extractConversationIDFromSSE(sampleBuf.Bytes())
				}
			}
			if conversationID != "" && !cyberPinned {
				h.pool.pin(conversationID, acc.ID)
			}
			// The client now holds this account's turn-state blob. Record it
			// so a later failover to another account strips the echo instead
			// of replaying a blob that account did not mint. Discarded
			// attempts return before this point, so they never poison it.
			h.noteCodexTurnState(userID, conversationID, acc, resp.Header.Get("x-codex-turn-state"))
			acc.mu.Lock()
			acc.LastUsed = time.Now()
			if acc.Penalty > 0 {
				acc.Penalty *= 0.5
				if acc.Penalty < 0.01 {
					acc.Penalty = 0
				}
			}
			acc.mu.Unlock()
		}

		h.metrics.inc(strconv.Itoa(resp.StatusCode), acc.ID)

		if h.cfg.debug.Load() {
			log.Printf("[%s] done status=%d account=%s duration_ms=%d", reqID, resp.StatusCode, acc.ID, time.Since(start).Milliseconds())
		}
		return
	}

	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && prelude.started() {
			prelude.httpError(w, "upstream request timed out", http.StatusGatewayTimeout)
		}
		// Client disconnected — no point sending an error response.
		return
	}
	status := http.StatusBadGateway
	if lastStatus == http.StatusTooManyRequests {
		status = http.StatusTooManyRequests
	}
	if lastErr == nil {
		lastErr = errors.New("all attempts failed")
	}
	prelude.httpError(w, lastErr.Error(), status)
}
