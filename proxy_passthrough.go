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
	"strconv"
	"strings"
	"time"
)

func looksLikeProviderCredential(authHeader string) (bool, AccountType) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false, ""
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return false, ""
	}

	// Pool-generated Claude tokens (current and legacy) should NOT be passed through.
	// These are fake Claude OAuth/API-looking tokens that identify pool users.
	if strings.HasPrefix(token, ClaudePoolTokenPrefix) || strings.HasPrefix(token, ClaudePoolTokenLegacyPrefix) {
		return false, ""
	}

	if strings.HasPrefix(token, "sk-ant-") {
		return true, AccountTypeClaude
	}

	if strings.HasPrefix(token, "sk-proj-") || (strings.HasPrefix(token, "sk-") && !strings.HasPrefix(token, "sk-ant-")) {
		return true, AccountTypeCodex
	}

	// Google OAuth tokens typically start with ya29. (access tokens)
	// But NOT pool tokens which are ya29.pool-*
	if strings.HasPrefix(token, "ya29.") && !strings.HasPrefix(token, "ya29.pool-") {
		return true, AccountTypeGemini
	}

	return false, ""
}

func isClaudePoolToken(secret, authHeader string) (bool, string) {
	if secret == "" {
		return false, ""
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false, ""
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	userID, valid := parseClaudePoolToken(secret, token)
	return valid, userID
}

func (h *proxyHandler) proxyPassthrough(w http.ResponseWriter, r *http.Request, reqID string, providerType AccountType, start time.Time) {
	h.metrics.incPassport("passthrough_requests", string(providerType))
	provider := h.registry.ForType(providerType)
	if provider == nil {
		provider, _ = h.pickUpstream(r.URL.Path, r.Header)
	}
	if provider == nil {
		http.Error(w, "unknown provider", http.StatusBadRequest)
		return
	}

	path := r.URL.Path
	originalPath := path
	if providerType == AccountTypeCodex {
		if shouldNoopCodexPath(path) {
			serveNoopCodexPath(w, r)
			return
		}
	}

	targetBase := provider.UpstreamURL(path)
	if isWebSocketUpgradeRequest(r) {
		h.proxyPassthroughWebSocket(w, r, reqID, providerType, provider, targetBase, start)
		return
	}
	if providerType == AccountTypeCodex && isCodexResponsesPath(path) && !isCompactPath(path) {
		encoding := strings.TrimSpace(strings.ToLower(r.Header.Get("Content-Encoding")))
		compressed := encoding == "gzip" || encoding == "zstd"
		if encoding != "" && encoding != "identity" && !compressed {
			responsesSpoolError(w, "streaming passthrough Responses filter: ", fmt.Errorf("%w: %q", errResponsesUnsupportedEncoding, encoding))
			return
		}
		largeOrChunked := r.ContentLength < 0 || r.ContentLength > h.cfg.maxInMemoryBodyBytes ||
			(h.responsesWireLimit() > 0 && r.ContentLength > h.responsesWireLimit())
		if largeOrChunked || compressed {
			releaseSpool, err := h.acquireResponsesSpool(r.Context())
			if err != nil {
				return
			}
			defer releaseSpool()
			spooled, err := h.spoolHTTPResponsesRequest(w, r, responsesStreamOptions{passthrough: true})
			if err != nil {
				responsesSpoolError(w, "streaming passthrough Responses filter: ", err)
				return
			}
			defer spooled.Close()
			if spooled.OriginalSize <= h.cfg.maxInMemoryBodyBytes {
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
				spooled.Close()
				releaseSpool()
			} else {
				r.Body = spooled.File
				r.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(io.NewSectionReader(spooled.File, 0, spooled.Size)), nil
				}
				r.ContentLength = spooled.Size
				r.Header.Del("Content-Length")
				r.Header.Del("Content-Encoding")
				r.Header.Set("Content-Type", "application/json")
				closeAndRemoveTemp(spooled.OriginalFile)
				spooled.OriginalFile = nil
				spooled.OriginalSize = 0
				r = r.WithContext(context.WithValue(r.Context(), responsesRequestIntentKey{}, requestIntent{stream: !spooled.ClientWantsNonStreaming}))
				h.proxyPassthroughStreamed(w, r, reqID, providerType, provider, targetBase, start)
				return
			}
		}
	}
	streamBody := shouldStreamBody(r, h.cfg.maxInMemoryBodyBytes)
	if providerType == AccountTypeCodex && (codexPassthroughNeedsBodyRewrite(path) || isCodexResponsesPath(path)) {
		streamBody = false
	}
	if streamBody {
		if h.cfg.debug.Load() {
			log.Printf("[%s] passthrough streaming body: method=%s path=%s provider=%s content-length=%d",
				reqID, r.Method, r.URL.Path, providerType, r.ContentLength)
		}
		h.proxyPassthroughStreamed(w, r, reqID, providerType, provider, targetBase, start)
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

	passthroughTranslateDir := TranslateNone
	compactRequest := providerType == AccountTypeCodex && r.Method == http.MethodPost && isCompactPath(path)
	if compactRequest {
		decoded, changed, err := decodeRequestBody(r.Header.Get("Content-Encoding"), bodyBytes, h.cfg.maxInMemoryBodyBytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if changed {
			r.Header.Del("Content-Encoding")
		}
		var obj map[string]any
		if err := json.Unmarshal(decoded, &obj); err != nil {
			http.Error(w, "compaction request must be a JSON object", http.StatusBadRequest)
			return
		}
		if err := prepareCompactRequest(r, obj); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		bodyBytes, err = json.Marshal(obj)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		path = r.URL.Path
	}
	if providerType == AccountTypeCodex {
		if strings.HasPrefix(originalPath, "/v1/completions") && !strings.HasPrefix(originalPath, "/v1/chat/completions") {
			passthroughTranslateDir = TranslateCompletionsToResponses
		} else if strings.HasPrefix(originalPath, "/v1/chat/completions") {
			passthroughTranslateDir = TranslateChatToResponses
		} else if strings.HasPrefix(originalPath, "/v1/messages") {
			passthroughTranslateDir = TranslateClaudeToResponses
		}
		path, bodyBytes, err = codexPassthroughRewrite(path, bodyBytes)
		if err != nil {
			http.Error(w, "format translation error: "+err.Error(), http.StatusBadRequest)
			return
		}
		targetBase = provider.UpstreamURL(path)
		r = r.Clone(r.Context())
		r.URL.Path = path
		if isCodexResponsesPath(path) {
			bodyBytes, _, err = filterHostedMCPRequestJSON(bodyBytes)
			if err != nil {
				http.Error(w, "hosted MCP request filtering error: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
	}

	if h.cfg.debug.Load() {
		log.Printf("[%s] passthrough %s %s provider=%s content-type=%q body_bytes=%d",
			reqID, r.Method, r.URL.Path, providerType,
			r.Header.Get("Content-Type"), len(bodyBytes))

		if providerType == AccountTypeClaude {
			var hdrs []string
			for k, v := range r.Header {
				if strings.HasPrefix(strings.ToLower(k), "anthropic") {
					hdrs = append(hdrs, fmt.Sprintf("%s=%s", k, v[0]))
				}
			}
			log.Printf("[%s] passthrough claude anthropic headers: %v", reqID, hdrs)
		}
	}
	if h.cfg.logBodies && len(bodySample) > 0 {
		logSample := bodySample
		if providerType == AccountTypeCodex && isCodexResponsesPath(r.URL.Path) {
			logSample = bodyBytes
			if h.cfg.bodyLogLimit > 0 && int64(len(logSample)) > h.cfg.bodyLogLimit {
				logSample = logSample[:h.cfg.bodyLogLimit]
			}
		}
		log.Printf("[%s] passthrough request body sample (%d bytes): %s", reqID, len(logSample), safeText(logSample))
	}

	timeout := clientOrDefaultTimeout(r, h.cfg.requestTimeout, h.cfg.streamTimeout, bodyBytes)

	ctx := r.Context()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	outURL := new(url.URL)
	*outURL = *r.URL
	outURL.Scheme = targetBase.Scheme
	outURL.Host = targetBase.Host
	outURL.Path = singleJoin(targetBase.Path, provider.NormalizePath(r.URL.Path))

	var body io.Reader
	if len(bodyBytes) > 0 {
		body = bytes.NewReader(bodyBytes)
	}
	outReq, err := http.NewRequestWithContext(ctx, r.Method, outURL.String(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	outReq.Host = targetBase.Host
	outReq.Header = cloneHeader(r.Header)
	removeHopByHopHeaders(outReq.Header)
	removeConflictingProxyHeaders(outReq.Header)

	outReq.Header.Del("Accept-Encoding")

	if providerType == AccountTypeClaude {
		if outReq.Header.Get("anthropic-version") == "" {
			outReq.Header.Set("anthropic-version", ccAnthropicVersion)
		}
	}

	if h.cfg.debug.Load() {
		log.Printf("[%s] passthrough -> %s %s", reqID, outReq.Method, outReq.URL.String())
	}

	resp, err := h.roundTripWithFirstByteDeadline(outReq)
	if err != nil {
		if providerType == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
			h.writeClaudeTrace(reqID, "passthrough", "", hashRequestOrigin(r, h.originHashSalt()), nil, r, bodyBytes, outReq, bodyBytes, nil, TranslateNone, nil, err.Error())
		}
		h.recent.add(err.Error())
		if errors.Is(err, errUpstreamFirstByteTimeout) {
			writeUpstreamFirstByteTimeout(w)
			return
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if compactRequest {
		if err := compactHTTPResponse(resp, cancel); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	}
	if providerType == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
		sampleLimit := h.claudeTraceSampleLimit(16 * 1024)
		if h.cfg.logBodies && h.cfg.bodyLogLimit > 0 {
			sampleLimit = h.claudeTraceSampleLimit(h.cfg.bodyLogLimit)
		}
		h.attachClaudeTrace(reqID, "passthrough", "", hashRequestOrigin(r, h.originHashSalt()), nil, r, bodyBytes, outReq, bodyBytes, resp, TranslateNone, &bytes.Buffer{}, sampleLimit)
	}

	respContentType := resp.Header.Get("Content-Type")
	isSSE := provider.DetectsSSE(r.URL.Path, respContentType)
	if isSSE && resp.StatusCode >= 400 && !strings.Contains(strings.ToLower(respContentType), "text/event-stream") {
		isSSE = false
	}
	if providerType == AccountTypeCodex && isCodexResponsesPath(r.URL.Path) && !isSSE {
		if err := filterHostedMCPNonStreamingResponse(resp); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	}
	clientWantsNonStreaming := true
	if len(bodyBytes) > 0 {
		var obj map[string]any
		if json.Unmarshal(bodyBytes, &obj) == nil {
			if stream, ok := obj["stream"].(bool); ok && stream {
				clientWantsNonStreaming = false
			}
		}
	}
	if passthroughTranslateDir != TranslateNone && resp.StatusCode < 400 && clientWantsNonStreaming && isSSE {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Del("Content-Length")
		if passthroughTranslateDir == TranslateCompletionsToResponses {
			bufWriter := &responsesToCompletionsBufferingWriter{debug: h.cfg.debug.Load(), reqID: reqID}
			_, _ = io.Copy(&hostedMCPResponseFilterWriter{w: bufWriter}, resp.Body)
			w.WriteHeader(resp.StatusCode)
			w.Write(bufWriter.Result())
			return
		}
		if passthroughTranslateDir == TranslateChatToResponses {
			bufWriter := &responsesToChatCompletionsBufferingWriter{debug: h.cfg.debug.Load(), reqID: reqID}
			_, _ = io.Copy(&hostedMCPResponseFilterWriter{w: bufWriter}, resp.Body)
			w.WriteHeader(resp.StatusCode)
			w.Write(bufWriter.Result())
			return
		}
	}
	if passthroughTranslateDir != TranslateNone && resp.StatusCode < 400 && !isSSE {
		respBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusBadGateway)
			return
		}
		translated := respBody
		if passthroughTranslateDir == TranslateCompletionsToResponses {
			if b, err := translateResponsesToCompletions(respBody); err == nil {
				translated = b
			}
		} else if passthroughTranslateDir == TranslateChatToResponses {
			if b, err := translateResponsesToChatCompletions(respBody); err == nil {
				translated = b
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		w.Write(translated)
		return
	}

	copyHeader(w.Header(), resp.Header)
	removeHopByHopHeaders(w.Header())
	h.logRateLimitResponseHeaders(reqID, providerType, resp.Header)
	h.replaceUsageHeaders(w.Header())
	if isSSE && passthroughTranslateDir != TranslateNone {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Del("Content-Length")
	}
	w.WriteHeader(resp.StatusCode)

	flusher, _ := w.(http.Flusher)

	var writer io.Writer = w
	var fw *flushWriter
	if isSSE && flusher != nil {
		fw = &flushWriter{w: w, f: flusher, flushInterval: h.cfg.flushInterval}
		writer = fw
		defer fw.stop()
	}
	if isSSE && passthroughTranslateDir == TranslateCompletionsToResponses {
		writer = &responsesToCompletionsWriter{w: writer, debug: h.cfg.debug.Load(), reqID: reqID}
	} else if isSSE && passthroughTranslateDir == TranslateChatToResponses {
		writer = &responsesToChatCompletionsWriter{w: writer, debug: h.cfg.debug.Load(), reqID: reqID}
	}
	if isSSE && providerType == AccountTypeCodex {
		writer = &hostedMCPResponseFilterWriter{w: writer}
	}

	var idleReader *idleTimeoutReader
	if isSSE && h.cfg.streamIdleTimeout > 0 {
		idleReader = newIdleTimeoutReader(resp.Body, h.cfg.streamIdleTimeout, cancel)
		defer idleReader.Close()
	}

	source := io.Reader(resp.Body)
	if idleReader != nil {
		source = idleReader
	}
	_, copyErr := io.Copy(writer, source)
	if fw != nil {
		if err := fw.stop(); copyErr == nil {
			copyErr = err
		}
	}
	if copyErr != nil {
		if r.Context().Err() == nil {
			h.recent.add(copyErr.Error())
			h.metrics.inc("error", "passthrough")
		}
		if idleReader != nil {
			log.Printf("[%s] passthrough SSE stream error: %v", reqID, copyErr)
		}
		return
	}

	h.metrics.inc(strconv.Itoa(resp.StatusCode), "passthrough")

	if h.cfg.debug.Load() {
		log.Printf("[%s] passthrough done status=%d duration_ms=%d", reqID, resp.StatusCode, time.Since(start).Milliseconds())
	}
}

func (h *proxyHandler) proxyPassthroughStreamed(w http.ResponseWriter, r *http.Request, reqID string, providerType AccountType, provider Provider, targetBase *url.URL, start time.Time) {
	intent, _ := r.Context().Value(responsesRequestIntentKey{}).(requestIntent)
	timeout := timeoutForRequestIntent(r, h.cfg.requestTimeout, h.cfg.streamTimeout, intent)

	ctx := r.Context()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	outURL := new(url.URL)
	*outURL = *r.URL
	outURL.Scheme = targetBase.Scheme
	outURL.Host = targetBase.Host
	outURL.Path = singleJoin(targetBase.Path, provider.NormalizePath(r.URL.Path))

	var reqSample *bytes.Buffer
	var body io.Reader = r.Body
	if r.GetBody != nil {
		var err error
		body, err = r.GetBody()
		if err != nil {
			http.Error(w, "request replay unavailable", http.StatusInternalServerError)
			return
		}
	}
	// A replayable disk spool may contain very large private prompts. Do not
	// duplicate or sample it into logs; ordinary non-spooled tracing is unchanged.
	if r.GetBody == nil && ((h.cfg.logBodies && h.cfg.bodyLogLimit > 0) || (providerType == AccountTypeClaude && h.cfg.claudeTraceEnabled())) {
		sampleLimit := h.cfg.bodyLogLimit
		if sampleLimit <= 0 || (providerType == AccountTypeClaude && h.cfg.claudeTraceEnabled() && h.cfg.claudeTraceBodyLimit > sampleLimit) {
			sampleLimit = h.cfg.claudeTraceBodyLimit
		}
		reqSample = &bytes.Buffer{}
		body = io.TeeReader(body, &limitedWriter{w: reqSample, n: sampleLimit})
	}

	outReq, err := http.NewRequestWithContext(ctx, r.Method, outURL.String(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	outReq.Host = targetBase.Host
	outReq.Header = cloneHeader(r.Header)
	removeHopByHopHeaders(outReq.Header)
	removeConflictingProxyHeaders(outReq.Header)
	if r.ContentLength >= 0 {
		outReq.ContentLength = r.ContentLength
	}

	outReq.Header.Del("Accept-Encoding")

	if providerType == AccountTypeClaude {
		if outReq.Header.Get("anthropic-version") == "" {
			outReq.Header.Set("anthropic-version", ccAnthropicVersion)
		}
	}

	if h.cfg.debug.Load() {
		log.Printf("[%s] passthrough streamed -> %s %s", reqID, outReq.Method, outReq.URL.String())
	}

	resp, err := h.roundTripWithFirstByteDeadline(outReq)
	if err != nil {
		if providerType == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
			var reqBody []byte
			if reqSample != nil {
				reqBody = reqSample.Bytes()
			}
			h.writeClaudeTrace(reqID, "passthrough_streamed", "", hashRequestOrigin(r, h.originHashSalt()), nil, r, reqBody, outReq, reqBody, nil, TranslateNone, nil, err.Error())
		}
		h.recent.add(err.Error())
		if errors.Is(err, errUpstreamFirstByteTimeout) {
			writeUpstreamFirstByteTimeout(w)
			return
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if providerType == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
		var reqBody []byte
		if reqSample != nil {
			reqBody = reqSample.Bytes()
		}
		sampleLimit := h.claudeTraceSampleLimit(16 * 1024)
		if h.cfg.logBodies && h.cfg.bodyLogLimit > 0 {
			sampleLimit = h.claudeTraceSampleLimit(h.cfg.bodyLogLimit)
		}
		h.attachClaudeTrace(reqID, "passthrough_streamed", "", hashRequestOrigin(r, h.originHashSalt()), nil, r, reqBody, outReq, reqBody, resp, TranslateNone, &bytes.Buffer{}, sampleLimit)
	}

	if h.cfg.logBodies && reqSample != nil && reqSample.Len() > 0 {
		log.Printf("[%s] passthrough request body sample (%d bytes): %s", reqID, reqSample.Len(), safeText(reqSample.Bytes()))
	}

	respContentType := resp.Header.Get("Content-Type")
	isSSE := provider.DetectsSSE(r.URL.Path, respContentType)
	if providerType == AccountTypeCodex && isCodexResponsesPath(r.URL.Path) && !isSSE {
		filterLimit := h.cfg.maxInMemoryBodyBytes
		if filterLimit <= 0 {
			filterLimit = 16 << 20
		}
		if err := filterHostedMCPNonStreamingResponseLimit(resp, filterLimit); err != nil {
			h.recent.add(err.Error())
			http.Error(w, "passthrough Responses response filtering failed: "+err.Error(), http.StatusBadGateway)
			return
		}
	}

	// Write response to client only after non-streaming hosted-MCP filtering has
	// succeeded; otherwise neither upstream headers nor private payload can leak.
	copyHeader(w.Header(), resp.Header)
	removeHopByHopHeaders(w.Header())
	h.logRateLimitResponseHeaders(reqID, providerType, resp.Header)
	h.replaceUsageHeaders(w.Header())
	w.WriteHeader(resp.StatusCode)

	flusher, _ := w.(http.Flusher)

	var writer io.Writer = w
	var fw *flushWriter
	if isSSE && flusher != nil {
		fw = &flushWriter{w: w, f: flusher, flushInterval: h.cfg.flushInterval}
		writer = fw
		defer fw.stop()
	}
	if isSSE && providerType == AccountTypeCodex {
		writer = &hostedMCPResponseFilterWriter{w: writer}
	}

	var idleReader *idleTimeoutReader
	if isSSE && h.cfg.streamIdleTimeout > 0 {
		idleReader = newIdleTimeoutReader(resp.Body, h.cfg.streamIdleTimeout, cancel)
		defer idleReader.Close()
	}

	source := io.Reader(resp.Body)
	if idleReader != nil {
		source = idleReader
	}
	_, copyErr := io.Copy(writer, source)
	if fw != nil {
		if err := fw.stop(); copyErr == nil {
			copyErr = err
		}
	}
	if copyErr != nil {
		h.recent.add(copyErr.Error())
		h.metrics.inc("error", "passthrough")
		if idleReader != nil {
			log.Printf("[%s] passthrough streamed SSE error: %v", reqID, copyErr)
		}
		return
	}

	h.metrics.inc(strconv.Itoa(resp.StatusCode), "passthrough")

	if h.cfg.debug.Load() {
		log.Printf("[%s] passthrough streamed done status=%d duration_ms=%d", reqID, resp.StatusCode, time.Since(start).Milliseconds())
	}
}
