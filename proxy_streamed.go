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
	"sync/atomic"
	"time"
)

func (h *proxyHandler) proxyRequestStreamed(w http.ResponseWriter, r *http.Request, reqID, userID, originID string, provider Provider, targetBase *url.URL, requestedModel string) {
	start := time.Now()
	accountType := provider.Type()
	spooled, _ := r.Context().Value(contextSpoolKey{}).(*streamedResponsesRequest)
	contextSession, requestedTier := "", ""
	if spooled != nil {
		contextSession = contextSessionID(spooled.contextMetadata)
		requestedModel, requestedTier = spooled.Model, spooled.ServiceTier
	}

	requiredPlan := requiredPlanForRequest(accountType, r, requestedModel)
	clientIP := getClientIP(r)
	exclude := h.pool.tierExclusions(nil, accountType, requestedModel, requestedTier)
	var acc *Account
	if accountType == AccountTypeKimi {
		acc = h.pool.candidateForModel(contextSession, exclude, accountType, requiredPlan, clientIP, requestedModel)
	} else {
		acc = h.pool.candidate(contextSession, exclude, accountType, requiredPlan, clientIP)
	}
	if acc == nil {
		http.Error(w, fmt.Sprintf("no live %s accounts", accountType), http.StatusServiceUnavailable)
		return
	}

	atomic.AddInt64(&acc.Inflight, 1)
	atomic.AddInt64(&h.inflight, 1)
	defer func() {
		atomic.AddInt64(&acc.Inflight, -1)
		atomic.AddInt64(&h.inflight, -1)
	}()

	intent, _ := r.Context().Value(responsesRequestIntentKey{}).(requestIntent)
	if spooled != nil {
		intent.stream = !spooled.ClientWantsNonStreaming
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

	refreshFailed := false
	if !h.cfg.disableRefresh && h.needsRefresh(acc) {
		if err := h.refreshAccount(ctx, acc); err != nil {
			if isRateLimitError(err) {
				h.applyRateLimit(acc, nil)
			} else {
				refreshFailed = true
			}
			if h.cfg.debug.Load() {
				log.Printf("[%s] refresh %s failed before streamed request: %v", reqID, acc.ID, err)
			}
		}
	}

	authAccount := acc
	if spooled != nil {
		if err := h.nativeContext.prepareSpool(contextScope(userID), clientIP, spooled); err != nil {
			writeContextError(w, err)
			return
		}
		if err := validateResponsesSpoolSize(spooled, h.cfg.maxSpoolBodyBytes); err != nil {
			responsesSpoolError(w, "native context Responses rewrite: ", err)
			return
		}
		r.Body = spooled.File
		r.ContentLength = spooled.Size
		r.Header.Del("Content-Length")
		authAccount = contextAuthSnapshot(acc)
		if err := h.nativeContext.recordDispatch(contextScope(userID), spooled.contextMetadata, authAccount, clientIP); err != nil {
			writeContextError(w, err)
			return
		}
	}

	outURL := new(url.URL)
	*outURL = *r.URL
	outURL.Scheme = targetBase.Scheme
	outURL.Host = targetBase.Host
	outURL.Path = singleJoin(targetBase.Path, provider.NormalizePath(r.URL.Path))
	if accountType == AccountTypeOpencodeGo && opencodeGoIsFreeModel(requestedModel) {
		outURL.Path = singleJoin(targetBase.Path, "/chat/completions")
	}

	authAccount.mu.Lock()
	access := authAccount.AccessToken
	authAccount.mu.Unlock()
	if access == "" {
		http.Error(w, fmt.Sprintf("account %s has empty access token", acc.ID), http.StatusServiceUnavailable)
		return
	}

	// For Claude OAuth tokens, add beta=true query param (required for OAuth to work)
	if provider.Type() == AccountTypeClaude && strings.HasPrefix(access, "sk-ant-oat") {
		q := outURL.Query()
		q.Set("beta", "true")
		outURL.RawQuery = q.Encode()
	}

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
	if spooled == nil && h.cfg.logBodies && h.cfg.bodyLogLimit > 0 {
		reqSample = &bytes.Buffer{}
		body = io.TeeReader(body, &limitedWriter{w: reqSample, n: h.cfg.bodyLogLimit})
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
	// Single-account path has no retry, but the next request may pin this
	// session elsewhere; never hand this account a known foreign echo.
	h.guardCodexTurnStateEcho(userID, extractConversationIDFromHeaders(r.Header), acc, outReq.Header)
	if r.ContentLength >= 0 {
		outReq.ContentLength = r.ContentLength
	}

	// Register and authenticate with the same credential snapshot.
	setPoolAuth(outReq, provider, authAccount, requestedModel)
	scopeCodexDeviceHeaders(outReq.Header, acc, userID)

	outReq.Header.Del("Accept-Encoding")

	if h.cfg.debug.Load() {
		log.Printf("[%s] streamed -> %s %s (account=%s)", reqID, outReq.Method, outReq.URL.String(), acc.ID)
	}

	attemptStart := time.Now()
	resp, err := h.roundTripWithFirstByteDeadline(outReq)
	firstResponseLatency := time.Since(attemptStart)
	captureCodexResponseState(acc, resp, reqID)
	if provider.Type() == AccountTypeCodex && upstreamTokenRevoked(resp) {
		persistDeadAccount(acc, "upstream token revoked")
	}
	if err != nil {
		if !isContextError(err) {
			acc.observeHealth(healthFailure, 0)
		}
		acc.mu.Lock()
		acc.Penalty += 0.2
		acc.mu.Unlock()
		h.recent.add(err.Error())
		if errors.Is(err, errUpstreamFirstByteTimeout) {
			writeUpstreamFirstByteTimeout(w)
			return
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if resp.StatusCode == http.StatusUnauthorized && r.GetBody != nil && h.retryPoolAuth(ctx, acc) {
		_ = resp.Body.Close()
		authAccount = contextAuthSnapshot(acc)
		if spooled != nil {
			if err := h.nativeContext.recordDispatch(contextScope(userID), spooled.contextMetadata, authAccount, clientIP); err != nil {
				writeContextError(w, err)
				return
			}
		}
		retry := outReq.Clone(ctx)
		retry.Body, err = r.GetBody()
		if err != nil {
			http.Error(w, "request replay unavailable", http.StatusInternalServerError)
			return
		}
		setPoolAuth(retry, provider, authAccount, requestedModel)
		resp, err = h.roundTripWithFirstByteDeadline(retry)
		captureCodexResponseState(acc, resp, reqID)
		if err != nil {
			if errors.Is(err, errUpstreamFirstByteTimeout) {
				writeUpstreamFirstByteTimeout(w)
				return
			}
			http.Error(w, "upstream request failed after authentication recovery", http.StatusBadGateway)
			return
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		markedDead, _ := applyProxyAuthFailure(acc, refreshFailed)
		if markedDead {
			if err := saveAccount(acc); err != nil {
				log.Printf("[%s] failed to save account %s after auth failure: %v", reqID, acc.ID, err)
			}
		}
		log.Printf("[%s] upstream authentication unavailable: account=%s path=streamed", reqID, acc.ID)
		h.metrics.inc(strconv.Itoa(http.StatusServiceUnavailable), acc.ID)
		writeUpstreamAuthError(w)
		return
	}

	if h.cfg.logBodies && reqSample != nil && reqSample.Len() > 0 {
		log.Printf("[%s] request body sample (%d bytes): %s", reqID, reqSample.Len(), safeText(reqSample.Bytes()))
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		h.applyRateLimit(acc, resp.Header)
		acc.mu.Lock()
		acc.Penalty += 0.2
		acc.mu.Unlock()
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		decompressed := bodyForInspection(nil, errBody)
		log.Printf("[%s] account %s got %d from %s, body=%s", reqID, acc.ID, resp.StatusCode, outReq.URL.Host, safeText(decompressed))

		resp.Body = io.NopCloser(bytes.NewReader(errBody))

		markedDead, _ := applyProxyAuthFailure(acc, refreshFailed)
		if markedDead {
			if err := saveAccount(acc); err != nil {
				log.Printf("[%s] warning: failed to save dead account %s: %v", reqID, acc.ID, err)
			}
		}
	} else if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
		acc.mu.Lock()
		acc.Penalty += 0.3
		acc.mu.Unlock()
		acc.observeHealth(healthFailure, 0)
	} else if resp.StatusCode < http.StatusBadRequest {
		acc.observeHealth(healthSuccess, firstResponseLatency)
	}

	provider.ParseUsageHeaders(acc, resp.Header)
	h.logRateLimitResponseHeaders(reqID, acc.Type, resp.Header)

	acc.mu.Lock()
	headerPrimaryPct := acc.Usage.PrimaryUsedPercent
	headerSecondaryPct := acc.Usage.SecondaryUsedPercent
	acc.mu.Unlock()

	// Keep hosted MCP output filtering identical for streamed-body requests even
	// when the upstream returns a non-SSE JSON response.
	respContentType := resp.Header.Get("Content-Type")
	isSSE := provider.DetectsSSE(r.URL.Path, respContentType)
	if !isSSE && accountType == AccountTypeCodex && isCodexResponsesPath(r.URL.Path) {
		if err := filterHostedMCPNonStreamingResponse(resp); err != nil {
			http.Error(w, "hosted MCP response filtering error", http.StatusBadGateway)
			return
		}
	}

	copyHeader(w.Header(), resp.Header)
	removeHopByHopHeaders(w.Header())
	h.replaceUsageHeaders(w.Header())
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Single-account path commits here; every exit below writes to the
		// client, so the blob (if any) is confirmedly downstream-held.
		h.noteCodexTurnState(userID, extractConversationIDFromHeaders(r.Header), acc, resp.Header.Get("x-codex-turn-state"))
	}
	flusher, _ := w.(http.Flusher)
	if isSSE {
		applyStreamingResponseHeaders(w.Header())
	}
	w.WriteHeader(resp.StatusCode)

	var writer io.Writer = w
	var fw *flushWriter
	var hw2 *heartbeatWriter
	if isSSE && flusher != nil {
		fw = &flushWriter{w: w, f: flusher, flushInterval: h.cfg.flushInterval}
		hw2 = newHeartbeatWriter(fw, flusher)
		writer = hw2
	}

	// Tee a bounded sample for usage extraction and conversation pinning.
	sampleLimit := int64(16 * 1024)
	if h.cfg.logBodies && h.cfg.bodyLogLimit > 0 {
		sampleLimit = h.cfg.bodyLogLimit
	}
	sampleBuf := &bytes.Buffer{}
	resp.Body = struct {
		io.Reader
		io.Closer
	}{
		Reader: io.TeeReader(resp.Body, &limitedWriter{w: sampleBuf, n: sampleLimit}),
		Closer: resp.Body,
	}

	// Claude sends usage across two SSE events (message_start: input, message_delta: output).
	// Accumulate them into a single RequestUsage before recording.

	var claudeAccum2 *RequestUsage
	cyberPinned := false
	conversationID := extractConversationIDFromHeaders(r.Header)

	if conversationID == "" {
		for _, key := range []string{"X-Claude-Code-Session-Id", "x-claude-code-session-id"} {
			if v := strings.TrimSpace(r.Header.Get(key)); v != "" {
				conversationID = v
				break
			}
		}
	}

	if isSSE {
		usageCallback := func(data []byte, add func(RequestUsage)) {
			if accountType == AccountTypeCodex && !acc.CyberAccess && isCyberPolicyError(data) {
				if h.pinConversationToCyberAccess(conversationID, accountType, requiredPlan, clientIP, acc.ID, reqID) {
					cyberPinned = true
					cancel()
				}
				return
			}
			var obj map[string]any
			if err := json.Unmarshal(data, &obj); err != nil {
				var arr []map[string]any
				if err2 := json.Unmarshal(data, &arr); err2 != nil || len(arr) == 0 {
					return
				}
				obj = arr[0]
			}
			ru := provider.ParseUsage(obj)
			if ru == nil {
				return
			}

			if acc.Type == AccountTypeClaude {
				if claudeAccum2 == nil {
					claudeAccum2 = ru
				} else {
					claudeAccum2.OutputTokens = ru.OutputTokens
					claudeAccum2.BillableTokens = clampNonNegative(
						claudeAccum2.InputTokens - claudeAccum2.CachedInputTokens + ru.OutputTokens)
					ru = claudeAccum2
					claudeAccum2 = nil
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
					add(*ru)
				}
				return
			}
			// Non-Claude usage commits after forwarding this chunk.
			ru.AccountID = acc.ID
			ru.UserID = userID
			ru.OriginID = originID
			ru.AccountType = acc.Type
			acc.mu.Lock()
			ru.PlanType = acc.PlanType
			acc.mu.Unlock()
			add(*ru)
		}
		if accountType == AccountTypeCodex && !acc.CyberAccess {
			suppressor := &cyberPolicyHTTPSuppressor{
				h:              h,
				reqID:          reqID,
				conversationID: conversationID,
				requiredPlan:   requiredPlan,
				clientIP:       clientIP,
				accountID:      acc.ID,
				pinned:         &cyberPinned,
			}
			writer = &sseInterceptWriter{w: writer, onEvent: suppressor.onEvent}
		}
		if accountType == AccountTypeCodex {
			writer = &hostedMCPResponseFilterWriter{w: writer}
		}
		writer = newUsageStream(writer, usageCallback, func(usage RequestUsage) { h.recordUsage(acc, usage) })
	}

	var idleReader *idleTimeoutReader
	if isSSE && h.cfg.streamIdleTimeout > 0 {
		idleReader = newIdleTimeoutReader(resp.Body, h.cfg.streamIdleTimeout, cancel)
		resp.Body = idleReader
	}

	_, copyErr := io.Copy(writer, resp.Body)
	if hw2 != nil {
		if err := hw2.Stop(); copyErr == nil {
			copyErr = err
		}
	}
	if fw != nil {
		if err := fw.stop(); copyErr == nil {
			copyErr = err
		}
	}

	// Flush any accumulated Claude usage that wasn't emitted (e.g., stream ended
	// without message_delta, or only got message_start before error/disconnect).
	if claudeAccum2 != nil {
		claudeAccum2.AccountID = acc.ID
		claudeAccum2.UserID = userID
		claudeAccum2.OriginID = originID
		claudeAccum2.AccountType = acc.Type
		acc.mu.Lock()
		claudeAccum2.PlanType = acc.PlanType
		acc.mu.Unlock()
		if claudeAccum2.PrimaryUsedPct == 0 && headerPrimaryPct > 0 {
			claudeAccum2.PrimaryUsedPct = headerPrimaryPct
		}
		if claudeAccum2.SecondaryUsedPct == 0 && headerSecondaryPct > 0 {
			claudeAccum2.SecondaryUsedPct = headerSecondaryPct
		}

		h.recordUsage(acc, *claudeAccum2)
		claudeAccum2 = nil
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

	respSample := sampleBuf.Bytes()
	if h.cfg.logBodies && len(respSample) > 0 {
		if accountType == AccountTypeCodex {
			respSample = filterHostedMCPResponseSample(respSample, isSSE)
		}
		log.Printf("[%s] response body sample (%d bytes): %s", reqID, len(respSample), safeText(respSample))
	}
	if !isSSE && len(respSample) > 0 {
		h.updateUsageFromBody(acc, respSample, userID, originID)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if conversationID == "" && len(respSample) > 0 {
			conversationID = extractConversationIDFromSSE(respSample)
		}
		if conversationID != "" && !cyberPinned {
			h.pool.pin(conversationID, acc.ID)
		}
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
		log.Printf("[%s] streamed done status=%d account=%s duration_ms=%d", reqID, resp.StatusCode, acc.ID, time.Since(start).Milliseconds())
	}
}
