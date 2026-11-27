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

	"github.com/google/uuid"
)

func (h *proxyHandler) tryOnce(
	ctx context.Context,
	in *http.Request,
	bodyBytes []byte,
	targetBase *url.URL,
	provider Provider,
	acc *Account,
	reqID string,
	translateDir TranslateDirection,
	requestedModel string,
	userID string,
	originID string,
	conversationID string,
) (*http.Response, *bytes.Buffer, bool, error) {
	if acc == nil {
		return nil, nil, false, errors.New("nil account")
	}
	refreshFailed := false
	var rawIncomingBody []byte
	if provider.Type() == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
		rawIncomingBody = append([]byte(nil), bodyBytes...)
	}
	if provider.Type() == AccountTypeGrok {
		bodyBytes = rewriteAndSanitizeGrokRequestBody(bodyBytes, requestedModel)
	}

	if !h.cfg.disableRefresh && h.needsRefresh(acc) {
		if err := h.refreshAccount(ctx, acc); err != nil {
			if isRateLimitError(err) {
				h.applyRateLimit(acc, nil)
			}
			if h.cfg.debug.Load() {
				log.Printf("[%s] refresh %s failed: %v (continuing with existing token)", reqID, acc.ID, err)
			}
		}
	}

	outURL := new(url.URL)
	*outURL = *in.URL
	outURL.Scheme = targetBase.Scheme
	outURL.Host = targetBase.Host

	outURL.Path = singleJoin(targetBase.Path, provider.NormalizePath(in.URL.Path))
	if provider.Type() == AccountTypeOpencodeGo && opencodeGoIsFreeModel(requestedModel) {
		outURL.Path = singleJoin(targetBase.Path, "/chat/completions")
	}
	if provider.Type() == AccountTypeCodex && isCodexLegacyLivePath(in.URL.Path) {
		q := outURL.Query()
		q.Set("intent", "quicksilver")
		q.Set("architecture", "avas")
		outURL.RawQuery = q.Encode()
	}

	// For Claude OAuth tokens, add beta=true query param (required for OAuth to work)
	if provider.Type() == AccountTypeClaude && strings.HasPrefix(acc.AccessToken, "sk-ant-oat") {
		q := outURL.Query()
		q.Set("beta", "true")
		outURL.RawQuery = q.Encode()
	}

	contextBody := bodyBytes
	contextObject, _ := in.Context().Value(contextFrameKey{}).(map[string]any)

	buildReq := func() (*http.Request, error) {
		authAccount := acc
		if provider.Type() == AccountTypeCodex && isCodexResponsesPath(in.URL.Path) {
			authAccount = contextAuthSnapshot(acc)
			bodyBytes = contextBody
			if contextObject != nil {
				prepared, changed, err := h.prepareContextObject(userID, getClientIP(in), contextObject, authAccount)
				if err != nil {
					return nil, err
				}
				if changed {
					bodyBytes, err = json.Marshal(prepared)
					if err != nil {
						return nil, errContextInvalid
					}
				}
			} else {
				var err error
				bodyBytes, err = h.prepareContextFrame(userID, getClientIP(in), contextBody, authAccount)
				if err != nil {
					return nil, err
				}
			}
		}
		var body io.Reader
		if len(bodyBytes) > 0 {
			body = bytes.NewReader(bodyBytes)
		}
		outReq, err := http.NewRequestWithContext(ctx, in.Method, outURL.String(), body)
		if err != nil {
			return nil, err
		}

		outReq.Host = targetBase.Host
		outReq.Header = cloneHeader(in.Header)
		removeHopByHopHeaders(outReq.Header)
		removeConflictingProxyHeaders(outReq.Header)
		// A client echo minted by another account is a proxy-chain-only
		// contradiction upstream never sees from real Codex; strip it before
		// this attempt's account sees it.
		h.guardCodexTurnStateEcho(userID, conversationID, acc, outReq.Header)

		outReq.Header.Del("ChatGPT-Account-ID")

		authAccount.mu.Lock()
		access := authAccount.AccessToken
		authAccount.mu.Unlock()

		if access == "" {
			return nil, fmt.Errorf("account %s has empty access token", acc.ID)
		}

		// Use provider's model-specific auth when OpenCode serves a Zen free model.
		setPoolAuth(outReq, provider, authAccount, requestedModel)
		scopeCodexDeviceHeaders(outReq.Header, acc, userID)
		// Native Realtime and GPT Live reject the Codex Responses websocket beta
		// header. Keep it only on the Responses transport that requires it.
		if provider.Type() == AccountTypeCodex && isCodexRealtimePath(in.URL.Path) {
			outReq.Header.Del("OpenAI-Beta")
		}
		if provider.Type() == AccountTypeGrok {
			outReq.Header.Set("x-grok-model-override", grokCanonicalModel(requestedModel))
			outReq.Header.Set("x-grok-context-window", strconv.Itoa(grokModelContextWindow(requestedModel)))
			outReq.Header.Set("x-grok-max-completion-tokens", strconv.Itoa(grokModelMaxCompletionTokens(requestedModel)))
			if conversationID != "" {
				outReq.Header.Set("x-grok-conv-id", conversationID)
			}
		}

		if provider.Type() == AccountTypeClaude && translateDir == TranslateNone && strings.HasPrefix(access, "sk-ant-oat") {
			outReq.Header.Set("anthropic-beta", appendAnthropicBeta(outReq.Header.Get("anthropic-beta"), betaOAuth))
		}

		// When translating, body size changes — remove the client's Content-Length
		// so Go's HTTP client recalculates it from the actual body.
		if translateDir != TranslateNone {
			outReq.Header.Del("Content-Length")
			outReq.ContentLength = int64(len(bodyBytes))
		}

		outReq.Header.Del("Accept-Encoding")

		if translateDir == TranslateClaudeToOAI || translateDir == TranslateClaudeToResponses {
			outReq.Header.Del("anthropic-version")
			outReq.Header.Del("anthropic-beta")
			outReq.Header.Del("anthropic-dangerous-direct-browser-access")
			outReq.Header.Del("Sec-Fetch-Mode")
			outReq.Header.Del("Accept-Language")
			outReq.Header.Del("X-App")

			for key := range outReq.Header {
				if strings.HasPrefix(strings.ToLower(key), "x-stainless-") {
					outReq.Header.Del(key)
				}
			}
			// For Codex Responses API, force SSE accept since Codex always streams
			if translateDir == TranslateClaudeToResponses {
				outReq.Header.Set("Accept", "text/event-stream")
			}
		} else if translateDir == TranslateChatToResponses || translateDir == TranslateCompletionsToResponses || translateDir == TranslateImagesToResponses {
			outReq.Header.Set("Accept", "text/event-stream")
			outReq.Header.Set("Content-Type", "application/json")
		} else if translateDir == TranslateOAIToClaude || translateDir == TranslateResponsesToClaude {
			// Client sent OpenAI/Responses format but upstream is Claude — make request
			// indistinguishable from a native Claude Code request.
			isOAuth := strings.HasPrefix(access, "sk-ant-oat")
			is1M := strings.Contains(strings.ToLower(requestedModel), "[1m]")

			acceptHeader := "application/json"
			isFastMode := false
			var bodyObj map[string]any
			if json.Unmarshal(bodyBytes, &bodyObj) == nil {
				if s, ok := bodyObj["stream"].(bool); ok && s {
					acceptHeader = "text/event-stream"
				}
				if sp, ok := bodyObj["speed"].(string); ok && sp == "fast" {
					isFastMode = true
				}

				sessionID := ccSessionHeader(in, userID)
				h.pacer.wait(sessionID)

				acc.mu.Lock()
				accUUID := acc.AccountUUID
				acc.mu.Unlock()
				ccInjectMetadata(bodyObj, accUUID, userID, sessionID)
				if !bodyHasClaudeSystemBlocks(bodyObj) {
					bodyBytes = ccInjectSystemBlocks(bodyObj, bodyBytes)
					_ = json.Unmarshal(bodyBytes, &bodyObj)
				}
				if reordered, err := orderedMarshal(bodyObj, claudeBodyKeyOrder); err == nil {
					bodyBytes = reordered
				}
			}

			bodyModel := ""
			if m, ok := bodyObj["model"].(string); ok {
				bodyModel = m
			}
			if bodyModel == "" {
				bodyModel = requestedModel
			}

			outReq.Header.Set("anthropic-version", ccAnthropicVersion)
			hasStructuredOutputs := ccRequestHasStructuredOutputs(bodyObj)
			hasTaskBudget := ccRequestHasTaskBudget(bodyObj)
			outReq.Header.Set("anthropic-beta", ccBetaHeader(bodyModel, isOAuth, is1M, isFastMode, hasStructuredOutputs, hasTaskBudget))
			outReq.Header.Set("anthropic-dangerous-direct-browser-access", "true")
			outReq.Header.Set("User-Agent", ccUserAgent())
			outReq.Header.Set("X-Claude-Code-Session-Id", ccSessionHeader(in, userID))
			outReq.Header.Set("X-App", "cli")
			outReq.Header.Set("x-client-request-id", uuid.NewString())
			outReq.Header.Set("Accept", acceptHeader)
			outReq.Header.Set("Accept-Language", "*")
			outReq.Header.Set("Content-Type", "application/json")
			outReq.Header.Set("Sec-Fetch-Mode", "cors")
			// Add x-stainless headers to match Anthropic SDK fingerprint
			ccStainlessHeaders(outReq.Header.Set)

			outReq.Header.Del("openai-beta")
			outReq.Header.Del("openai-organization")
		}

		if provider.Type() == AccountTypeClaude &&
			translateDir == TranslateNone &&
			strings.HasPrefix(access, "sk-ant-oat") {
			var bodyObj map[string]any
			if json.Unmarshal(bodyBytes, &bodyObj) == nil && !ccIsGenuineClaudeCodeRequest(in, bodyObj) {
				sessionID := ccSessionHeader(in, userID)
				acc.mu.Lock()
				accUUID := acc.AccountUUID
				acc.mu.Unlock()
				ccInjectMetadata(bodyObj, accUUID, userID, sessionID)
				if _, ok := bodyObj["tools"]; !ok {
					bodyObj["tools"] = []any{}
				}
				if _, ok := bodyObj["temperature"]; !ok {
					bodyObj["temperature"] = 1
				}
				if !bodyHasClaudeSystemBlocks(bodyObj) {
					bodyBytes = ccInjectSystemBlocks(bodyObj, bodyBytes)
					_ = json.Unmarshal(bodyBytes, &bodyObj)
				}
				if reordered, err := orderedMarshal(bodyObj, claudeBodyKeyOrder); err == nil {
					bodyBytes = reordered
				}

				model, _ := bodyObj["model"].(string)
				outReq.Header.Set("anthropic-version", ccAnthropicVersion)
				outReq.Header.Set("anthropic-beta", ccBetaHeader(model, true, false, false, ccRequestHasStructuredOutputs(bodyObj), ccRequestHasTaskBudget(bodyObj)))
				outReq.Header.Set("anthropic-dangerous-direct-browser-access", "true")
				outReq.Header.Set("User-Agent", ccUserAgent())
				outReq.Header.Set("X-Claude-Code-Session-Id", sessionID)
				outReq.Header.Set("X-App", "cli")
				outReq.Header.Set("x-client-request-id", uuid.NewString())
				outReq.Header.Set("Accept-Language", "*")
				outReq.Header.Set("Sec-Fetch-Mode", "cors")
				ccStainlessHeaders(outReq.Header.Set)
			}
		}

		if provider.Type() == AccountTypeClaude && strings.HasPrefix(access, "sk-ant-oat") {
			if normalized, hits, changed := normalizeAnthropicDateline(bodyBytes); changed {
				bodyBytes = normalized
				if h.cfg.debug.Load() {
					log.Printf("[%s] normalized %d Anthropic dateline fingerprint(s)", reqID, len(hits))
				}
			}
		}

		if len(bodyBytes) > 0 {
			// buildReq runs again after a refresh, so the scoped copy never
			// replaces bodyBytes.
			wireBody := scopeCodexDeviceBody(bodyBytes, acc, userID)
			outReq.Body = io.NopCloser(bytes.NewReader(wireBody))
			outReq.ContentLength = int64(len(wireBody))
			outReq.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(wireBody)), nil
			}
			outReq.Header.Del("Content-Length")
		}

		if h.cfg.debug.Load() {
			log.Printf("[%s] outgoing headers (%s): %v", reqID, provider.Type(), debugHeaderSummary(outReq.Header))
		}

		return outReq, nil
	}

	outReq, err := buildReq()
	if err != nil {
		if provider.Type() == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
			h.writeClaudeTrace(reqID, "pool", userID, originID, acc, in, rawIncomingBody, nil, bodyBytes, nil, translateDir, nil, err.Error())
		}
		return nil, nil, false, err
	}

	if h.cfg.debug.Load() {
		acc.mu.Lock()
		log.Printf("[%s] -> %s %s (account=%s account_id=%s)", reqID, outReq.Method, outReq.URL.String(), acc.ID, acc.AccountID)
		acc.mu.Unlock()
	}

	resp, err := h.roundTripWithFirstByteDeadline(outReq)
	captureCodexResponseState(acc, resp, reqID)
	if err != nil {
		if provider.Type() == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
			h.writeClaudeTrace(reqID, "pool", userID, originID, acc, in, rawIncomingBody, outReq, bodyBytes, resp, translateDir, nil, err.Error())
		}
		acc.mu.Lock()
		acc.Penalty += 0.2
		acc.mu.Unlock()
		return nil, nil, false, err
	}

	if provider.Type() == AccountTypeCodex && upstreamTokenRevoked(resp) {
		persistDeadAccount(acc, "upstream token revoked")
		refreshFailed = true
	}
	if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && !h.cfg.disableRefresh {
		if h.cfg.debug.Load() {
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))

			decompressed := bodyForInspection(nil, errBody)
			log.Printf("[%s] got %d from upstream, body: %s", reqID, resp.StatusCode, safeText(decompressed))
		}
		acc.mu.Lock()
		hasRefresh := acc.RefreshToken != ""
		acc.mu.Unlock()
		if hasRefresh {
			_ = resp.Body.Close()
			if err := h.refreshAccountAfterAuthFailure(ctx, acc); err == nil {
				outReq, err = buildReq()
				if err != nil {
					if provider.Type() == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
						h.writeClaudeTrace(reqID, "pool", userID, originID, acc, in, rawIncomingBody, nil, bodyBytes, nil, translateDir, nil, err.Error())
					}
					return nil, nil, false, err
				}
				if h.cfg.debug.Load() {
					acc.mu.Lock()
					log.Printf("[%s] retry after refresh -> %s %s (account=%s account_id=%s)", reqID, outReq.Method, outReq.URL.String(), acc.ID, acc.AccountID)
					acc.mu.Unlock()
				}
				resp, err = h.roundTripWithFirstByteDeadline(outReq)
				captureCodexResponseState(acc, resp, reqID)
				if err != nil {
					if provider.Type() == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
						h.writeClaudeTrace(reqID, "pool", userID, originID, acc, in, rawIncomingBody, outReq, bodyBytes, resp, translateDir, nil, err.Error())
					}
					acc.mu.Lock()
					acc.Penalty += 0.2
					acc.mu.Unlock()
					return nil, nil, false, err
				}

				if h.cfg.debug.Load() && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
					errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
					decompressed := bodyForInspection(nil, errBody)
					log.Printf("[%s] after refresh retry got %d, body: %s", reqID, resp.StatusCode, safeText(decompressed))

					resp.Body = io.NopCloser(bytes.NewReader(errBody))
				}

			} else {
				errStr := err.Error()
				if isRateLimitError(err) {
					h.applyRateLimit(acc, nil)
				} else if isPermanentRefreshTokenError(err) {
					if retireAfterRefreshFail(acc, err, time.Now()) {
						persistDeadAccount(acc, "refresh token revoked/invalid")
					}
					refreshFailed = true
				} else if !strings.Contains(errStr, "rate limited") {
					refreshFailed = true
				}
				if h.cfg.debug.Load() {
					log.Printf("[%s] refresh failed for %s: %v (refreshFailed=%v)", reqID, acc.ID, err, refreshFailed)
				}
			}
		} else {
			refreshFailed = true
		}
	}

	if provider.Type() == AccountTypeCodex && isCodexRealtimeCallCreatePath(in.URL.Path) && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if callID := codexRealtimeCallIDFromLocation(resp.Header.Get("Location")); callID != "" {
			h.pool.pin(codexRealtimeCallPinKey(callID), acc.ID)
			// OpenAI currently returns 201 with text/plain even though the body is
			// an SDP answer. Normalize the public contract for Codex clients that
			// require the documented signaling shape.
			resp.StatusCode = http.StatusOK
			resp.Status = "200 OK"
			resp.Header.Set("Content-Type", "application/sdp")
			if h.cfg.debug.Load() {
				log.Printf("[%s] pinned realtime call %s to account %s", reqID, callID, acc.ID)
			}
		}
	}

	// Tee a bounded response sample only when later code needs it. Pass-through SSE
	// stays on the direct upstream->client path so first tokens are not delayed by
	// accounting-only parsing or sampling.
	sampleLimit := int64(16 * 1024)
	if h.cfg.logBodies && h.cfg.bodyLogLimit > 0 {
		sampleLimit = h.cfg.bodyLogLimit
	}
	sampleLimit = h.claudeTraceSampleLimit(sampleLimit)
	var buf *bytes.Buffer
	if provider.Type() == AccountTypeClaude && h.cfg.claudeTraceEnabled() {
		buf = &bytes.Buffer{}
		h.attachClaudeTrace(reqID, "pool", userID, originID, acc, in, rawIncomingBody, outReq, bodyBytes, resp, translateDir, buf, sampleLimit)
	} else if shouldSampleResponseBodyForRequest(provider, acc, in.URL.Path, resp, translateDir, conversationID, h.cfg.logBodies) {
		buf = &bytes.Buffer{}
		resp.Body = struct {
			io.Reader
			io.Closer
		}{
			Reader: io.TeeReader(resp.Body, &limitedWriter{w: buf, n: sampleLimit}),
			Closer: resp.Body,
		}
	}
	return resp, buf, refreshFailed, nil
}

func applyStreamingResponseHeaders(header http.Header) {
	header.Set("X-Accel-Buffering", "no")
	header.Set("Connection", "keep-alive")
	cacheControl := header.Get("Cache-Control")
	if cacheControl == "" {
		header.Set("Cache-Control", "no-cache, no-transform")
	} else if !strings.Contains(strings.ToLower(cacheControl), "no-transform") {
		header.Set("Cache-Control", cacheControl+", no-transform")
	}
}

func shouldSampleResponseBodyForRequest(provider Provider, acc *Account, path string, resp *http.Response, translateDir TranslateDirection, conversationID string, logBodies bool) bool {
	if provider == nil || resp == nil {
		return true
	}
	if logBodies || translateDir != TranslateNone {
		return true
	}
	if !provider.DetectsSSE(path, resp.Header.Get("Content-Type")) {
		return true
	}
	if provider.Type() == AccountTypeCodex {
		if acc != nil && !acc.CyberAccess {
			return true
		}
		return conversationID == ""
	}
	return false
}
