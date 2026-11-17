package main

import (
	"io"
	"log"
	"net/http"
	"strings"
)

func extractConversationIDFromHeaders(headers http.Header) string {
	for _, key := range []string{
		"session_id",
		"Session_id",
		"Session-Id",
		"conversation_id",
		"Conversation_id",
		"prompt_cache_key",
		"x-codex-conversation-id",
	} {
		if value := strings.TrimSpace(headers.Get(key)); value != "" {
			return value
		}
		for actualKey, values := range headers {
			if !strings.EqualFold(actualKey, key) {
				continue
			}
			for _, value := range values {
				if value = strings.TrimSpace(value); value != "" {
					return value
				}
			}
		}
	}
	return ""
}

func (h *proxyHandler) pinConversationToCyberAccess(conversationID string, accountType AccountType, requiredPlan, clientIP, currentAccountID, reqID string) bool {
	if conversationID == "" || accountType != AccountTypeCodex {
		return false
	}
	exclude := map[string]bool{}
	if currentAccountID != "" {
		exclude[currentAccountID] = true
	}
	acc := h.pool.candidateWithCyberAccess(exclude, accountType, requiredPlan, clientIP)
	if acc == nil {
		if h.cfg.debug.Load() {
			log.Printf("[%s] cyber_policy seen for conversation %s, but no cyber_access account is available", reqID, conversationID)
		}
		return false
	}
	h.pool.pin(conversationID, acc.ID)
	if h.cfg.debug.Load() {
		log.Printf("[%s] pinned conversation %s to cyber_access account %s after cyber_policy", reqID, conversationID, acc.ID)
	}
	return true
}

func (h *proxyHandler) shouldRetryBufferedSSEForCyberPolicy(cyberPinned bool, attempt, attempts int, acc *Account, reqID, label string) bool {
	if !cyberPinned || attempt >= attempts || acc == nil || acc.CyberAccess {
		return false
	}
	log.Printf("[%s] buffered %s SSE saw cyber_policy on account %s; retrying on cyber_access account", reqID, label, acc.ID)
	if h.metrics != nil {
		h.metrics.incCyberPolicy(acc.ID, "retry_buffered")
	}
	return true
}

func (h *proxyHandler) wrapBufferedSSEWithCyberDetector(under io.Writer, accountType AccountType, acc *Account, conversationID, requiredPlan, originIP, reqID string, cyberPinned *bool) io.Writer {
	if accountType != AccountTypeCodex || acc == nil || acc.CyberAccess {
		return under
	}
	return &sseInterceptWriter{
		w: under,
		onEvent: func(eventData []byte) (bool, bool) {
			if !isCyberPolicyError(eventData) {
				return false, false
			}
			if h.metrics != nil {
				h.metrics.incCyberPolicy(acc.ID, "suppressed_buffered")
			}
			if h.pinConversationToCyberAccess(conversationID, accountType, requiredPlan, originIP, acc.ID, reqID) {
				if cyberPinned != nil {
					*cyberPinned = true
				}
			}
			return true, true
		},
	}
}
