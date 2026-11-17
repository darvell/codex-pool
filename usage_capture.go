package main

import (
	"bytes"
	"encoding/json"
)

func (h *proxyHandler) updateUsageFromBody(a *Account, sample []byte, userID, originID string) {
	if a == nil || len(sample) == 0 {
		return
	}
	lines := bytes.Split(sample, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			line = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		}
		if bytes.Equal(line, []byte("[DONE]")) {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal(line, &obj); err != nil {
			continue
		}

		if objType, _ := obj["type"].(string); objType == "token_count" {
			ru := parseTokenCountEvent(obj)
			if ru != nil {
				ru.AccountID = a.ID
				ru.UserID = userID
				ru.OriginID = originID
				ru.AccountType = a.Type
				a.mu.Lock()
				ru.PlanType = a.PlanType
				a.mu.Unlock()
				h.recordUsage(a, *ru)
			}

			if rl, ok := obj["rate_limits"].(map[string]any); ok {
				a.applyRateLimitsFromTokenCount(rl)
			}
			continue
		}

		// Legacy: rate_limit at top level
		if rl, ok := obj["rate_limit"].(map[string]any); ok {
			a.applyRateLimitObject(rl)
		}

		// Legacy: response object with usage
		if resp, ok := obj["response"].(map[string]any); ok {
			if rl, ok := resp["rate_limit"].(map[string]any); ok {
				a.applyRateLimitObject(rl)
			}
			if ru := parseRequestUsage(resp); ru != nil {
				ru.AccountID = a.ID
				ru.UserID = userID
				ru.OriginID = originID
				ru.AccountType = a.Type
				a.mu.Lock()
				ru.PlanType = a.PlanType
				a.mu.Unlock()
				h.recordUsage(a, *ru)
			}
		}

		// Legacy: direct usage object
		if ru := parseRequestUsage(obj); ru != nil {
			ru.AccountID = a.ID
			ru.UserID = userID
			ru.OriginID = originID
			ru.AccountType = a.Type
			a.mu.Lock()
			ru.PlanType = a.PlanType
			a.mu.Unlock()
			h.recordUsage(a, *ru)
		}
	}
}
