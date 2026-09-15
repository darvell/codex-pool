package main

import (
	"encoding/json"
	"strings"
	"sync"
)

// codexEffortRank orders Codex reasoning efforts from cheapest to most
// expensive. Reasoning tokens bill as output, so an uncapped xhigh client
// burns subscription quota far faster than its request count suggests.
// Unranked values (unknown future efforts) are left untouched.
var codexEffortRank = map[string]int{
	"none":    0,
	"minimal": 1,
	"low":     2,
	"medium":  3,
	"high":    4,
	"xhigh":   5,
	"max":     6,
}

// effortCap clamps Codex reasoning effort for specific principals and
// origins. Matching is by pool user ID (with or without the "-c-" client
// suffix) and by raw client IP, so a single noisy machine can be capped
// without affecting the rest of that principal's clients.
type effortCap struct {
	mu      sync.RWMutex
	users   map[string]string
	origins map[string]string
}

func newEffortCap(users, origins map[string]string) *effortCap {
	c := &effortCap{}
	c.reload(users, origins)
	return c
}

func (c *effortCap) reload(users, origins map[string]string) {
	normalized := func(cfg map[string]string) map[string]string {
		out := make(map[string]string, len(cfg))
		for key, effort := range cfg {
			key = strings.ToLower(strings.TrimSpace(key))
			effort = strings.ToLower(strings.TrimSpace(effort))
			if key == "" || effort == "" {
				continue
			}
			if _, ok := codexEffortRank[effort]; !ok {
				continue
			}
			out[key] = effort
		}
		return out
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.users = normalized(users)
	c.origins = normalized(origins)
}

func (c *effortCap) configured() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.users) > 0 || len(c.origins) > 0
}

// limitFor returns the strictest configured cap for this identity, or "" when
// the request is unrestricted. A principal-wide rule and a per-client or
// per-IP rule can both match; the cheaper effort wins.
func (c *effortCap) limitFor(userID, clientIP string) string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.users) == 0 && len(c.origins) == 0 {
		return ""
	}

	best := ""
	consider := func(candidate string) {
		if candidate == "" {
			return
		}
		if best == "" || codexEffortRank[candidate] < codexEffortRank[best] {
			best = candidate
		}
	}

	if userID = strings.ToLower(strings.TrimSpace(userID)); userID != "" {
		consider(c.users[userID])
		// A credential-scoped ID ("principal-c-client") must also honor a rule
		// written against the bare principal.
		if principal, _ := splitClientIdentity(userID); principal != userID {
			consider(c.users[strings.ToLower(principal)])
		}
	}
	if clientIP = strings.ToLower(strings.TrimSpace(clientIP)); clientIP != "" {
		consider(c.origins[clientIP])
	}
	return best
}

// capCodexEffortValue clamps obj["reasoning"]["effort"] to limit. It reports
// the effort that was replaced so callers can log the override, and whether
// the object changed.
func capCodexEffortValue(obj map[string]any, limit string) (previous string, changed bool) {
	if obj == nil || limit == "" {
		return "", false
	}
	ceiling, ok := codexEffortRank[limit]
	if !ok {
		return "", false
	}
	reasoning, _ := obj["reasoning"].(map[string]any)
	if reasoning == nil {
		return "", false
	}
	current, _ := reasoning["effort"].(string)
	current = strings.ToLower(strings.TrimSpace(current))
	if current == "" {
		return "", false
	}
	rank, known := codexEffortRank[current]
	if !known || rank <= ceiling {
		return "", false
	}
	reasoning["effort"] = limit
	obj["reasoning"] = reasoning
	return current, true
}

// capCodexEffortInBody clamps reasoning effort in a flat Responses body or a
// nested websocket "response.create" envelope. The body is returned unchanged
// when no cap applies, so non-matching traffic pays no re-encoding cost.
func capCodexEffortInBody(body []byte, limit string) (out []byte, previous string, changed bool) {
	if len(body) == 0 || limit == "" {
		return body, "", false
	}
	// Avoid decoding large agent transcripts that carry no effort field.
	if !strings.Contains(string(body), `"effort"`) {
		return body, "", false
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body, "", false
	}

	previous, changed = capCodexEffortValue(obj, limit)
	if response, ok := obj["response"].(map[string]any); ok {
		nestedPrev, nestedChanged := capCodexEffortValue(response, limit)
		if nestedChanged {
			obj["response"] = response
			changed = true
			if previous == "" {
				previous = nestedPrev
			}
		}
	}
	if !changed {
		return body, "", false
	}

	encoded, err := json.Marshal(obj)
	if err != nil {
		return body, "", false
	}
	return encoded, previous, true
}
