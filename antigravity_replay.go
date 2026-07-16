package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	antigravityReplayTTL        = time.Hour
	antigravityReplayMaxEntries = 10240
	antigravityReplayEvictBatch = 128
)

type antigravityReplayScope struct {
	Model   string
	Session string
}

func (s antigravityReplayScope) valid() bool {
	return strings.TrimSpace(s.Model) != "" && strings.TrimSpace(s.Session) != ""
}

type antigravityReplayPart struct {
	ContentIndex int
	PartIndex    int
	Signature    string
	Part         map[string]any
}

type antigravityReplayEntry struct {
	Parts     []antigravityReplayPart
	Timestamp time.Time
}

type antigravityReplayCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	entries    map[string]antigravityReplayEntry
	now        func() time.Time
}

func newAntigravityReplayCache(ttl time.Duration, maxEntries int) *antigravityReplayCache {
	return &antigravityReplayCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		entries:    make(map[string]antigravityReplayEntry),
		now:        time.Now,
	}
}

var antigravityNativeReplay = newAntigravityReplayCache(antigravityReplayTTL, antigravityReplayMaxEntries)

func antigravityReplayScopeFromBody(body []byte) antigravityReplayScope {
	var root map[string]any
	if json.Unmarshal(body, &root) != nil {
		return antigravityReplayScope{}
	}
	request, _ := root["request"].(map[string]any)
	model := strings.TrimSpace(stringValue(root["model"]))
	if model == "" {
		model = strings.TrimSpace(stringValue(request["model"]))
	}
	session := firstAntigravityString(root, "sessionId", "session_id")
	if session == "" {
		session = firstAntigravityString(request, "sessionId", "session_id")
	}
	if session == "" {
		session = antigravityStableReplaySession(request)
	}
	if model == "" || session == "" {
		return antigravityReplayScope{}
	}
	return antigravityReplayScope{Model: model, Session: "session:" + session}
}

func antigravityStableReplaySession(request map[string]any) string {
	for _, rawContent := range anySlice(request["contents"]) {
		content, _ := rawContent.(map[string]any)
		if !strings.EqualFold(stringValue(content["role"]), "user") {
			continue
		}
		for _, rawPart := range anySlice(content["parts"]) {
			part, _ := rawPart.(map[string]any)
			if text := strings.TrimSpace(stringValue(part["text"])); text != "" {
				sum := sha256.Sum256([]byte(text))
				return hex.EncodeToString(sum[:16])
			}
		}
	}
	return ""
}

// antigravityApplyNativeReplay restores native Gemini signatures and function
// call parts before a translated request is sent upstream.
func antigravityApplyNativeReplay(body []byte) ([]byte, antigravityReplayScope, bool) {
	scope := antigravityReplayScopeFromBody(body)
	updated, changed := antigravityNativeReplay.apply(scope, body)
	return updated, scope, changed
}

// antigravityCaptureNativeReplay records signed upstream parts. It accepts one
// SSE JSON payload or a collected response body.
func antigravityCaptureNativeReplay(scope antigravityReplayScope, requestBody, responseBody []byte) bool {
	return antigravityNativeReplay.capture(scope, requestBody, responseBody)
}

// antigravityClearNativeReplayOnError discards stale native state only when
// Gemini rejects a signature.
func antigravityClearNativeReplayOnError(scope antigravityReplayScope, status int, body []byte) bool {
	return antigravityNativeReplay.clearForInvalidSignature(scope, status, body)
}

func (c *antigravityReplayCache) key(scope antigravityReplayScope) string {
	if !scope.valid() {
		return ""
	}
	return strings.TrimSpace(scope.Model) + "\x00" + strings.TrimSpace(scope.Session)
}

func (c *antigravityReplayCache) get(scope antigravityReplayScope, now time.Time) (antigravityReplayEntry, bool) {
	key := c.key(scope)
	if key == "" {
		return antigravityReplayEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return antigravityReplayEntry{}, false
	}
	if now.Sub(entry.Timestamp) > c.ttl {
		delete(c.entries, key)
		return antigravityReplayEntry{}, false
	}
	entry.Timestamp = now
	c.entries[key] = entry
	return cloneAntigravityReplayEntry(entry), true
}

func (c *antigravityReplayCache) capture(scope antigravityReplayScope, requestBody, responseBody []byte) bool {
	key := c.key(scope)
	if key == "" {
		return false
	}
	var requestRoot map[string]any
	if json.Unmarshal(requestBody, &requestRoot) != nil {
		return false
	}
	request, _ := requestRoot["request"].(map[string]any)
	contentIndex, partIndex := antigravityReplayPendingPosition(request)

	var responseRoot map[string]any
	if json.Unmarshal(responseBody, &responseRoot) != nil {
		return false
	}
	response, _ := responseRoot["response"].(map[string]any)
	if response == nil {
		response = responseRoot
	}
	candidates := anySlice(response["candidates"])
	if len(candidates) == 0 {
		return false
	}
	candidate, _ := candidates[0].(map[string]any)
	content, _ := candidate["content"].(map[string]any)
	var captured []antigravityReplayPart
	for offset, rawPart := range anySlice(content["parts"]) {
		part, _ := rawPart.(map[string]any)
		if part == nil {
			continue
		}
		signature := antigravityNativeThoughtSignature(part)
		_, hasCall := part["functionCall"].(map[string]any)
		if signature == "" && !hasCall {
			continue
		}
		cloned := cloneAntigravityReplayMap(part)
		if signature != "" {
			cloned["thoughtSignature"] = signature
		}
		captured = append(captured, antigravityReplayPart{ContentIndex: contentIndex, PartIndex: partIndex + offset, Signature: signature, Part: cloned})
	}
	if len(captured) == 0 {
		return false
	}

	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[key]
	entry.Timestamp = now
	for _, replay := range captured {
		entry.Parts = appendOrReplaceAntigravityReplayPart(entry.Parts, replay)
	}
	c.entries[key] = entry
	c.purgeAndEvictLocked(now)
	return true
}

func antigravityReplayPendingPosition(request map[string]any) (int, int) {
	contents := anySlice(request["contents"])
	if len(contents) == 0 {
		return 0, 0
	}
	last, _ := contents[len(contents)-1].(map[string]any)
	if strings.EqualFold(stringValue(last["role"]), "model") {
		return len(contents) - 1, len(anySlice(last["parts"]))
	}
	return len(contents), 0
}

func antigravityNativeThoughtSignature(part map[string]any) string {
	if value := firstAntigravityString(part, "thoughtSignature", "thought_signature"); value != "" {
		return value
	}
	extra, _ := part["extra_content"].(map[string]any)
	google, _ := extra["google"].(map[string]any)
	return firstAntigravityString(google, "thought_signature", "thoughtSignature")
}

func appendOrReplaceAntigravityReplayPart(parts []antigravityReplayPart, candidate antigravityReplayPart) []antigravityReplayPart {
	candidateID := antigravityReplayFunctionCallID(candidate.Part)
	for i := range parts {
		partID := antigravityReplayFunctionCallID(parts[i].Part)
		if candidateID != "" && candidateID == partID {
			parts[i] = candidate
			return parts
		}
		if candidateID == "" && partID == "" && candidate.Signature != "" && candidate.Signature == parts[i].Signature {
			parts[i] = candidate
			return parts
		}
	}
	return append(parts, candidate)
}

func antigravityReplayFunctionCallID(part map[string]any) string {
	call, _ := part["functionCall"].(map[string]any)
	return strings.TrimSpace(stringValue(call["id"]))
}

func (c *antigravityReplayCache) apply(scope antigravityReplayScope, body []byte) ([]byte, bool) {
	entry, ok := c.get(scope, c.now())
	if !ok {
		return body, false
	}
	var root map[string]any
	if json.Unmarshal(body, &root) != nil {
		return body, false
	}
	request, _ := root["request"].(map[string]any)
	contents := anySlice(request["contents"])
	changed := false
	for _, replay := range entry.Parts {
		callID := antigravityReplayFunctionCallID(replay.Part)
		cachedCall, hasCall := replay.Part["functionCall"].(map[string]any)
		if callID != "" {
			if ci, pi, found := antigravityFindFunctionCall(contents, callID); found {
				content := contents[ci].(map[string]any)
				parts := anySlice(content["parts"])
				part, _ := parts[pi].(map[string]any)
				if replay.Signature != "" && antigravityNativeThoughtSignature(part) != replay.Signature {
					part["thoughtSignature"] = replay.Signature
					changed = true
				}
				continue
			}
			if responseIndex, found := antigravityFindFunctionResponseContent(contents, callID); found {
				modelContent := map[string]any{"role": "model", "parts": []any{cloneAntigravityReplayMap(replay.Part)}}
				contents = append(contents, nil)
				copy(contents[responseIndex+1:], contents[responseIndex:])
				contents[responseIndex] = modelContent
				changed = true
			}
			continue
		}
		if hasCall && replay.ContentIndex >= 0 && replay.ContentIndex < len(contents) {
			content, _ := contents[replay.ContentIndex].(map[string]any)
			parts := anySlice(content["parts"])
			if replay.PartIndex >= 0 && replay.PartIndex < len(parts) {
				part, _ := parts[replay.PartIndex].(map[string]any)
				requestCall, _ := part["functionCall"].(map[string]any)
				if requestCall != nil && stringValue(requestCall["name"]) == stringValue(cachedCall["name"]) {
					if replay.Signature != "" && antigravityNativeThoughtSignature(part) != replay.Signature {
						part["thoughtSignature"] = replay.Signature
						changed = true
					}
					continue
				}
			}
		}
		if replay.Signature != "" && replay.ContentIndex >= 0 && replay.ContentIndex < len(contents) {
			content, _ := contents[replay.ContentIndex].(map[string]any)
			parts := anySlice(content["parts"])
			if replay.PartIndex >= 0 && replay.PartIndex < len(parts) {
				part, _ := parts[replay.PartIndex].(map[string]any)
				if antigravityNativeThoughtSignature(part) == "" {
					part["thoughtSignature"] = replay.Signature
					changed = true
				}
			}
		}
	}
	if !changed {
		return body, false
	}
	request["contents"] = contents
	updated, err := json.Marshal(root)
	if err != nil {
		return body, false
	}
	return updated, true
}

func antigravityFindFunctionCall(contents []any, callID string) (int, int, bool) {
	for ci, rawContent := range contents {
		content, _ := rawContent.(map[string]any)
		for pi, rawPart := range anySlice(content["parts"]) {
			part, _ := rawPart.(map[string]any)
			if antigravityReplayFunctionCallID(part) == callID {
				return ci, pi, true
			}
		}
	}
	return -1, -1, false
}

func antigravityFindFunctionResponseContent(contents []any, callID string) (int, bool) {
	for ci, rawContent := range contents {
		content, _ := rawContent.(map[string]any)
		for _, rawPart := range anySlice(content["parts"]) {
			part, _ := rawPart.(map[string]any)
			response, _ := part["functionResponse"].(map[string]any)
			if strings.TrimSpace(stringValue(response["id"])) == callID {
				return ci, true
			}
		}
	}
	return -1, false
}

func (c *antigravityReplayCache) clearForInvalidSignature(scope antigravityReplayScope, status int, body []byte) bool {
	if status != http.StatusBadRequest {
		return false
	}
	lower := strings.ToLower(string(body))
	if !strings.Contains(lower, "thoughtsignature") && !strings.Contains(lower, "thought_signature") && !strings.Contains(lower, "signature") {
		return false
	}
	key := c.key(scope)
	if key == "" {
		return false
	}
	c.mu.Lock()
	_, existed := c.entries[key]
	delete(c.entries, key)
	c.mu.Unlock()
	return existed
}

func (c *antigravityReplayCache) purgeAndEvictLocked(now time.Time) {
	for key, entry := range c.entries {
		if now.Sub(entry.Timestamp) > c.ttl {
			delete(c.entries, key)
		}
	}
	if c.maxEntries <= 0 || len(c.entries) <= c.maxEntries {
		return
	}
	type candidate struct {
		key       string
		timestamp time.Time
	}
	candidates := make([]candidate, 0, len(c.entries))
	for key, entry := range c.entries {
		candidates = append(candidates, candidate{key: key, timestamp: entry.Timestamp})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].timestamp.Before(candidates[j].timestamp) })
	count := antigravityReplayEvictBatch
	if count > len(candidates) {
		count = len(candidates)
	}
	for i := 0; i < count; i++ {
		delete(c.entries, candidates[i].key)
	}
}

func cloneAntigravityReplayEntry(entry antigravityReplayEntry) antigravityReplayEntry {
	result := antigravityReplayEntry{Timestamp: entry.Timestamp, Parts: make([]antigravityReplayPart, 0, len(entry.Parts))}
	for _, part := range entry.Parts {
		part.Part = cloneAntigravityReplayMap(part.Part)
		result.Parts = append(result.Parts, part)
	}
	return result
}

func cloneAntigravityReplayMap(input map[string]any) map[string]any {
	raw, _ := json.Marshal(input)
	var result map[string]any
	_ = json.Unmarshal(raw, &result)
	return result
}
