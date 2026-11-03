package main

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Response IDs are scoped to the connection that minted them. A newly dialed
// socket cannot honor previous_response_id, so a redial must rebuild the
// conversation from a full input transcript the pool has actually seen. This
// file ports sub2api's tool-continuation replay: the upstream response frames
// are mined for the assistant's tool calls and messages, and those items are
// accumulated per conversation so a failover can forward them instead of the
// dead response id.

func isCodexToolCallContextItemType(typ string) bool {
	switch strings.TrimSpace(typ) {
	case "tool_call", "function_call", "local_shell_call", "tool_search_call", "custom_tool_call", "mcp_tool_call":
		return true
	default:
		return false
	}
}

func isCodexToolCallOutputItemType(typ string) bool {
	switch strings.TrimSpace(typ) {
	case "function_call_output", "tool_search_output", "custom_tool_call_output", "mcp_tool_call_output":
		return true
	default:
		return false
	}
}

// codexToolReplayCollector mines assistant output items from upstream events.
// items holds only tool-call context items; all holds every output item so a
// failover can replay assistant messages alongside the tool calls.
type codexToolReplayCollector struct {
	items   []json.RawMessage
	all     []json.RawMessage
	seen    map[string]struct{}
	allSeen map[string]struct{}
}

func (c *codexToolReplayCollector) AddEvent(eventType string, message []byte) {
	switch strings.TrimSpace(eventType) {
	case "response.output_item.done":
		c.addItem(rawJSONField(message, "item"))
	case "response.completed", "response.done":
		for _, item := range responseOutputItems(message) {
			c.addItem(item)
		}
	}
}

func (c *codexToolReplayCollector) addItem(item json.RawMessage) {
	if len(item) == 0 {
		return
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(item, &obj) != nil {
		return
	}
	typ := rawStringValue(obj["type"])
	if typ == "" {
		return
	}
	key := rawStringValue(obj["id"])
	if key == "" {
		key = rawStringValue(obj["call_id"])
	}
	if key == "" {
		key = string(bytes.TrimSpace(item))
	}
	if isCodexToolCallContextItemType(typ) {
		if c.seen == nil {
			c.seen = map[string]struct{}{}
		}
		if _, ok := c.seen[key]; !ok {
			c.seen[key] = struct{}{}
			c.items = append(c.items, append(json.RawMessage(nil), item...))
		}
	}
	if c.allSeen == nil {
		c.allSeen = map[string]struct{}{}
	}
	if _, ok := c.allSeen[key]; !ok {
		c.allSeen[key] = struct{}{}
		c.all = append(c.all, append(json.RawMessage(nil), item...))
	}
}

func (c *codexToolReplayCollector) Items() []json.RawMessage {
	return c.items
}

func (c *codexToolReplayCollector) AllItems() []json.RawMessage {
	return c.all
}

func rawJSONField(message []byte, name string) json.RawMessage {
	var obj map[string]json.RawMessage
	if json.Unmarshal(message, &obj) != nil {
		return nil
	}
	return obj[name]
}

func responseOutputItems(message []byte) []json.RawMessage {
	response := rawJSONField(message, "response")
	if len(response) == 0 {
		return nil
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(response, &obj) != nil {
		return nil
	}
	output := obj["output"]
	var items []json.RawMessage
	if json.Unmarshal(output, &items) == nil {
		return items
	}
	if len(bytes.TrimSpace(output)) == 0 {
		return nil
	}
	return []json.RawMessage{output}
}

func rawStringValue(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

func codexEventType(data []byte) string {
	var event struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &event) != nil {
		return ""
	}
	return strings.TrimSpace(event.Type)
}

// extractInputItems reads the input sequence from a response.create payload,
// covering both the flat Responses shape and the nested Codex response.create
// envelope. The returned items share no memory with body.
func extractInputItems(body []byte) []json.RawMessage {
	var obj map[string]json.RawMessage
	if json.Unmarshal(body, &obj) != nil {
		return nil
	}
	input := obj["input"]
	if len(input) == 0 {
		if nested := obj["response"]; len(nested) > 0 {
			var inner map[string]json.RawMessage
			if json.Unmarshal(nested, &inner) == nil {
				input = inner["input"]
			}
		}
	}
	trimmed := bytes.TrimSpace(input)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var items []json.RawMessage
	if json.Unmarshal(input, &items) == nil {
		return items
	}
	return []json.RawMessage{append(json.RawMessage(nil), input...)}
}

func combineInputItems(history, delta []json.RawMessage) []json.RawMessage {
	if len(delta) == 0 {
		return history
	}
	out := make([]json.RawMessage, 0, len(history)+len(delta))
	out = append(out, history...)
	out = append(out, delta...)
	return out
}

func itemsHavePrefix(items, prefix []json.RawMessage) bool {
	if len(prefix) == 0 {
		return true
	}
	if len(items) < len(prefix) {
		return false
	}
	for i := range prefix {
		if !bytes.Equal(bytes.TrimSpace(prefix[i]), bytes.TrimSpace(items[i])) {
			return false
		}
	}
	return true
}

func hasPreviousResponseID(body []byte) bool {
	return bytes.Contains(body, []byte(`"previous_response_id"`))
}

// buildReplaySequence appends the current turn's input to the accumulated
// history. A client that resends the full transcript already contains the
// history as a prefix, so its payload is used unchanged to avoid duplication.
func buildReplaySequence(history, current []json.RawMessage, hasPrevID bool) []json.RawMessage {
	if !hasPrevID {
		return current
	}
	if itemsHavePrefix(current, history) {
		return current
	}
	return combineInputItems(history, current)
}

// analyzeToolOutputCoverage reports whether every tool-call output's call_id
// has a matching tool-call context item or item_reference in the sequence.
// Without that coverage the upstream rejects a previous_response_id-less
// replay with "No tool call found for function call output".
func analyzeToolOutputCoverage(items []json.RawMessage) (hasOutput, coversAll bool) {
	outputCallIDs := map[string]struct{}{}
	contextIDs := map[string]struct{}{}
	for _, raw := range items {
		var item map[string]json.RawMessage
		if json.Unmarshal(raw, &item) != nil {
			continue
		}
		typ := rawStringValue(item["type"])
		switch {
		case isCodexToolCallOutputItemType(typ):
			hasOutput = true
			callID := rawStringValue(item["call_id"])
			if callID == "" {
				return hasOutput, false
			}
			outputCallIDs[callID] = struct{}{}
		case isCodexToolCallContextItemType(typ):
			if callID := rawStringValue(item["call_id"]); callID != "" {
				contextIDs[callID] = struct{}{}
			}
		case typ == "item_reference":
			if id := rawStringValue(item["id"]); id != "" {
				contextIDs[id] = struct{}{}
			}
		}
	}
	if !hasOutput {
		return false, false
	}
	for callID := range outputCallIDs {
		if _, ok := contextIDs[callID]; !ok {
			return true, false
		}
	}
	return true, true
}

// buildRedialPayload rebuilds a response.create for a freshly dialed socket.
// With accumulated history it forwards the full input transcript and drops the
// dead response id; the prior turn's context survives the redial. Without
// history, or when the transcript cannot cover a tool-call output, it falls
// back to stripping the id so the delta request at least reaches upstream.
func buildRedialPayload(request []byte, history []json.RawMessage) []byte {
	if len(history) == 0 {
		return stripPreviousResponseID(request)
	}
	current := extractInputItems(request)
	full := buildReplaySequence(history, current, hasPreviousResponseID(request))
	if len(full) == 0 {
		return stripPreviousResponseID(request)
	}
	hasOutput, coversAll := analyzeToolOutputCoverage(full)
	if hasOutput && !coversAll {
		return stripPreviousResponseID(request)
	}
	return setInputAndStripPrevID(request, full)
}

func setInputAndStripPrevID(body []byte, full []json.RawMessage) []byte {
	var obj map[string]json.RawMessage
	if json.Unmarshal(body, &obj) != nil {
		return body
	}
	inputRaw, err := json.Marshal(full)
	if err != nil {
		return body
	}
	if nested, ok := obj["response"]; ok {
		var inner map[string]json.RawMessage
		if json.Unmarshal(nested, &inner) == nil {
			inner["input"] = inputRaw
			delete(inner, "previous_response_id")
			if rebuilt, err := json.Marshal(inner); err == nil {
				obj["response"] = rebuilt
				delete(obj, "previous_response_id")
				delete(obj, "input")
				if out, err := json.Marshal(obj); err == nil {
					return out
				}
			}
		}
	}
	obj["input"] = inputRaw
	delete(obj, "previous_response_id")
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

const (
	codexReplayHistoryMaxItems = 256
	codexReplayHistoryMaxBytes = 8 << 20
)

// capHistory keeps the most recent tail of the accumulated transcript within
// bounded memory. Older context beyond the cap is dropped rather than letting
// a long session grow without limit.
func capHistory(items []json.RawMessage) []json.RawMessage {
	total := 0
	start := len(items)
	for i := len(items) - 1; i >= 0; i-- {
		if len(items)-i > codexReplayHistoryMaxItems {
			break
		}
		total += len(items[i])
		if total > codexReplayHistoryMaxBytes {
			break
		}
		start = i
	}
	return items[start:]
}
