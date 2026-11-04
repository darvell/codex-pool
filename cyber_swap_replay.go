package main

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Response IDs are scoped to the connection that minted them. A newly dialed
// socket cannot honor previous_response_id, so a redial must rebuild the
// conversation from a full input transcript the pool has actually seen. The
// upstream response frames are mined for assistant tool calls and messages;
// those items accumulate per conversation so failover can forward them
// instead of the dead response ID.

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

// contextRedialPayload is the Codex Responses websocket redial rule.
// That path expands native context for the account that receives the frame,
// so pool replay history is not a substitute for previous_response_id:
// recorded output items, including encrypted reasoning, belong to the
// upstream that minted them.
//
// A frame with no previous_response_id is the client's own transcript and is
// forwarded unchanged. A frame that still carries the id is a cached delta
// unless it also carries a pool context envelope. Stripping the id and
// forwarding only that delta makes Codex reject a tool result with
// "No tool call found for function call output", or accept a lone user
// message while dropping the rest of the conversation. Those frames are
// refused. The caller writes previous_response_not_found so the client
// resends the full transcript without the id.
//
// A native-context tool result is the exception. Its function_call_output
// holds the encrypted envelope, which is meaningful on the new account only
// after expansion, and the id is dropped so the dead response is not named.
// A sibling tool result that does not carry the envelope, and whose call is
// not in the same input, is still a cached delta and the whole frame is refused.
func contextRedialPayload(request []byte) ([]byte, error) {
	if !hasPreviousResponseID(request) {
		return append([]byte(nil), request...), nil
	}
	items := extractInputItems(request)
	if !bytes.Contains(request, []byte(contextEnvelopePrefix)) || uncoveredNonContextOutput(items) {
		return nil, errPreviousResponseUnreplayable
	}
	out := setInputAndStripPrevID(request, items)
	if hasPreviousResponseID(out) {
		return nil, errPreviousResponseUnreplayable
	}
	return out, nil
}

// uncoveredNonContextOutput reports a tool result that is neither a native
// context envelope nor paired with a tool call in the same input. Replaying
// that item without previous_response_id is what Codex rejects as
// "No tool call found for function call output".
func uncoveredNonContextOutput(items []json.RawMessage) bool {
	contextIDs := map[string]struct{}{}
	for _, raw := range items {
		var item map[string]json.RawMessage
		if json.Unmarshal(raw, &item) != nil {
			continue
		}
		typ := rawStringValue(item["type"])
		switch {
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
	for _, raw := range items {
		if bytes.Contains(raw, []byte(contextEnvelopePrefix)) {
			continue
		}
		var item map[string]json.RawMessage
		if json.Unmarshal(raw, &item) != nil {
			continue
		}
		if !isCodexToolCallOutputItemType(rawStringValue(item["type"])) {
			continue
		}
		if _, ok := contextIDs[rawStringValue(item["call_id"])]; !ok {
			return true
		}
	}
	return false
}

// buildRedialPayload rebuilds a response.create for a freshly dialed socket
// on relays that do not expand native context. Codex Responses websockets use
// contextRedialPayload instead. A full transcript the pool has seen is
// forwarded without previous_response_id, because that id dies with the
// socket that minted it, even on the same account. A cached delta that cannot
// be rebuilt is refused. Stripping the id and forwarding only the delta would
// look like success while dropping the conversation. The caller writes
// previous_response_not_found so Pi resends the original full body. A request
// that never carried the id is unchanged.
func buildRedialPayload(request []byte, history []json.RawMessage) ([]byte, error) {
	if !hasPreviousResponseID(request) {
		return request, nil
	}
	if len(history) == 0 {
		return nil, errPreviousResponseUnreplayable
	}
	current := extractInputItems(request)
	full := buildReplaySequence(history, current, true)
	if len(full) == 0 {
		return nil, errPreviousResponseUnreplayable
	}
	hasOutput, coversAll := analyzeToolOutputCoverage(full)
	if hasOutput && !coversAll {
		return nil, errPreviousResponseUnreplayable
	}
	out := setInputAndStripPrevID(request, full)
	if hasPreviousResponseID(out) {
		return nil, errPreviousResponseUnreplayable
	}
	return out, nil
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
// bounded memory. truncated is true when any older item was dropped. A
// truncated transcript must not be replayed in place of previous_response_id.
func capHistory(items []json.RawMessage) ([]json.RawMessage, bool) {
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
	if start >= len(items) {
		return nil, len(items) > 0
	}
	return items[start:], start > 0
}
