package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"unicode/utf8"
)

const compactResponseLimit = 16 << 20

func readCompactResponse(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, compactResponseLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read compact response: %w", err)
	}
	if len(data) > compactResponseLimit {
		return nil, fmt.Errorf("compact response exceeds %d-byte limit", compactResponseLimit)
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("compact response contains invalid UTF-8")
	}

	var createdID string
	var terminal map[string]json.RawMessage
	var output []struct {
		index uint64
		item  json.RawMessage
	}
	var framer sseFramer
	for len(data) > 0 {
		event, advance, ok := framer.next(data)
		if !ok {
			// EOF can terminate the last SSE event without a blank line.
			event, advance = data, len(data)
		}
		data = data[advance:]
		_, payload := parseSSEEvent(event)
		payload = bytes.TrimSpace(payload)
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}

		var value map[string]json.RawMessage
		if err := json.Unmarshal(payload, &value); err != nil {
			return nil, fmt.Errorf("decode compact event: %w", err)
		}
		if value == nil {
			return nil, fmt.Errorf("compact event must be an object")
		}
		var eventType string
		_ = json.Unmarshal(value["type"], &eventType)
		switch eventType {
		case "response.created":
			var response struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(value["response"], &response) == nil && response.ID != "" {
				createdID = response.ID
			}
		case "response.output_item.done":
			item := bytes.TrimSpace(value["item"])
			if len(item) == 0 || item[0] != '{' {
				continue
			}
			index := uint64(len(output))
			if err := json.Unmarshal(value["output_index"], &index); err != nil {
				index = uint64(len(output))
			}
			output = append(output, struct {
				index uint64
				item  json.RawMessage
			}{index: index, item: item})
		case "response.completed", "response.failed", "response.incomplete":
			terminal = nil
			if err := json.Unmarshal(value["response"], &terminal); err != nil || terminal == nil {
				return nil, fmt.Errorf("compact terminal response must be an object")
			}
		}
	}
	if terminal == nil {
		return nil, fmt.Errorf("compact stream ended without a terminal response")
	}

	result := map[string]any{
		"object": "response.compact",
		"id":     nil,
		"status": "completed",
	}
	if id, ok := terminal["id"]; ok {
		result["id"] = id
	} else if createdID != "" {
		result["id"] = createdID
	}
	if status, ok := terminal["status"]; ok {
		result["status"] = status
	}

	// Done items are authoritative even when the terminal response omits them.
	if len(output) > 0 {
		sort.SliceStable(output, func(i, j int) bool { return output[i].index < output[j].index })
		items := make([]json.RawMessage, len(output))
		for i, entry := range output {
			items[i] = entry.item
		}
		result["output"] = items
	} else {
		var items []json.RawMessage
		if json.Unmarshal(terminal["output"], &items) == nil && len(items) > 0 {
			result["output"] = items
		}
	}
	for _, key := range []string{"usage", "error"} {
		if value, ok := terminal[key]; ok && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			result[key] = value
		}
	}
	return json.Marshal(result)
}
