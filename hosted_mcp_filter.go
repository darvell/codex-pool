package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const hostedMCPToolType = "mcp"

var hostedMCPItemTypes = map[string]struct{}{
	"mcp_list_tools":        {},
	"mcp_call":              {},
	"mcp_approval_request":  {},
	"mcp_approval_response": {},
}

func isHostedMCPItemType(value any) bool {
	typ, ok := value.(string)
	if !ok {
		return false
	}
	_, ok = hostedMCPItemTypes[strings.TrimSpace(typ)]
	return ok
}

// stripHostedMCPFromResponsesRequest removes only OpenAI-hosted MCP tools and
// MCP transcript items. Codex's local MCP tools use function/namespace tool
// definitions, so exact type matching preserves them along with web_search and
// tool_search.
func stripHostedMCPFromResponsesRequest(request map[string]any) bool {
	changed := false
	if tools, ok := request["tools"].([]any); ok {
		kept := tools[:0]
		for _, raw := range tools {
			tool, _ := raw.(map[string]any)
			if typ, _ := tool["type"].(string); strings.TrimSpace(typ) == hostedMCPToolType {
				changed = true
				continue
			}
			kept = append(kept, raw)
		}
		request["tools"] = kept
	}

	if input, ok := request["input"].([]any); ok {
		kept := input[:0]
		for _, raw := range input {
			item, _ := raw.(map[string]any)
			if isHostedMCPItemType(item["type"]) {
				changed = true
				continue
			}
			kept = append(kept, raw)
		}
		request["input"] = kept
	}

	if choice, ok := request["tool_choice"].(map[string]any); ok {
		if typ, _ := choice["type"].(string); strings.TrimSpace(typ) == hostedMCPToolType {
			delete(request, "tool_choice")
			changed = true
		}
	} else if choice, ok := request["tool_choice"].(string); ok && strings.TrimSpace(choice) == hostedMCPToolType {
		delete(request, "tool_choice")
		changed = true
	}
	return changed
}

func filterHostedMCPRequestJSON(data []byte) ([]byte, bool, error) {
	var request map[string]any
	if err := json.Unmarshal(data, &request); err != nil {
		return data, false, nil
	}
	if !stripHostedMCPFromResponsesRequest(request) {
		return data, false, nil
	}
	filtered, err := json.Marshal(request)
	if err != nil {
		return nil, false, fmt.Errorf("encode hosted MCP-filtered request: %w", err)
	}
	return filtered, true, nil
}

func stripHostedMCPItems(items []any) ([]any, bool) {
	kept := make([]any, 0, len(items))
	changed := false
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		if isHostedMCPItemType(item["type"]) {
			changed = true
			continue
		}
		kept = append(kept, raw)
	}
	return kept, changed
}

// filterHostedMCPResponseJSON removes hosted MCP output items from either an
// SSE/WebSocket event envelope or a non-streaming Responses API response.
// It returns drop=true when the entire event represents an MCP item.
func filterHostedMCPResponseJSON(data []byte) (filtered []byte, drop bool, changed bool) {
	var event map[string]any
	if err := json.Unmarshal(data, &event); err != nil {
		return data, false, false
	}

	if eventType, _ := event["type"].(string); strings.HasPrefix(eventType, "response.mcp_") || isHostedMCPItemType(eventType) {
		return nil, true, true
	}
	if item, _ := event["item"].(map[string]any); item != nil && isHostedMCPItemType(item["type"]) {
		return nil, true, true
	}

	stripOutput := func(container map[string]any) {
		if output, ok := container["output"].([]any); ok {
			if kept, removed := stripHostedMCPItems(output); removed {
				container["output"] = kept
				changed = true
			}
		}
	}
	stripOutput(event)
	if response, _ := event["response"].(map[string]any); response != nil {
		stripOutput(response)
	}
	if !changed {
		return data, false, false
	}
	filtered, err := json.Marshal(event)
	if err != nil {
		// Fail closed: a response that was positively identified as containing
		// hosted MCP data must never fall back to the unfiltered bytes.
		return nil, true, true
	}
	return filtered, false, true
}

func filterHostedMCPNonStreamingResponse(resp *http.Response) error {
	if resp == nil || resp.Body == nil {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	filtered, drop, changed := filterHostedMCPResponseJSON(body)
	if drop {
		filtered = []byte(`{}`)
		changed = true
	}
	if !changed {
		filtered = body
	}
	resp.Body = io.NopCloser(bytes.NewReader(filtered))
	resp.ContentLength = int64(len(filtered))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(filtered)))
	return nil
}

const hostedMCPMaxSSEEventBytes = 512 * 1024 * 1024

type hostedMCPResponseFilterWriter struct {
	w   io.Writer
	buf []byte
}

func (fw *hostedMCPResponseFilterWriter) Write(p []byte) (int, error) {
	fw.buf = append(fw.buf, p...)
	for {
		event, advance, ok := nextSSEEvent(fw.buf)
		if !ok {
			if len(fw.buf) > hostedMCPMaxSSEEventBytes {
				return len(p), fmt.Errorf("Responses SSE event exceeded %d bytes", hostedMCPMaxSSEEventBytes)
			}
			break
		}
		rawEvent := append([]byte(nil), fw.buf[:advance]...)
		fw.buf = fw.buf[advance:]
		eventName, data := parseSSEEvent(event)
		if len(data) == 0 {
			if _, err := fw.w.Write(rawEvent); err != nil {
				return len(p), err
			}
			continue
		}
		filtered, drop, changed := filterHostedMCPResponseJSON(bytes.TrimSpace(data))
		if drop {
			continue
		}
		if !changed {
			if _, err := fw.w.Write(rawEvent); err != nil {
				return len(p), err
			}
			continue
		}
		if eventName != "" {
			if _, err := fmt.Fprintf(fw.w, "event: %s\ndata: %s\n\n", eventName, filtered); err != nil {
				return len(p), err
			}
		} else if _, err := fmt.Fprintf(fw.w, "data: %s\n\n", filtered); err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}

func nextSSEEvent(buf []byte) (event []byte, advance int, ok bool) {
	if idx := bytes.Index(buf, []byte("\n\n")); idx >= 0 {
		return buf[:idx], idx + 2, true
	}
	if idx := bytes.Index(buf, []byte("\r\n\r\n")); idx >= 0 {
		return buf[:idx], idx + 4, true
	}
	return nil, 0, false
}

func filterHostedMCPResponseSample(data []byte, isSSE bool) []byte {
	if len(data) == 0 {
		return data
	}
	if !isSSE {
		filtered, drop, changed := filterHostedMCPResponseJSON(data)
		if drop {
			return nil
		}
		if changed {
			return filtered
		}
		return data
	}
	var safe bytes.Buffer
	filter := &hostedMCPResponseFilterWriter{w: &safe}
	if _, err := filter.Write(data); err != nil {
		return nil
	}
	// Deliberately omit an incomplete trailing event: it cannot be proven safe.
	return safe.Bytes()
}
