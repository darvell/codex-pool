package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const compactionTrigger = "compaction_trigger"
const compactIdleTimeout = 120 * time.Second

func compactHTTPResponse(resp *http.Response, cancel context.CancelFunc) error {
	if resp.StatusCode >= http.StatusBadRequest {
		return nil
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		resp.Body.Close()
		return errors.New("compaction upstream did not return an event stream")
	}

	reader := newIdleTimeoutReader(resp.Body, compactIdleTimeout, cancel)
	body, err := readCompactResponse(reader)
	reader.Close()
	if err != nil {
		return fmt.Errorf("compaction response: %w", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Del("Content-Encoding")
	resp.ContentLength = int64(len(body))
	return nil
}

func isCompactPath(path string) bool {
	switch normalizeNoopPath(path) {
	case "/v1/responses/compact", "/responses/compact", "/backend-api/codex/responses/compact":
		return true
	default:
		return false
	}
}

func compactTurnMetadata(raw string) (string, error) {
	var metadata map[string]any
	_ = json.Unmarshal([]byte(raw), &metadata)
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["request_kind"] = "compaction"
	encoded, err := json.Marshal(metadata)
	return string(encoded), err
}

func prepareCompactRequest(r *http.Request, obj map[string]any) error {
	if obj == nil {
		return errors.New("compaction request must be a JSON object")
	}

	// Compaction now runs as a Responses turn, without generation tools or text formatting.
	for _, key := range []string{"text", "tools", "tool_choice"} {
		delete(obj, key)
	}
	prepareResponsesObject(obj)
	input, ok := obj["input"].([]any)
	if !ok {
		return errors.New("compaction input must be an array or string")
	}
	var last map[string]any
	if len(input) > 0 {
		last, _ = input[len(input)-1].(map[string]any)
	}
	if last["type"] != compactionTrigger {
		obj["input"] = append(input, map[string]any{"type": compactionTrigger})
	}

	encoded, err := compactTurnMetadata(r.Header.Get("X-Codex-Turn-Metadata"))
	if err != nil {
		return err
	}
	r.Header.Set("X-Codex-Turn-Metadata", encoded)
	// Current Codex uses the body metadata as canonical; its header omits large inventories.
	if metadata, _ := obj["client_metadata"].(map[string]any); metadata != nil {
		if raw, ok := metadata["x-codex-turn-metadata"].(string); ok {
			metadata["x-codex-turn-metadata"], err = compactTurnMetadata(raw)
			if err != nil {
				return err
			}
		}
	}
	r.Header.Set("Accept", "text/event-stream")
	r.Header.Del("Content-Length")
	r.URL.Path = strings.TrimSuffix(normalizeNoopPath(r.URL.Path), "/compact")
	return nil
}
