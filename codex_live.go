package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
)

// rewriteCodexLiveCall adapts the public Live SDP multipart shape to the
// ChatGPT OAuth backend's {sdp, session} JSON request shape.
const codexRealtimeCallPinPrefix = "realtime-call:"

func codexRealtimeCallPinKey(callID string) string {
	callID = strings.TrimSpace(callID)
	if callID == "" {
		return ""
	}
	return codexRealtimeCallPinPrefix + callID
}

func codexRealtimeCallIDFromRequest(path string, query url.Values) string {
	if callID := strings.TrimSpace(query.Get("call_id")); callID != "" {
		return callID
	}
	path = normalizeNoopPath(path)
	for _, prefix := range []string{"/live/", "/v1/live/"} {
		if strings.HasPrefix(path, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(path, prefix))
		}
	}
	return ""
}

func codexRealtimeCallIDFromLocation(location string) string {
	location = strings.TrimSpace(location)
	if location == "" {
		return ""
	}
	if parsed, err := url.Parse(location); err == nil && parsed.Path != "" {
		location = parsed.Path
	}
	parts := strings.Split(strings.Trim(location, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		part := strings.TrimSpace(parts[i])
		if strings.HasPrefix(part, "rtc_") {
			return part
		}
	}
	return ""
}

func isCodexVoiceAccessDenied(body []byte) bool {
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "voice session access denied")
}

func isCodexRealtimeCallCreatePath(path string) bool {
	path = normalizeNoopPath(path)
	return path == "/v1/realtime/calls" || path == "/live" || path == "/v1/live"
}

func rewriteCodexLiveCall(body []byte, contentType string) ([]byte, error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "multipart/form-data") {
		return nil, fmt.Errorf("GPT Live requires multipart/form-data with sdp and session parts")
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, fmt.Errorf("GPT Live multipart request is missing a boundary")
	}
	form, err := multipart.NewReader(bytes.NewReader(body), boundary).ReadForm(2 << 20)
	if err != nil {
		return nil, fmt.Errorf("parse GPT Live multipart request: %w", err)
	}
	defer form.RemoveAll()
	sdp := form.Value["sdp"]
	session := form.Value["session"]
	if len(sdp) != 1 || len(session) != 1 || strings.TrimSpace(sdp[0]) == "" || strings.TrimSpace(session[0]) == "" {
		return nil, fmt.Errorf("GPT Live multipart request needs exactly one sdp and one session part")
	}
	var sessionObject map[string]any
	if err := json.Unmarshal([]byte(session[0]), &sessionObject); err != nil {
		return nil, fmt.Errorf("parse GPT Live session JSON: %w", err)
	}
	sessionJSON, err := json.Marshal(sessionObject)
	if err != nil {
		return nil, fmt.Errorf("encode GPT Live session JSON: %w", err)
	}
	return json.Marshal(struct {
		SDP     string          `json:"sdp"`
		Session json.RawMessage `json:"session"`
	}{SDP: sdp[0], Session: sessionJSON})
}
