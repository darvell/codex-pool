package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"mime/multipart"
	"strings"
)

// rewriteCodexLiveCall adapts the public Live SDP multipart shape to the
// ChatGPT OAuth backend's {sdp, session} JSON request shape.
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
	var sessionJSON json.RawMessage
	if err := json.Unmarshal([]byte(session[0]), &sessionJSON); err != nil {
		return nil, fmt.Errorf("parse GPT Live session JSON: %w", err)
	}
	return json.Marshal(struct {
		SDP     string          `json:"sdp"`
		Session json.RawMessage `json:"session"`
	}{SDP: sdp[0], Session: sessionJSON})
}
