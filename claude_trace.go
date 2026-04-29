package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type claudeTracePayload struct {
	Method        string              `json:"method,omitempty"`
	Path          string              `json:"path,omitempty"`
	URL           string              `json:"url,omitempty"`
	Headers       map[string][]string `json:"headers,omitempty"`
	Body          string              `json:"body,omitempty"`
	BodyBytes     int                 `json:"body_bytes,omitempty"`
	BodyTruncated bool                `json:"body_truncated,omitempty"`
}

type claudeTraceRecord struct {
	Timestamp    string              `json:"timestamp"`
	RequestID    string              `json:"request_id"`
	Mode         string              `json:"mode"`
	UserID       string              `json:"user_id,omitempty"`
	OriginID     string              `json:"origin_id,omitempty"`
	ClientIP     string              `json:"client_ip,omitempty"`
	AccountID    string              `json:"account_id,omitempty"`
	AccountPlan  string              `json:"account_plan,omitempty"`
	TranslateDir string              `json:"translate_dir,omitempty"`
	Error        string              `json:"error,omitempty"`
	Incoming     *claudeTracePayload `json:"incoming,omitempty"`
	Upstream     *claudeTracePayload `json:"upstream,omitempty"`
	Response     *claudeTracePayload `json:"response,omitempty"`
}

type claudeTraceReadCloser struct {
	reader   io.Reader
	closer   io.Closer
	finalize func()
	once     sync.Once
}

func (rc *claudeTraceReadCloser) Read(p []byte) (int, error) {
	return rc.reader.Read(p)
}

func (rc *claudeTraceReadCloser) Close() error {
	err := rc.closer.Close()
	rc.once.Do(func() {
		if rc.finalize != nil {
			rc.finalize()
		}
	})
	return err
}

func (c *config) claudeTraceEnabled() bool {
	return c != nil && c.claudeTraceDir != "" && c.claudeTraceBodyLimit > 0
}

func (h *proxyHandler) claudeTraceSampleLimit(base int64) int64 {
	limit := base
	if h != nil && h.cfg != nil && h.cfg.claudeTraceEnabled() && h.cfg.claudeTraceBodyLimit > limit {
		limit = h.cfg.claudeTraceBodyLimit
	}
	return limit
}

func (h *proxyHandler) attachClaudeTrace(
	reqID string,
	mode string,
	userID string,
	originID string,
	acc *Account,
	incoming *http.Request,
	incomingBody []byte,
	upstream *http.Request,
	upstreamBody []byte,
	resp *http.Response,
	translateDir TranslateDirection,
	buf *bytes.Buffer,
	limit int64,
) {
	if h == nil || h.cfg == nil || !h.cfg.claudeTraceEnabled() || upstream == nil || resp == nil {
		return
	}

	closer := resp.Body
	resp.Body = &claudeTraceReadCloser{
		reader: io.TeeReader(resp.Body, &limitedWriter{w: buf, n: limit}),
		closer: closer,
		finalize: func() {
			h.writeClaudeTrace(reqID, mode, userID, originID, acc, incoming, incomingBody, upstream, upstreamBody, resp, translateDir, buf.Bytes(), "")
		},
	}
}

func (h *proxyHandler) writeClaudeTrace(
	reqID string,
	mode string,
	userID string,
	originID string,
	acc *Account,
	incoming *http.Request,
	incomingBody []byte,
	upstream *http.Request,
	upstreamBody []byte,
	resp *http.Response,
	translateDir TranslateDirection,
	respSample []byte,
	traceErr string,
) {
	if h == nil || h.cfg == nil || !h.cfg.claudeTraceEnabled() {
		return
	}
	if err := os.MkdirAll(h.cfg.claudeTraceDir, 0o755); err != nil {
		log.Printf("[%s] failed to create claude trace dir %s: %v", reqID, h.cfg.claudeTraceDir, err)
		return
	}

	record := claudeTraceRecord{
		Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
		RequestID:    reqID,
		Mode:         mode,
		UserID:       userID,
		OriginID:     originID,
		TranslateDir: translateDirectionName(translateDir),
		Error:        traceErr,
		Incoming:     tracePayloadFromRequest(incoming, incomingBody, h.cfg.claudeTraceBodyLimit, h.cfg.claudeTraceSecrets),
		Upstream:     tracePayloadFromRequest(upstream, upstreamBody, h.cfg.claudeTraceBodyLimit, h.cfg.claudeTraceSecrets),
		Response:     tracePayloadFromResponse(resp, respSample, h.cfg.claudeTraceBodyLimit, h.cfg.claudeTraceSecrets),
	}
	if incoming != nil {
		record.ClientIP = getClientIP(incoming)
	}
	if acc != nil {
		record.AccountID = acc.ID
		record.AccountPlan = acc.PlanType
	}

	body, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		log.Printf("[%s] failed to marshal claude trace: %v", reqID, err)
		return
	}

	name := time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + reqID
	if acc != nil && acc.ID != "" {
		name += "-" + sanitizeTracePathComponent(acc.ID)
	}
	path := filepath.Join(h.cfg.claudeTraceDir, name+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		log.Printf("[%s] failed to write claude trace temp file %s: %v", reqID, tmp, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("[%s] failed to finalize claude trace file %s: %v", reqID, path, err)
		return
	}
	log.Printf("[%s] wrote claude trace %s", reqID, path)
}

func tracePayloadFromRequest(r *http.Request, body []byte, limit int64, includeSecrets bool) *claudeTracePayload {
	if r == nil {
		return nil
	}
	payload := &claudeTracePayload{
		Method:  r.Method,
		Path:    r.URL.Path,
		URL:     r.URL.String(),
		Headers: traceHeaderSnapshot(r.Header, includeSecrets),
	}
	payload.Body, payload.BodyBytes, payload.BodyTruncated = traceBodyString(body, limit)
	return payload
}

func tracePayloadFromResponse(resp *http.Response, body []byte, limit int64, includeSecrets bool) *claudeTracePayload {
	if resp == nil {
		return nil
	}
	payload := &claudeTracePayload{
		Headers: traceHeaderSnapshot(resp.Header, includeSecrets),
	}
	payload.Body, payload.BodyBytes, payload.BodyTruncated = traceBodyString(bodyForInspection(nil, body), limit)
	if resp.Request != nil {
		payload.Method = resp.Request.Method
		payload.Path = resp.Request.URL.Path
		payload.URL = resp.Request.URL.String()
	}
	if payload.Headers == nil {
		payload.Headers = map[string][]string{}
	}
	payload.Headers[":status"] = []string{http.StatusText(resp.StatusCode)}
	payload.Headers[":status_code"] = []string{strconv.Itoa(resp.StatusCode)}
	return payload
}

func traceBodyString(body []byte, limit int64) (string, int, bool) {
	if len(body) == 0 || limit <= 0 {
		return "", len(body), false
	}
	truncated := false
	if int64(len(body)) > limit {
		body = body[:limit]
		truncated = true
	}
	return safeText(body), len(body), truncated
}

func traceHeaderSnapshot(src http.Header, includeSecrets bool) map[string][]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string][]string, len(src))
	for key, values := range src {
		copied := make([]string, len(values))
		for i, value := range values {
			copied[i] = traceHeaderValue(key, value, includeSecrets)
		}
		out[key] = copied
	}
	return out
}

func traceHeaderValue(key, value string, includeSecrets bool) string {
	if includeSecrets {
		return value
	}
	switch strings.ToLower(key) {
	case "authorization", "x-api-key", "cookie", "set-cookie", "proxy-authorization", "x-goog-api-key":
		if value == "" {
			return ""
		}
		return "<redacted>"
	default:
		return value
	}
}

func translateDirectionName(dir TranslateDirection) string {
	switch dir {
	case TranslateNone:
		return ""
	case TranslateClaudeToOAI:
		return "claude_to_oai"
	case TranslateOAIToClaude:
		return "oai_to_claude"
	case TranslateClaudeToResponses:
		return "claude_to_responses"
	case TranslateChatToResponses:
		return "chat_to_responses"
	case TranslateResponsesToClaude:
		return "responses_to_claude"
	default:
		return "unknown"
	}
}

func sanitizeTracePathComponent(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "trace"
	}
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_")
	return replacer.Replace(s)
}
