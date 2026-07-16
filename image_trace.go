package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const imageTraceLimit = 8 * 1024 * 1024

func (h *proxyHandler) writeImageGenerationTrace(reqID string, account *Account, rawStream, assembled []byte, cause error) {
	dir := strings.TrimSpace(os.Getenv("PROXY_IMAGE_TRACE_DIR"))
	if dir == "" {
		dir = "./data/image-traces"
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("[%s] create image trace directory: %v", reqID, err)
		return
	}
	accountID := ""
	if account != nil {
		accountID = account.ID
	}
	payload := map[string]any{
		"request_id":  reqID,
		"account_id":  accountID,
		"error":       cause.Error(),
		"raw_sse":     string(limitImageTrace(rawStream)),
		"assembled":   string(limitImageTrace(assembled)),
		"recorded_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		log.Printf("[%s] marshal image trace: %v", reqID, err)
		return
	}
	name := time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + safeImageTraceName(reqID) + ".json"
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
		log.Printf("[%s] write image trace: %v", reqID, err)
	}
}

func limitImageTrace(value []byte) []byte {
	if len(value) <= imageTraceLimit {
		return value
	}
	return value[:imageTraceLimit]
}

func safeImageTraceName(value string) string {
	value = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, value)
	if value == "" {
		return "unknown"
	}
	return value
}
