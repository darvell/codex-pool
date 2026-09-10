package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type contextFrameKey struct{}

func isContextRequestPath(path string) bool {
	path = nativeContextPath(path)
	return path == "/alpha/history" || path == "/alpha/notes" || isNativeContextPath(path)
}

func isContextError(err error) bool {
	return errors.Is(err, errContextInvalid) || errors.Is(err, errContextUnavailable) || errors.Is(err, errContextResult)
}

func contextErrorStatus(err error) int {
	if errors.Is(err, errContextInvalid) || errors.Is(err, errContextResult) {
		return http.StatusBadRequest
	}
	return http.StatusServiceUnavailable
}

func contextErrorBody(err error) []byte {
	message := "Context is unavailable. Restore the original account and retry."
	kind := "context_unavailable"
	if contextErrorStatus(err) == http.StatusBadRequest {
		message = "Invalid context. Start a new session and retry."
		kind = "invalid_context"
	}
	body, _ := json.Marshal(map[string]any{"type": "error", "status": contextErrorStatus(err), "error": map[string]string{"type": kind, "message": message}})
	return body
}

func writeContextError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(contextErrorStatus(err))
	_, _ = w.Write(contextErrorBody(err))
}

func (h *proxyHandler) proxyNativeContext(w http.ResponseWriter, r *http.Request, userID string) {
	w.Header().Set("Content-Type", "application/json")
	// Reject unknown operations before any account selection or upstream traffic.
	if !contextRoute(r.URL.Path) || strings.HasSuffix(r.URL.Path, "/") {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":{"message":"Context operation not found."}}`)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = io.WriteString(w, `{"error":{"message":"Use POST for context operations."}}`)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), contextDeadline)
	defer cancel()
	// Bound both wire bytes and decompressed JSON independently.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(contextDeadline))
	defer http.NewResponseController(w).SetReadDeadline(time.Time{})
	body, err := io.ReadAll(io.LimitReader(r.Body, contextRequestLimit+1))
	if err != nil || len(body) > contextRequestLimit {
		writeContextError(w, errContextInvalid)
		return
	}
	encoding := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	if encoding != "" && encoding != "identity" && encoding != "gzip" && encoding != "zstd" {
		writeContextError(w, errContextInvalid)
		return
	}
	body, _, err = decodeRequestBody(encoding, body, contextRequestLimit)
	if err != nil {
		writeContextError(w, errContextInvalid)
		return
	}
	result, err := h.nativeContext.relay(ctx, contextScope(userID), getClientIP(r), r.URL.Path, r.Header, body)
	if err != nil {
		writeContextError(w, err)
		return
	}
	_, _ = w.Write(result)
}

// Keep the unexpanded object for every attempt so source credentials are revalidated.
func (h *proxyHandler) prepareContextObject(userID, ip string, obj map[string]any, acc *Account) (map[string]any, bool, error) {
	copyObj := make(map[string]any, len(obj))
	for key, value := range obj {
		copyObj[key] = value
	}
	var service *nativeContext
	if h != nil {
		service = h.nativeContext
	}
	changed, err := service.expand(contextScope(userID), ip, copyObj)
	if err != nil {
		return nil, false, err
	}
	if err := service.recordDispatch(contextScope(userID), copyObj, acc, ip); err != nil {
		return nil, false, err
	}
	return copyObj, changed, nil
}

func mayHaveContext(body []byte) bool {
	return bytes.Contains(body, []byte(`"client_metadata"`)) || bytes.Contains(body, []byte(`"reasoning"`)) || bytes.Contains(body, []byte(`"encrypted_content"`)) || bytes.Contains(body, []byte(`\`))
}

func (h *proxyHandler) prepareContextFrame(userID, ip string, body []byte, acc *Account) ([]byte, error) {
	if !mayHaveContext(body) {
		return body, nil
	}
	var root map[string]any
	if json.Unmarshal(body, &root) != nil || root == nil {
		return nil, errContextInvalid
	}
	obj := root
	nested, isNested := root["response"].(map[string]any)
	if isNested {
		obj = nested
	}
	prepared, changed, err := h.prepareContextObject(userID, ip, obj, acc)
	if err != nil {
		return nil, err
	}
	if !changed {
		return body, nil
	}
	if isNested {
		root["response"] = prepared
	} else {
		root = prepared
	}
	return json.Marshal(root)
}

// The credential snapshot used for registration must also authenticate the dispatch.
func contextAuthSnapshot(acc *Account) *Account {
	if acc == nil {
		return nil
	}
	acc.mu.Lock()
	defer acc.mu.Unlock()
	snapshot := &Account{Type: acc.Type, ID: acc.ID, AccessToken: acc.AccessToken, IDToken: acc.IDToken, AccountID: acc.AccountID, IDTokenChatGPTAccountID: acc.IDTokenChatGPTAccountID, Dead: acc.Dead, Disabled: acc.Disabled, AllowedSourceIPs: append([]string(nil), acc.AllowedSourceIPs...), CodexCookies: make(map[string]string, len(acc.CodexCookies))}
	for key, value := range acc.CodexCookies {
		snapshot.CodexCookies[key] = value
	}
	return snapshot
}
