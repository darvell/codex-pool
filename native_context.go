package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"

	"golang.org/x/sync/errgroup"
)

const (
	contextRequestLimit   = 2_000_000
	contextDeadline       = 30 * time.Second
	contextConcurrency    = 4
	contextExpansionLimit = 128_000_000
)

var (
	errContextUnavailable = errors.New("required context account is unavailable")
	errContextInvalid     = errors.New("invalid context request")
	errContextResult      = errors.New("invalid context tool result")
)

type nativeContext struct {
	store     *nativeContextStore
	pool      *poolState
	provider  Provider
	transport http.RoundTripper
	refresh   func(context.Context, *Account) error
}

func nativeContextPath(path string) string {
	path = strings.TrimRight(path, "/")
	for _, prefix := range []string{"/backend-api/codex", "/v1", "/api/codex"} {
		if strings.HasPrefix(path, prefix+"/alpha/") {
			return strings.TrimPrefix(path, prefix)
		}
	}
	return path
}

func isNativeContextPath(path string) bool {
	path = nativeContextPath(path)
	return strings.HasPrefix(path, "/alpha/history/") || strings.HasPrefix(path, "/alpha/notes/")
}

func contextRoute(path string) bool {
	switch nativeContextPath(path) {
	case "/alpha/history/v2/list_windows", "/alpha/history/v2/list_items", "/alpha/history/v2/read_item", "/alpha/history/v2/search_contents",
		"/alpha/notes/v2/thread_hint", "/alpha/notes/v2/list_files_by_prefix", "/alpha/notes/v2/read_file", "/alpha/notes/v2/search_contents", "/alpha/notes/v2/append_to_file", "/alpha/notes/v2/write_file":
		return true
	default:
		return false
	}
}

func validContextSession(session string) bool {
	if len(session) != 36 {
		return false
	}
	for i, b := range []byte(session) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if b != '-' {
				return false
			}
			continue
		}
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}

func contextTurnMetadata(obj map[string]any) map[string]any {
	metadata, _ := obj["client_metadata"].(map[string]any)
	encoded, _ := metadata["x-codex-turn-metadata"].(string)
	var turn map[string]any
	_ = json.Unmarshal([]byte(encoded), &turn)
	return turn
}

func contextSessionID(obj map[string]any) string {
	metadata, _ := obj["client_metadata"].(map[string]any)
	session, _ := metadata["session_id"].(string)
	canonical, _ := contextTurnMetadata(obj)["session_id"].(string)
	if canonical != "" {
		if session != "" && session != canonical {
			return ""
		}
		session = canonical
	}
	if !validContextSession(session) {
		return ""
	}
	return session
}

func contextRequested(obj map[string]any) bool {
	metadata, _ := obj["client_metadata"].(map[string]any)
	return contextAllTurns(obj) || contextTurnMetadata(obj)["history_ingest_requested"] == true || metadata["history_ingest_requested"] == "true"
}

func contextAllTurns(obj map[string]any) bool {
	reasoning, _ := obj["reasoning"].(map[string]any)
	return reasoning["context"] == "all_turns"
}

func contextScope(userID string) string {
	principal, _ := splitClientIdentity(userID)
	return principal
}

// A workspace ID alone does not distinguish two users logged into the same workspace.
func contextIdentity(acc *Account) (contextAccount, *Account, error) {
	acc.mu.Lock()
	snapshot := &Account{Type: acc.Type, ID: acc.ID, AccessToken: acc.AccessToken, IDToken: acc.IDToken, AccountID: acc.AccountID, IDTokenChatGPTAccountID: acc.IDTokenChatGPTAccountID, Dead: acc.Dead, Disabled: acc.Disabled, AllowedSourceIPs: append([]string(nil), acc.AllowedSourceIPs...), CodexCookies: make(map[string]string, len(acc.CodexCookies))}
	for key, value := range acc.CodexCookies {
		snapshot.CodexCookies[key] = value
	}
	acc.mu.Unlock()
	accountID := snapshot.AccountID
	if accountID == "" {
		accountID = snapshot.IDTokenChatGPTAccountID
	}
	var user string
	for _, token := range []string{snapshot.AccessToken, snapshot.IDToken} {
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			continue
		}
		data, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			continue
		}
		var claims map[string]any
		if json.Unmarshal(data, &claims) != nil {
			continue
		}
		auth, _ := claims["https://api.openai.com/auth"].(map[string]any)
		user, _ = auth["chatgpt_user_id"].(string)
		if user == "" {
			user, _ = claims["sub"].(string)
		}
		if user != "" {
			break
		}
	}
	if snapshot.Type != AccountTypeCodex || accountID == "" || user == "" || snapshot.AccessToken == "" || snapshot.Dead || snapshot.Disabled {
		return contextAccount{}, nil, errContextUnavailable
	}
	identity, _ := json.Marshal([]string{accountID, user})
	digest := sha256.Sum256(identity)
	return contextAccount{Alias: snapshot.ID, Identity: hex.EncodeToString(digest[:])}, snapshot, nil
}

func (s *nativeContext) credentials(owner contextAccount, clientIP string) (*Account, *Account, error) {
	if s == nil || s.pool == nil {
		return nil, nil, errContextUnavailable
	}
	for _, acc := range s.pool.allAccounts() {
		if acc.Type != AccountTypeCodex || acc.ID != owner.Alias {
			continue
		}
		identity, snapshot, err := contextIdentity(acc)
		if err != nil || identity != owner || !accountAllowsClientIPLocked(snapshot, clientIP) {
			return nil, nil, errContextUnavailable
		}
		return acc, snapshot, nil
	}
	return nil, nil, errContextUnavailable
}

func (s *nativeContext) recordDispatch(scope string, obj map[string]any, acc *Account, clientIP string) error {
	session := contextSessionID(obj)
	if session == "" {
		if contextRequested(obj) {
			return errContextInvalid
		}
		return nil
	}
	if s == nil || s.store == nil {
		if contextRequested(obj) {
			return errContextUnavailable
		}
		return nil
	}
	if err := s.store.claim(scope, session); err != nil {
		return errContextUnavailable
	}
	stored, err := s.store.lookup(scope, session)
	if err != nil {
		return errContextUnavailable
	}
	if stored == nil && !contextRequested(obj) {
		return nil
	}
	identity, _, err := contextIdentity(acc)
	if err != nil {
		return errContextUnavailable
	}
	if _, _, err := s.credentials(identity, clientIP); err != nil {
		return err
	}
	_, err = s.store.record(scope, session, identity)
	if err != nil {
		return errContextUnavailable
	}
	return nil
}

func (s *nativeContext) owner(scope, session, clientIP string) (*contextSession, error) {
	if s == nil || s.store == nil || scope == "" {
		return nil, errContextUnavailable
	}
	if err := s.store.claim(scope, session); err != nil {
		return nil, errContextUnavailable
	}
	stored, err := s.store.lookup(scope, session)
	if err != nil {
		return nil, errContextUnavailable
	}
	if stored != nil {
		return stored, nil
	}
	for _, acc := range s.pool.allAccounts() {
		owner, snapshot, err := contextIdentity(acc)
		if err != nil || !accountAllowsClientIPLocked(snapshot, clientIP) {
			continue
		}
		stored, err = s.store.record(scope, session, owner)
		if err != nil {
			return nil, errContextUnavailable
		}
		return stored, nil
	}
	return nil, errContextUnavailable
}

func parseContextRequest(body []byte) (string, error) {
	var obj struct {
		Context struct {
			Session string `json:"session_id"`
			Agent   string `json:"current_agent_name"`
		} `json:"context"`
	}
	if json.Unmarshal(body, &obj) != nil || !validContextSession(obj.Context.Session) {
		return "", errContextInvalid
	}
	agent := obj.Context.Agent
	if len(agent) > 1024 || (agent != "/root" && !strings.HasPrefix(agent, "/root/")) || strings.IndexFunc(agent, unicode.IsControl) >= 0 {
		return "", errContextInvalid
	}
	for _, part := range strings.Split(strings.TrimPrefix(agent, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			return "", errContextInvalid
		}
	}
	return obj.Context.Session, nil
}

func (s *nativeContext) relay(ctx context.Context, scope, clientIP, path string, headers http.Header, body []byte) ([]byte, error) {
	if len(body) > contextRequestLimit || !contextRoute(path) {
		return nil, errContextInvalid
	}
	session, err := parseContextRequest(body)
	if err != nil {
		return nil, err
	}
	stored, err := s.owner(scope, session, clientIP)
	if err != nil {
		return nil, err
	}
	owners := []contextAccount{stored.Owner}
	path = nativeContextPath(path)
	if strings.HasPrefix(path, "/alpha/history/") {
		owners = stored.Participants
	}
	ctx, cancel := context.WithTimeout(ctx, contextDeadline)
	defer cancel()
	group, ctx := errgroup.WithContext(ctx)
	group.SetLimit(contextConcurrency)
	results := make([]contextResult, len(owners))
	for i, owner := range owners {
		group.Go(func() error {
			value, err := s.send(ctx, owner, clientIP, path, headers, body)
			if err != nil {
				return errContextUnavailable
			}
			results[i] = contextResult{Account: owner, Value: value}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, errContextUnavailable
	}
	if strings.HasSuffix(path, "/thread_hint") {
		return results[0].Value, nil
	}
	for _, result := range results {
		if _, err := contextResultParts(result.Value); err != nil {
			return nil, errContextUnavailable
		}
	}
	encoded, err := s.store.pack(scope, session, results)
	if err != nil {
		return nil, errContextUnavailable
	}
	return json.Marshal(map[string]string{"encrypted_output": encoded})
}

func (s *nativeContext) send(ctx context.Context, owner contextAccount, clientIP, path string, headers http.Header, body []byte) (json.RawMessage, error) {
	for attempt := 0; attempt < 2; attempt++ {
		acc, snapshot, err := s.credentials(owner, clientIP)
		if err != nil {
			return nil, err
		}
		base := s.provider.UpstreamURL("/responses")
		outURL := *base
		outURL.Path = singleJoin(base.Path, path)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, outURL.String(), bytes.NewReader(body))
		if err != nil {
			return nil, errContextUnavailable
		}
		req.Header = cloneHeader(headers)
		removeHopByHopHeaders(req.Header)
		removeConflictingProxyHeaders(req.Header)
		for _, key := range []string{"Authorization", "ChatGPT-Account-ID", "X-Api-Key", "X-Goog-Api-Key", "Cookie", "Content-Length", "Content-Encoding"} {
			req.Header.Del(key)
		}
		s.provider.SetAuthHeaders(req, snapshot)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Accept-Encoding", "identity")
		resp, err := s.transport.RoundTrip(req)
		if err != nil {
			return nil, errContextUnavailable
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 && s.refresh != nil {
			resp.Body.Close()
			if err := s.refresh(ctx, acc); err != nil {
				return nil, errContextUnavailable
			}
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, contextRequestLimit+1))
		resp.Body.Close()
		if err != nil || len(data) > contextRequestLimit || resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices || !json.Valid(data) {
			return nil, errContextUnavailable
		}
		if _, _, err := s.credentials(owner, clientIP); err != nil {
			return nil, err
		}
		return data, nil
	}
	return nil, errContextUnavailable
}

func (s *nativeContext) expand(scope, clientIP string, obj map[string]any) (bool, error) {
	input, _ := obj["input"].([]any)
	var rewritten []any
	expandedBytes := 0
	for i, raw := range input {
		item, _ := raw.(map[string]any)
		if item["type"] != "function_call_output" {
			continue
		}
		output, _ := item["output"].([]any)
		var parts []any
		changed := false
		for _, rawPart := range output {
			part, _ := rawPart.(map[string]any)
			token, _ := part["encrypted_content"].(string)
			if part["type"] != "encrypted_content" || !strings.HasPrefix(token, contextEnvelopePrefix) {
				parts = append(parts, rawPart)
				continue
			}
			if s == nil || s.store == nil || contextSessionID(obj) == "" {
				return false, errContextResult
			}
			results, err := s.store.unpack(scope, contextSessionID(obj), token)
			if err != nil || len(results) == 0 || len(results) > contextParticipantLimit {
				return false, errContextResult
			}
			for _, result := range results {
				if len(result.Value) > contextExpansionLimit-expandedBytes {
					return false, errContextResult
				}
				expandedBytes += len(result.Value)
			}
			for index, result := range results {
				if _, _, err := s.credentials(result.Account, clientIP); err != nil {
					return false, errContextUnavailable
				}
				if len(results) > 1 {
					parts = append(parts, map[string]any{"type": "input_text", "text": fmt.Sprintf("History partition %d of %d. Combine all partitions, deduplicate item and window IDs, then apply the requested order and limit.", index+1, len(results))})
				}
				native, err := contextResultParts(result.Value)
				if err != nil {
					return false, errContextResult
				}
				parts = append(parts, native...)
			}
			changed = true
		}
		if !changed {
			continue
		}
		if rewritten == nil {
			rewritten = append([]any(nil), input...)
		}
		copyItem := make(map[string]any, len(item))
		for key, value := range item {
			copyItem[key] = value
		}
		copyItem["output"] = parts
		rewritten[i] = copyItem
	}
	if rewritten == nil {
		return false, nil
	}
	obj["input"] = rewritten
	return true, nil
}

func contextResultParts(data json.RawMessage) ([]any, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return nil, errContextResult
	}
	obj, isObject := value.(map[string]any)
	if !isObject {
		return []any{map[string]any{"type": "input_text", "text": string(data)}}, nil
	}
	var parts []any
	images, exists := obj["images"]
	delete(obj, "images")
	if encrypted, ok := obj["encrypted_output"].(string); ok {
		parts = append(parts, map[string]any{"type": "encrypted_content", "encrypted_content": encrypted})
	} else {
		text, err := json.Marshal(obj)
		if err != nil {
			return nil, errContextResult
		}
		parts = append(parts, map[string]any{"type": "input_text", "text": string(text)})
	}
	if !exists {
		return parts, nil
	}
	list, ok := images.([]any)
	if !ok {
		return nil, errContextResult
	}
	for _, raw := range list {
		image, _ := raw.(map[string]any)
		data, dataOK := image["data"].(string)
		mime, mimeOK := image["mime_type"].(string)
		if !dataOK || !mimeOK {
			return nil, errContextResult
		}
		switch image["detail"] {
		case nil, "auto", "low", "high", "original":
		default:
			return nil, errContextResult
		}
		parts = append(parts, map[string]any{"type": "input_image", "image_url": "data:" + mime + ";base64," + data, "detail": image["detail"]})
	}
	return parts, nil
}
