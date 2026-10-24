package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.etcd.io/bbolt"
)

const chatGPTProBucket = "chatgpt_pro_responses"
const chatGPTProTimeout = 10 * time.Minute
const chatGPTProErrorLimit = 8 << 10

var errProActivityRestricted = errors.New("ChatGPT restricted this session. Recover access in the normal client before retrying.")

var chatGPTProModels = map[string]string{
	"gpt-6-pro":   "gpt-6-pro",
	"gpt-5.6-pro": "gpt-5-6-pro",
	"gpt-5-6-pro": "gpt-5-6-pro",
	"gpt-5.5-pro": "gpt-5-5-pro",
	"gpt-5-5-pro": "gpt-5-5-pro",
	"o3-pro":      "o3-pro",
}

type chatGPTProRecord struct {
	Principal string    `json:"principal"`
	Alias     string    `json:"alias"`
	Identity  string    `json:"identity"`
	Input     []any     `json:"input"`
	Created   time.Time `json:"created"`
}

type chatGPTProClient struct {
	h           *proxyHandler
	alias       string
	identity    string
	principal   string
	ip          string
	reservation *chatGPTReservation
	cookies     http.CookieJar
	cookieInit  sync.Once
}

func (h *proxyHandler) proAccount(principal, ip, alias, identity string) (*chatGPTProClient, error) {
	cookies, err := cookiejar.New(nil)
	if err != nil {
		return nil, errors.New("Pro session initialization failed")
	}
	client := &chatGPTProClient{h: h, alias: alias, identity: identity, principal: principal, ip: ip, cookies: cookies}
	if h.chatGPT != nil {
		if reservation, ok := h.chatGPT.reservation(principal); ok {
			if alias != "" && (alias != reservation.Alias || identity != reservation.Identity) {
				return nil, errors.New("Pro account binding changed")
			}
			client.alias, client.identity = reservation.Alias, reservation.Identity
			client.reservation = &reservation
			return client, nil
		}
	}
	if alias != "" {
		if _, err := client.account(); err != nil {
			return nil, err
		}
		return client, nil
	}
	account := h.pool.proCandidate(ip)
	if account == nil {
		return nil, errors.New("no available Pro account")
	}
	account.mu.Lock()
	client.alias, client.identity = account.ID, chatGPTPhysicalLocked(account)
	account.mu.Unlock()
	if client.identity == "" {
		return nil, errors.New("Pro account identity unavailable")
	}
	return client, nil
}

func (p *poolState) proCandidate(ip string) *Account {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	var selected *Account
	var best float64
	for _, account := range p.accounts {
		account.mu.Lock()
		plan := normalizeCodexPlanType(account.PlanType)
		eligible := account.Type == AccountTypeCodex && (plan == "pro" || plan == "promax") &&
			!p.chatGPTReservedLocked(account) && !account.Disabled && !account.Dead &&
			!account.RateLimitUntil.After(now) && accountAllowsClientIPLocked(account, ip) &&
			!primaryUsageBlocksRoutingLocked(account, accountPrimaryUsageLocked(account)) &&
			accountSecondaryUsageLocked(account) < secondaryHardExcludeThreshold
		score := scoreAccountLocked(account, now)
		account.mu.Unlock()
		if eligible && (selected == nil || score > best) {
			selected, best = account, score
		}
	}
	return selected
}

func (c *chatGPTProClient) account() (*Account, error) {
	if c.reservation != nil {
		account, _, _, _, err := c.h.chatGPT.account(*c.reservation, c.ip)
		return account, err
	}
	c.h.pool.mu.RLock()
	defer c.h.pool.mu.RUnlock()
	account := c.h.pool.getLocked(c.alias)
	if account == nil {
		return nil, errors.New("Pro account unavailable")
	}
	account.mu.Lock()
	defer account.mu.Unlock()
	if c.h.pool.chatGPTReservedLocked(account) || chatGPTPhysicalLocked(account) != c.identity {
		return nil, errors.New("Pro account binding changed")
	}
	if account.Disabled || account.Dead || account.RateLimitUntil.After(time.Now()) || !accountAllowsClientIPLocked(account, c.ip) {
		return nil, errors.New("Pro account unavailable")
	}
	return account, nil
}

func (c *chatGPTProClient) send(ctx context.Context, path string, headers http.Header, body any) (*http.Response, error) {
	account, err := c.account()
	if err != nil {
		return nil, err
	}
	account.mu.Lock()
	expired := !account.ExpiresAt.IsZero() && !account.ExpiresAt.After(time.Now())
	account.mu.Unlock()
	if expired {
		if err := c.h.refreshAccountAfterAuthFailure(ctx, account); err != nil {
			return nil, errors.New("Pro account refresh failed")
		}
		if _, err := c.account(); err != nil {
			return nil, err
		}
	}
	var payload []byte
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	method := http.MethodPost
	if body == nil {
		method = http.MethodGet
	}
	provider := c.h.registry.ForType(AccountTypeCodex)
	if provider == nil {
		return nil, errors.New("Pro upstream unavailable")
	}
	base := *provider.UpstreamURL("/backend-api/" + path)
	base.Path = singleJoin(base.Path, path)
	base.RawQuery, base.Fragment = "", ""
	req, err := http.NewRequestWithContext(ctx, method, base.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header = headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Content-Type", "application/json")
	provider.SetAuthHeaders(req, contextAuthSnapshot(account))
	// Seed once so a server deletion is not undone by the saved account cookies.
	c.cookieInit.Do(func() {
		cookies := req.Cookies()
		for _, cookie := range cookies {
			cookie.Path = "/"
		}
		c.cookies.SetCookies(req.URL, cookies)
	})
	req.Header.Del("Cookie")
	for _, cookie := range c.cookies.Cookies(req.URL) {
		req.AddCookie(cookie)
	}
	resp, err := c.h.transport.RoundTrip(req)
	if err != nil {
		return nil, errors.New("Pro upstream unavailable")
	}
	if _, err := c.account(); err != nil {
		resp.Body.Close()
		return nil, err
	}
	c.cookies.SetCookies(req.URL, resp.Cookies())
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			var failure struct {
				Detail string `json:"detail"`
			}
			if json.NewDecoder(io.LimitReader(resp.Body, chatGPTProErrorLimit)).Decode(&failure) == nil &&
				strings.Contains(strings.ToLower(failure.Detail), "unusual activity") {
				return nil, errProActivityRestricted
			}
		}
		return nil, fmt.Errorf("Pro upstream rejected request (HTTP %d %s)", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	return resp, nil
}

func (c *chatGPTProClient) json(ctx context.Context, path string, body any) (map[string]any, error) {
	resp, err := c.send(ctx, path, nil, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, chatGPTEventLimit)).Decode(&result); err != nil {
		return nil, errors.New("invalid Pro upstream response")
	}
	return result, nil
}

func (c *chatGPTProClient) eligible(ctx context.Context, model string) error {
	account, err := c.account()
	if err != nil {
		return err
	}
	account.mu.Lock()
	id := account.AccountID
	if id == "" {
		id = account.IDTokenChatGPTAccountID
	}
	account.mu.Unlock()
	membership, err := c.json(ctx, "accounts/check/v4-2023-04-27", nil)
	if err != nil {
		return err
	}
	accounts, _ := membership["accounts"].(map[string]any)
	member, _ := accounts[id].(map[string]any)
	metadata, _ := member["account"].(map[string]any)
	if metadata["account_id"] != id || (metadata["plan_type"] != "pro" && metadata["plan_type"] != "promax") {
		return errors.New("live Pro membership required")
	}
	catalog, err := c.json(ctx, "models", nil)
	if err != nil {
		return err
	}
	models, _ := catalog["models"].([]any)
	for _, raw := range models {
		entry, _ := raw.(map[string]any)
		if entry["slug"] == model && entry["disabled"] != true {
			return nil
		}
	}
	return errors.New("Pro model unavailable for this account")
}

func (c *chatGPTProClient) integrity(ctx context.Context) (http.Header, error) {
	browser, err := newChatGPTIntegrity(ctx)
	if err != nil {
		return nil, err
	}
	defer browser.close()
	key, err := browser.prepare()
	if err != nil {
		return nil, err
	}
	requirements, err := c.json(ctx, "sentinel/chat-requirements/prepare", map[string]any{"p": key})
	if err != nil {
		return nil, err
	}
	proofs, err := browser.complete(requirements)
	if err != nil {
		return nil, err
	}
	token, _ := requirements["token"].(string)
	if token == "" {
		prepare, _ := requirements["prepare_token"].(string)
		if prepare == "" {
			return nil, errors.New("Pro integrity token unavailable")
		}
		final, err := c.json(ctx, "sentinel/chat-requirements/finalize", map[string]any{"prepare_token": prepare, "proofofwork": proofs["proofofwork"], "turnstile": proofs["turnstile"]})
		if err != nil {
			return nil, err
		}
		token, _ = final["token"].(string)
	}
	if token == "" {
		return nil, errors.New("Pro integrity token unavailable")
	}
	headers := make(http.Header)
	headers.Set("OpenAI-Sentinel-Chat-Requirements-Token", token)
	if proofs["proofofwork"] != "" {
		headers.Set("OpenAI-Sentinel-Proof-Token", proofs["proofofwork"])
	}
	if proofs["turnstile"] != "" {
		headers.Set("OpenAI-Sentinel-Turnstile-Token", proofs["turnstile"])
	}
	headers.Set("Accept", "text/event-stream")
	return headers, nil
}

func proRecordKey(principal, response string) []byte {
	digest := sha256.Sum256([]byte(principal + "\x00" + response))
	return []byte(hex.EncodeToString(digest[:]))
}

func (h *proxyHandler) readProRecord(principal, id string) (*chatGPTProRecord, error) {
	if h.store == nil {
		return nil, errors.New("Pro response storage unavailable")
	}
	var record chatGPTProRecord
	err := h.store.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(chatGPTProBucket))
		if bucket == nil {
			return errors.New("previous Pro response unavailable")
		}
		raw := bucket.Get(proRecordKey(principal, id))
		if raw == nil {
			return errors.New("previous Pro response unavailable")
		}
		return json.Unmarshal(raw, &record)
	})
	if err != nil {
		return nil, err
	}
	if record.Principal != principal {
		return nil, errors.New("previous Pro response unavailable")
	}
	return &record, nil
}

func (h *proxyHandler) saveProRecord(principal, id string, record chatGPTProRecord) error {
	if h.store == nil {
		return errors.New("Pro response storage unavailable")
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return h.store.db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(chatGPTProBucket))
		if err != nil {
			return err
		}
		return bucket.Put(proRecordKey(principal, id), raw)
	})
}

func proInput(input any) ([]any, error) {
	if text, ok := input.(string); ok {
		return []any{map[string]any{"role": "user", "content": text}}, nil
	}
	items, ok := input.([]any)
	if !ok {
		return nil, errors.New("Responses input must be text or an array")
	}
	return items, nil
}

func proModel(model string) string {
	return chatGPTProModels[strings.ToLower(strings.TrimSpace(model))]
}

func (h *proxyHandler) handleSpooledPro(w http.ResponseWriter, r *http.Request, spooled *streamedResponsesRequest) bool {
	if proModel(spooled.Model) == "" {
		return false
	}
	if spooled.Size > h.cfg.maxInMemoryBodyBytes {
		respondJSONError(w, http.StatusRequestEntityTooLarge, "Pro request exceeds the configured request size limit")
		return true
	}
	var request map[string]any
	reader := io.NewSectionReader(spooled.File, 0, spooled.Size)
	if json.NewDecoder(reader).Decode(&request) != nil {
		respondJSONError(w, http.StatusBadRequest, "Invalid Responses request")
		return true
	}
	request["stream"] = !spooled.ClientWantsNonStreaming
	return h.handleChatGPTPro(w, r, mustJSON(request), spooled.Model)
}

func respondProError(w http.ResponseWriter, status int, err error) {
	if errors.Is(err, errProActivityRestricted) {
		status = http.StatusForbidden
	}
	respondJSONError(w, status, err.Error())
}

func (h *proxyHandler) handleChatGPTPro(w http.ResponseWriter, r *http.Request, body []byte, model string) bool {
	upstreamModel := proModel(model)
	if upstreamModel == "" || !isCodexResponsesPath(r.URL.Path) {
		return false
	}
	if r.Method != http.MethodPost {
		respondJSONError(w, http.StatusMethodNotAllowed, "Pro models require a Responses POST")
		return true
	}
	_, principal, _, _, authorized := h.authorizePoolCredentialRequest(r)
	if !authorized || principal == "" || h.passport == nil {
		respondJSONError(w, http.StatusUnauthorized, "A live pool credential is required")
		return true
	}
	var request map[string]any
	if json.Unmarshal(body, &request) != nil {
		respondJSONError(w, http.StatusBadRequest, "Invalid Responses request")
		return true
	}
	input, err := proInput(request["input"])
	if err != nil {
		respondJSONError(w, http.StatusBadRequest, err.Error())
		return true
	}
	var prior *chatGPTProRecord
	if previous, ok := request["previous_response_id"].(string); ok && previous != "" {
		prior, err = h.readProRecord(principal, previous)
		if err != nil {
			respondJSONError(w, http.StatusNotFound, "Previous Pro response unavailable")
			return true
		}
		input = append(append([]any{}, prior.Input...), input...)
		request["input"] = input
		delete(request, "previous_response_id")
	}
	translated, err := translateChatGPTRequest(mustJSON(request), upstreamModel, uuid.NewString())
	if err != nil {
		respondJSONError(w, http.StatusBadRequest, err.Error())
		return true
	}
	var conversation map[string]any
	if json.Unmarshal(translated, &conversation) != nil {
		respondJSONError(w, http.StatusBadRequest, "Invalid Pro conversation")
		return true
	}
	alias, identity := "", ""
	if prior != nil {
		alias, identity = prior.Alias, prior.Identity
	}
	client, err := h.proAccount(principal, getClientIP(r), alias, identity)
	if err != nil {
		respondJSONError(w, http.StatusServiceUnavailable, err.Error())
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), chatGPTProTimeout)
	defer cancel()
	if err = client.eligible(ctx, upstreamModel); err != nil {
		respondProError(w, http.StatusServiceUnavailable, err)
		return true
	}
	headers, err := client.integrity(ctx)
	if err != nil {
		respondProError(w, http.StatusServiceUnavailable, err)
		return true
	}
	response, err := client.send(ctx, "f/conversation", headers, conversation)
	if err != nil {
		respondProError(w, http.StatusBadGateway, err)
		return true
	}
	streaming, _ := request["stream"].(bool)
	responseID := "resp_" + uuid.NewString()
	started := false
	var final map[string]any
	emit := func(event map[string]any) error {
		if event["type"] == "response.completed" {
			value, _ := event["response"].(map[string]any)
			output, _ := value["output"].([]map[string]any)
			storedInput := append([]any{}, input...)
			for _, item := range output {
				storedInput = append(storedInput, item)
			}
			record := chatGPTProRecord{Principal: principal, Alias: client.alias, Identity: client.identity, Input: storedInput, Created: time.Now().UTC()}
			if err := h.saveProRecord(principal, responseID, record); err != nil {
				return errors.New("Pro response persistence failed")
			}
			final = value
		}
		if !streaming {
			return nil
		}
		if !started {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-store")
			started = true
		}
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if _, err = io.WriteString(w, "event: "+event["type"].(string)+"\ndata: "+string(data)+"\n\n"); err != nil {
			return err
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		return nil
	}
	tools := map[string]bool{}
	if request["tool_choice"] != "none" {
		definitions, _ := request["tools"].([]any)
		for _, raw := range definitions {
			tool, _ := raw.(map[string]any)
			name, _ := tool["name"].(string)
			tools[name] = tool["type"] == "custom"
		}
	}
	decoder := newChatGPTStream(responseID, model, emit, tools)
	var state chatGPTStreamState
	for {
		_, err = io.Copy(proStreamWriter{decoder}, response.Body)
		response.Body.Close()
		if err != nil {
			break
		}
		state, err = decoder.Finish()
		if err != nil || state.Completed {
			break
		}
		if !state.Handoff || state.ConversationID == "" || state.ResumeToken == "" {
			err = errors.New("Pro response ended before completion")
			break
		}
		if err = decoder.Resume(); err != nil {
			break
		}
		headers.Set("X-Conduit-Token", state.ResumeToken)
		response, err = client.send(ctx, "f/conversation/resume", headers, map[string]any{"conversation_id": state.ConversationID, "offset": state.Offset})
		if err != nil {
			break
		}
	}
	if err != nil {
		if started {
			code := "pro_upstream_error"
			if errors.Is(err, errProActivityRestricted) {
				code = "pro_activity_restricted"
			}
			_ = emit(map[string]any{"type": "response.failed", "response": map[string]any{"id": responseID, "object": "response", "model": model, "status": "failed", "output": []any{}, "error": map[string]any{"code": code, "message": err.Error()}}})
		} else {
			respondProError(w, http.StatusBadGateway, err)
		}
		return true
	}
	if !streaming {
		respondJSON(w, final)
	}
	return true
}

type proStreamWriter struct{ decoder *chatGPTStream }

func (w proStreamWriter) Write(data []byte) (int, error) {
	if err := w.decoder.Feed(data); err != nil {
		return 0, err
	}
	return len(data), nil
}

func mustJSON(value any) []byte { data, _ := json.Marshal(value); return data }
