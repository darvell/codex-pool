package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const vibeSignInLimit = 64

var errVibeExpired = errors.New("Mistral sign-in expired. Start again")

func (h *proxyHandler) vibeJSON(ctx context.Context, method, target string, input any, key string, output any) error {
	ctx, cancel := context.WithTimeout(ctx, vibeHTTPTimeout)
	defer cancel()
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return errors.New("Invalid Mistral endpoint")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "codex-pool/Mistral-Vibe")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		request.Header.Set("Authorization", "Bearer "+key)
	}
	response, err := h.transport.RoundTrip(request)
	if err != nil {
		return errors.New("Mistral connection failed. Try again")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return errors.New("Mistral rejected this credential. Sign in again")
	}
	if response.StatusCode == http.StatusGone {
		return errVibeExpired
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("Mistral returned HTTP %d. Try again", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, vibeResponseLimit+1))
	if err != nil || len(data) > vibeResponseLimit || json.Unmarshal(data, output) != nil {
		return errors.New("Mistral returned an invalid response. Try again")
	}
	return nil
}

type vibeSignInSession struct {
	mu        sync.Mutex
	ID        string
	ActorID   string
	ProcessID string
	Verifier  string
	PollURL   string
	ExpiresAt time.Time
	Status    string
	AccountID string
	Error     string
}

var vibeSignIns = struct {
	sync.Mutex
	sessions map[string]*vibeSignInSession
}{sessions: make(map[string]*vibeSignInSession)}

func vibeAuthURL(value, pathPrefix string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Host == "console.mistral.ai" && u.User == nil && strings.HasPrefix(u.Path, pathPrefix) && !strings.Contains(u.Path, "..") && !strings.Contains(u.EscapedPath(), "%") && u.Fragment == ""
}

func (h *proxyHandler) startVibeSignIn(w http.ResponseWriter, r *http.Request) {
	vibeSignIns.Lock()
	for id, session := range vibeSignIns.sessions {
		if !session.ExpiresAt.After(time.Now()) {
			delete(vibeSignIns.sessions, id)
		}
	}
	full := len(vibeSignIns.sessions) >= vibeSignInLimit
	vibeSignIns.Unlock()
	if full {
		respondJSONError(w, http.StatusTooManyRequests, "Too many pending sign-ins. Try again later")
		return
	}
	verifier := randomHex(32)
	challenge := sha256.Sum256([]byte(verifier))
	var process struct {
		ID        string    `json:"process_id"`
		URL       string    `json:"sign_in_url"`
		PollURL   string    `json:"poll_url"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	input := map[string]string{"code_challenge": base64.RawURLEncoding.EncodeToString(challenge[:]), "code_challenge_method": "S256"}
	if err := h.vibeJSON(r.Context(), http.MethodPost, vibeConsoleURL+"/api/vibe/sign-in", input, "", &process); err != nil {
		respondJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	if process.ID == "" || strings.ContainsAny(process.ID, "/?#%\\") || !vibeAuthURL(process.URL, "/") || !vibeAuthURL(process.PollURL, "/api/vibe/") || !process.ExpiresAt.After(time.Now()) {
		respondJSONError(w, http.StatusBadGateway, "Mistral returned an invalid sign-in session")
		return
	}
	if maximum := time.Now().Add(vibePlanTTL); process.ExpiresAt.After(maximum) {
		process.ExpiresAt = maximum
	}
	session := &vibeSignInSession{ID: randomHex(24), ActorID: providerContributionActor(r), ProcessID: process.ID, Verifier: verifier, PollURL: process.PollURL, ExpiresAt: process.ExpiresAt, Status: "pending"}
	vibeSignIns.Lock()
	if len(vibeSignIns.sessions) >= vibeSignInLimit {
		vibeSignIns.Unlock()
		respondJSONError(w, http.StatusTooManyRequests, "Too many pending sign-ins. Try again later")
		return
	}
	vibeSignIns.sessions[session.ID] = session
	vibeSignIns.Unlock()
	respondJSON(w, map[string]any{"session_id": session.ID, "oauth_url": process.URL, "expires_at": session.ExpiresAt})
}

func (h *proxyHandler) vibeSignInStatus(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SessionID string `json:"session_id"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil || input.SessionID == "" {
		respondJSONError(w, http.StatusBadRequest, "A sign-in session is required")
		return
	}
	vibeSignIns.Lock()
	session := vibeSignIns.sessions[input.SessionID]
	vibeSignIns.Unlock()
	if session == nil {
		respondJSONError(w, http.StatusNotFound, "Sign-in session expired. Start again")
		return
	}
	if session.ActorID != providerContributionActor(r) {
		respondJSONError(w, http.StatusForbidden, "This sign-in belongs to another account")
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.Status == "pending" && !session.ExpiresAt.After(time.Now()) {
		session.Status = "expired"
		session.Verifier = ""
	}
	if session.Status == "pending" {
		if err := h.advanceVibeSignIn(r, session); err != nil {
			session.Status = "error"
			session.Error = err.Error()
			session.Verifier = ""
		}
	}
	respondJSON(w, map[string]any{"status": session.Status, "account_id": session.AccountID, "error": session.Error})
}

func (h *proxyHandler) advanceVibeSignIn(r *http.Request, session *vibeSignInSession) error {
	var status struct {
		Status string `json:"status"`
		Token  string `json:"exchange_token"`
	}
	if err := h.vibeJSON(r.Context(), http.MethodGet, session.PollURL, nil, "", &status); err != nil {
		if errors.Is(err, errVibeExpired) {
			session.Status = "expired"
			session.Verifier = ""
			return nil
		}
		return err
	}
	switch status.Status {
	case "pending":
		return nil
	case "expired", "denied":
		session.Status = status.Status
		session.Verifier = ""
		return nil
	case "completed":
	default:
		return errors.New("Mistral sign-in failed. Start again")
	}
	if status.Token == "" {
		return errors.New("Mistral sign-in returned no exchange token")
	}
	var credential struct {
		APIKey string `json:"api_key"`
	}
	target := vibeConsoleURL + "/api/vibe/sign-in/" + session.ProcessID + "/exchange"
	payload := map[string]string{"exchange_token": status.Token, "code_verifier": session.Verifier}
	if err := h.vibeJSON(r.Context(), http.MethodPost, target, payload, "", &credential); err != nil {
		return err
	}
	session.Verifier = ""
	if strings.TrimSpace(credential.APIKey) == "" {
		return errors.New("Mistral sign-in returned no credential")
	}
	info, err := h.vibeAccountInfo(r.Context(), credential.APIKey)
	if err != nil {
		return err
	}
	provider := h.registry.ForType(AccountTypeMistralVibe)
	if provider == nil {
		return errors.New("Mistral Vibe is not configured")
	}
	account := &Account{Type: AccountTypeMistralVibe, AccessToken: credential.APIKey}
	ctx, cancel := context.WithTimeout(r.Context(), vibeHTTPTimeout)
	defer cancel()
	snapshot, err := fetchProviderModels(ctx, h.transport, provider, account)
	if err != nil {
		return errors.New("Could not load Mistral models. Sign in again")
	}
	id, err := h.writeAPIKeyAccount(AccountTypeMistralVibe, "mistral_vibe", credential.APIKey, map[string]any{"vibe_account": info, "provider_model_snapshot": snapshot})
	if err != nil {
		return errors.New("Could not save this account. Sign in again")
	}
	h.reloadAccounts()
	h.auditProviderContribution(r, string(AccountTypeMistralVibe), id)
	session.AccountID = id
	session.Status = "complete"
	return nil
}
