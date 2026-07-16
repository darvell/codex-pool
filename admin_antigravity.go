package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	antigravityOAuthAuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
	antigravityOAuthCallbackURL  = "http://localhost:51121/oauth-callback"
)

var antigravityOAuthScopes = []string{
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
	"https://www.googleapis.com/auth/cclog",
	"https://www.googleapis.com/auth/experimentsandconfigs",
}

type antigravityOAuthSession struct {
	ID           string
	State        string
	Verifier     string
	CreatedAt    time.Time
	Status       string
	AccountID    string
	Error        string
	RedirectURI  string
	TargetOrigin string
}

var antigravityOAuthSessions = struct {
	sync.Mutex
	byID    map[string]*antigravityOAuthSession
	byState map[string]*antigravityOAuthSession
}{byID: make(map[string]*antigravityOAuthSession), byState: make(map[string]*antigravityOAuthSession)}

func newAntigravityOAuthSession() (*antigravityOAuthSession, error) {
	random := func(size int) (string, error) {
		buffer := make([]byte, size)
		if _, err := rand.Read(buffer); err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(buffer), nil
	}
	id, err := random(24)
	if err != nil {
		return nil, err
	}
	state, err := random(32)
	if err != nil {
		return nil, err
	}
	verifier, err := random(48)
	if err != nil {
		return nil, err
	}
	return &antigravityOAuthSession{ID: id, State: state, Verifier: verifier, CreatedAt: time.Now(), Status: "pending"}, nil
}

func antigravityOAuthRedirectURI() string {
	if value := strings.TrimSpace(os.Getenv("ANTIGRAVITY_OAUTH_REDIRECT_URI")); value != "" {
		return value
	}
	return antigravityOAuthCallbackURL
}

func (h *proxyHandler) handleAntigravityAdd(w http.ResponseWriter, r *http.Request) {
	clientID := antigravityOAuthClientID()
	if clientID == "" {
		respondJSONError(w, http.StatusServiceUnavailable, "Antigravity OAuth is not configured.")
		return
	}
	redirectURI := antigravityOAuthRedirectURI()
	session, err := newAntigravityOAuthSession()
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "failed to create OAuth session")
		return
	}
	session.RedirectURI = redirectURI
	session.TargetOrigin = antigravityOAuthTargetOrigin(r, h)
	challenge := sha256.Sum256([]byte(session.Verifier))
	u, _ := url.Parse(antigravityOAuthAuthorizeURL)
	query := u.Query()
	query.Set("response_type", "code")
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", strings.Join(antigravityOAuthScopes, " "))
	query.Set("access_type", "offline")
	query.Set("prompt", "consent")
	query.Set("state", session.State)
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	query.Set("code_challenge_method", "S256")
	u.RawQuery = query.Encode()
	antigravityOAuthSessions.Lock()
	antigravityOAuthSessions.byID[session.ID] = session
	antigravityOAuthSessions.byState[session.State] = session
	for id, candidate := range antigravityOAuthSessions.byID {
		if time.Since(candidate.CreatedAt) > 30*time.Minute {
			delete(antigravityOAuthSessions.byID, id)
			delete(antigravityOAuthSessions.byState, candidate.State)
		}
	}
	antigravityOAuthSessions.Unlock()
	callbackMode := "public"
	if isAntigravityLoopbackRedirect(redirectURI) {
		callbackMode = "manual"
		if err := ensureAntigravityLoopbackListener(h, redirectURI); err == nil {
			callbackMode = "automatic"
		}
	}
	respondJSON(w, map[string]any{"oauth_url": u.String(), "session_id": session.ID, "state": session.State, "callback_mode": callbackMode})
}

func (h *proxyHandler) handleAntigravityStatus(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		respondJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	antigravityOAuthSessions.Lock()
	session := antigravityOAuthSessions.byID[input.SessionID]
	var status, accountID, sessionError string
	if session != nil {
		status, accountID, sessionError = session.Status, session.AccountID, session.Error
	}
	antigravityOAuthSessions.Unlock()
	if session == nil || time.Since(session.CreatedAt) > 30*time.Minute {
		respondJSONError(w, http.StatusNotFound, "OAuth session expired")
		return
	}
	respondJSON(w, map[string]any{"status": status, "account_id": accountID, "error": sessionError})
}

func (h *proxyHandler) handleAntigravityExchange(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SessionID   string `json:"session_id"`
		Code        string `json:"code"`
		CallbackURL string `json:"callback_url"`
		State       string `json:"state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		respondJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	antigravityOAuthSessions.Lock()
	session := antigravityOAuthSessions.byID[input.SessionID]
	antigravityOAuthSessions.Unlock()
	if session == nil || time.Since(session.CreatedAt) > 30*time.Minute {
		respondJSONError(w, http.StatusBadRequest, "invalid or expired OAuth session")
		return
	}
	code := strings.TrimSpace(input.Code)
	if strings.TrimSpace(input.CallbackURL) != "" {
		callback, err := url.Parse(strings.TrimSpace(input.CallbackURL))
		if err != nil || callback.Query().Get("state") != session.State {
			respondJSONError(w, http.StatusBadRequest, "callback state does not match the OAuth session")
			return
		}
		code = callback.Query().Get("code")
	} else if strings.TrimSpace(input.State) != session.State {
		respondJSONError(w, http.StatusBadRequest, "state is required when submitting a raw authorization code")
		return
	}
	if code == "" {
		respondJSONError(w, http.StatusBadRequest, "authorization code is required")
		return
	}
	accountID, err := h.completeAntigravityOAuth(r.Context(), session, code)
	if err != nil {
		respondJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	respondJSON(w, map[string]any{"success": true, "account_id": accountID})
}

func (h *proxyHandler) handleAntigravityCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	antigravityOAuthSessions.Lock()
	session := antigravityOAuthSessions.byState[state]
	antigravityOAuthSessions.Unlock()
	if session == nil || time.Since(session.CreatedAt) > 30*time.Minute {
		h.renderAntigravityCallback(w, nil, "error", "", "invalid or expired OAuth state")
		return
	}
	if upstreamError := strings.TrimSpace(r.URL.Query().Get("error")); upstreamError != "" {
		antigravityOAuthSessions.Lock()
		session.Status, session.Error = "error", upstreamError
		antigravityOAuthSessions.Unlock()
		h.renderAntigravityCallback(w, session, "error", "", upstreamError)
		return
	}
	accountID, err := h.completeAntigravityOAuth(r.Context(), session, strings.TrimSpace(r.URL.Query().Get("code")))
	if err != nil {
		h.renderAntigravityCallback(w, session, "error", "", err.Error())
		return
	}
	h.renderAntigravityCallback(w, session, "complete", accountID, "")
}

func (h *proxyHandler) renderAntigravityCallback(w http.ResponseWriter, session *antigravityOAuthSession, status, accountID, message string) {
	sessionID, targetOrigin := "", "*"
	if session != nil {
		sessionID = session.ID
		if session.TargetOrigin != "" {
			targetOrigin = session.TargetOrigin
		}
	}
	payload, _ := json.Marshal(map[string]string{
		"type": "codex-pool-antigravity-oauth", "session_id": sessionID,
		"status": status, "account_id": accountID, "error": message,
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	encodedPayload := base64.StdEncoding.EncodeToString(payload)
	_, _ = fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>Antigravity sign-in</title><p>%s</p><script>const payload=JSON.parse(atob(%q));if(window.opener){window.opener.postMessage(payload,%q)}window.close()</script>`, template.HTMLEscapeString(status), encodedPayload, targetOrigin)
}

var antigravityLoopback = struct {
	sync.Mutex
	listeners map[string]net.Listener
}{listeners: make(map[string]net.Listener)}

func isAntigravityLoopbackRedirect(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	hostname := strings.ToLower(parsed.Hostname())
	return parsed.Scheme == "http" && (hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1")
}

func antigravityOAuthTargetOrigin(r *http.Request, h *proxyHandler) string {
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		if parsed, err := url.Parse(origin); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" {
			return parsed.Scheme + "://" + parsed.Host
		}
	}
	if h != nil {
		if parsed, err := url.Parse(h.getEffectivePublicURL(r)); err == nil && parsed.Host != "" {
			return parsed.Scheme + "://" + parsed.Host
		}
	}
	return ""
}

func ensureAntigravityLoopbackListener(h *proxyHandler, rawRedirect string) error {
	parsed, err := url.Parse(rawRedirect)
	if err != nil || !isAntigravityLoopbackRedirect(rawRedirect) || parsed.Port() == "" {
		return errors.New("Antigravity OAuth redirect is not a loopback URL with a port")
	}
	key := parsed.Host
	antigravityLoopback.Lock()
	defer antigravityLoopback.Unlock()
	if antigravityLoopback.listeners[key] != nil {
		return nil
	}
	address := net.JoinHostPort("127.0.0.1", parsed.Port())
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc(parsed.Path, h.handleAntigravityCallback)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	antigravityLoopback.listeners[key] = listener
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			// The status poll and manual callback paste remain available if the listener exits.
		}
		antigravityLoopback.Lock()
		delete(antigravityLoopback.listeners, key)
		antigravityLoopback.Unlock()
	}()
	return nil
}

type antigravityTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
}

func (h *proxyHandler) completeAntigravityOAuth(ctx context.Context, session *antigravityOAuthSession, code string) (string, error) {
	if code == "" {
		return "", errors.New("Google callback did not contain an authorization code")
	}
	antigravityOAuthSessions.Lock()
	if session.Status == "complete" {
		accountID := session.AccountID
		antigravityOAuthSessions.Unlock()
		return accountID, nil
	}
	if session.Status == "exchanging" {
		antigravityOAuthSessions.Unlock()
		return "", errors.New("OAuth session is already being exchanged")
	}
	session.Status = "exchanging"
	antigravityOAuthSessions.Unlock()

	fail := func(err error) (string, error) {
		antigravityOAuthSessions.Lock()
		session.Status, session.Error = "error", err.Error()
		antigravityOAuthSessions.Unlock()
		return "", err
	}
	token, err := h.exchangeAntigravityCode(ctx, code, session.Verifier, session.RedirectURI)
	if err != nil {
		return fail(err)
	}
	email, err := h.fetchAntigravityEmail(ctx, token.AccessToken)
	if err != nil {
		return fail(err)
	}
	projectID, planType, err := h.discoverAntigravityProject(ctx, token.AccessToken)
	if err != nil {
		return fail(err)
	}
	accountID := safeAntigravityAccountID(email)
	if token.ExpiresIn <= 0 {
		token.ExpiresIn = 3600
	}
	file := filepath.Join(h.cfg.poolDir, "antigravity", accountID+".json")
	account := &Account{
		Type: AccountTypeAntigravity, ID: accountID, File: file, Email: email,
		ProjectID: projectID, AccessToken: token.AccessToken, RefreshToken: token.RefreshToken,
		PlanType: planType, ExpiresAt: time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
		LastRefresh: time.Now().UTC(), AddedAt: time.Now().UTC(), ModelRateLimits: make(map[string]time.Time),
	}
	provider, _ := h.registry.ForType(AccountTypeAntigravity).(*AntigravityProvider)
	if provider == nil {
		return fail(errors.New("Antigravity provider is not configured"))
	}
	syncCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	snapshot, err := fetchAntigravityModels(syncCtx, h.transport, account, provider.DailyURL(), provider.ProductionURL())
	cancel()
	if err != nil {
		return fail(fmt.Errorf("model discovery failed: %w", err))
	}
	antigravityModels.ReplaceAccount(account.ID, snapshot)
	if err := saveAntigravityAccount(account); err != nil {
		return fail(fmt.Errorf("save Antigravity account: %w", err))
	}
	h.reloadAccounts()
	antigravityOAuthSessions.Lock()
	session.Status, session.AccountID, session.Error = "complete", accountID, ""
	antigravityOAuthSessions.Unlock()
	return accountID, nil
}

func (h *proxyHandler) exchangeAntigravityCode(ctx context.Context, code, verifier, redirectURI string) (antigravityTokenResponse, error) {
	clientID := antigravityOAuthClientID()
	if clientID == "" {
		return antigravityTokenResponse{}, errors.New("antigravity OAuth client ID is not configured")
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code":          {code},
		"code_verifier": {verifier},
	}
	if secret := antigravityOAuthClientSecret(); secret != "" {
		form.Set("client_secret", secret)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, antigravityOAuthTokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return antigravityTokenResponse{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return antigravityTokenResponse{}, fmt.Errorf("Google token exchange failed: %s: %s", resp.Status, safeText(body))
	}
	var token antigravityTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return token, err
	}
	if token.AccessToken == "" || token.RefreshToken == "" {
		return token, errors.New("Google token exchange did not return access and refresh tokens")
	}
	return token, nil
}

func (h *proxyHandler) fetchAntigravityEmail(ctx context.Context, accessToken string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var profile struct {
		Email string `json:"email"`
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&profile) != nil || profile.Email == "" {
		return "", fmt.Errorf("Google userinfo failed: %s", resp.Status)
	}
	return profile.Email, nil
}

func (h *proxyHandler) discoverAntigravityProject(ctx context.Context, accessToken string) (string, string, error) {
	payload := map[string]any{"metadata": map[string]any{"ideType": "ANTIGRAVITY"}}
	root, err := h.callAntigravityInternal(ctx, accessToken, h.cfg.antigravityProdBase, "/v1internal:loadCodeAssist", payload)
	if err != nil {
		return "", "", err
	}
	projectID := antigravityLoadProjectID(root)
	plan := findAntigravityTierID(root)
	if projectID != "" {
		return projectID, plan, nil
	}
	tierID := findDefaultAntigravityTier(root)
	if tierID == "" {
		return "", "", errors.New("Google did not return a project or an allowed onboarding tier")
	}
	for attempt := 0; attempt < 5; attempt++ {
		onboard := map[string]any{
			"tier_id": tierID,
			"metadata": map[string]any{
				"ide_type": "ANTIGRAVITY", "ide_name": "antigravity", "ide_version": antigravityClientVersion(),
			},
		}
		result, callErr := h.callAntigravityInternal(ctx, accessToken, h.cfg.antigravityOnboardBase, "/v1internal:onboardUser", onboard)
		if callErr == nil {
			if projectID = antigravityOnboardProjectID(result); projectID != "" {
				return projectID, tierID, nil
			}
		}
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return "", "", errors.New("Google Antigravity project onboarding did not complete")
}

func (h *proxyHandler) callAntigravityInternal(ctx context.Context, accessToken string, base *url.URL, path string, payload any) (map[string]any, error) {
	body, _ := json.Marshal(payload)
	u := *base
	u.Path = singleJoin(u.Path, path)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	if strings.HasSuffix(path, ":onboardUser") {
		req.Header.Set("User-Agent", antigravityOnboardUserAgent())
		req.Header.Set("X-Goog-Api-Client", "gl-node/22.21.1")
	} else {
		req.Header.Set("User-Agent", antigravityUserAgent())
	}
	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s failed: %s: %s", path, resp.Status, safeText(responseBody))
	}
	var result map[string]any
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func antigravityLoadProjectID(root map[string]any) string {
	for _, key := range []string{"cloudaicompanionProject", "projectId", "project"} {
		switch value := root[key].(type) {
		case string:
			if value != "" {
				return value
			}
		case map[string]any:
			if id, _ := value["id"].(string); id != "" {
				return id
			}
		}
	}
	return ""
}

func antigravityOnboardProjectID(root map[string]any) string {
	done, _ := root["done"].(bool)
	if !done {
		return ""
	}
	response, _ := root["response"].(map[string]any)
	return antigravityLoadProjectID(response)
}

func findDefaultAntigravityTier(root map[string]any) string {
	items, _ := root["allowedTiers"].([]any)
	for _, item := range items {
		tier, _ := item.(map[string]any)
		if preferred, _ := tier["isDefault"].(bool); preferred {
			if id, _ := tier["id"].(string); id != "" {
				return id
			}
		}
	}
	if current, ok := root["currentTier"].(map[string]any); ok {
		if id, _ := current["id"].(string); id != "" {
			return id
		}
	}
	return "free-tier"
}

func findAntigravityTierID(root map[string]any) string {
	for _, key := range []string{"paidTier", "currentTier"} {
		if tier, ok := root[key].(map[string]any); ok {
			if id, _ := tier["id"].(string); id != "" {
				return id
			}
		}
	}
	return "antigravity"
}

var antigravityAccountIDPattern = regexp.MustCompile(`[^a-z0-9._-]+`)

func safeAntigravityAccountID(email string) string {
	id := antigravityAccountIDPattern.ReplaceAllString(strings.ToLower(strings.TrimSpace(email)), "-")
	id = strings.Trim(id, "-.")
	if id == "" {
		return "antigravity-" + randomID()
	}
	return "antigravity-" + id
}

func (h *proxyHandler) handleAntigravityModelSync(w http.ResponseWriter, r *http.Request) {
	provider, _ := h.registry.ForType(AccountTypeAntigravity).(*AntigravityProvider)
	if provider == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "Antigravity provider is not configured")
		return
	}
	type result struct {
		AccountID string `json:"account_id"`
		Error     string `json:"error,omitempty"`
	}
	results := make([]result, 0)
	for _, account := range h.pool.allAccounts() {
		if account.Type != AccountTypeAntigravity {
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		err := syncAntigravityModels(ctx, h.transport, account, provider.DailyURL(), provider.ProductionURL())
		cancel()
		entry := result{AccountID: account.ID}
		if err != nil {
			entry.Error = err.Error()
		}
		results = append(results, entry)
	}
	respondJSON(w, map[string]any{"accounts": results, "models": antigravityModels.Models(h.pool)})
}

func (h *proxyHandler) handleAntigravityModelVerify(w http.ResponseWriter, r *http.Request) {
	provider, _ := h.registry.ForType(AccountTypeAntigravity).(*AntigravityProvider)
	if provider == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "Antigravity provider is not configured")
		return
	}
	type verification struct {
		Model     string `json:"model"`
		AccountID string `json:"account_id,omitempty"`
		Status    int    `json:"status"`
		LatencyMS int64  `json:"latency_ms"`
		Error     string `json:"error,omitempty"`
	}
	requested := strings.TrimSpace(r.URL.Query().Get("model"))
	models := antigravityModels.Models(h.pool)
	results := make([]verification, 0, len(models))
	for _, model := range models {
		if requested != "" && requested != model.ID && requested != "antigravity/"+model.ID {
			continue
		}
		entry := verification{Model: model.ID}
		account := h.pool.candidateForAntigravityModel("", nil, model.ID, getClientIP(r))
		if account == nil {
			entry.Error = "no available account supports this model"
			results = append(results, entry)
			continue
		}
		entry.AccountID = account.ID
		account.mu.Lock()
		projectID := account.ProjectID
		account.mu.Unlock()
		requestBody := []byte(`{"contents":[{"role":"user","parts":[{"text":"Reply with OK."}]}]}`)
		prepared, err := prepareAntigravityRequest("/v1beta/models/"+model.ID+":generateContent", requestBody, "antigravity/"+model.ID, projectID, "")
		if err != nil {
			entry.Error = err.Error()
			results = append(results, entry)
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		started := time.Now()
		resp, err := h.doAntigravityRequest(ctx, nil, account, provider, prepared)
		entry.LatencyMS = time.Since(started).Milliseconds()
		if err != nil {
			entry.Error = err.Error()
			cancel()
			results = append(results, entry)
			continue
		}
		entry.Status = resp.StatusCode
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			_, _, err = collectAntigravitySSE(resp.Body)
			clearAntigravityModelCooldown(account, model.ID)
		} else {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			entry.Error = strings.TrimSpace(string(body))
			if resp.StatusCode == http.StatusTooManyRequests {
				if until, ok := parseAntigravityRetry(body, time.Now()); ok {
					setAntigravityModelCooldown(account, model.ID, until)
				}
			}
		}
		resp.Body.Close()
		cancel()
		if err != nil {
			entry.Error = err.Error()
		}
		results = append(results, entry)
	}
	respondJSON(w, map[string]any{"verified_at": time.Now().UTC(), "models": results})
}
