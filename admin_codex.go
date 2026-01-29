package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Codex OAuth constants (from codex-rs/login/src/server.rs)
const (
	CodexOAuthClientID     = "app_EMoamEEZ73f0CkXaXp7hrann"
	CodexOAuthRedirectURI  = "http://localhost:1455/auth/callback"
	CodexOAuthTokenURL     = "https://auth.openai.com/oauth/token"
	CodexOAuthAuthorizeURL = "https://auth.openai.com/oauth/authorize"
)

// CodexOAuthSession stores pending OAuth state
type CodexOAuthSession struct {
	AccountID string
	Verifier  string
	Challenge string
	State     string
	CreatedAt time.Time
}

// In-memory store for pending Codex OAuth sessions
var codexOAuthSessions = struct {
	sync.RWMutex
	sessions map[string]*CodexOAuthSession
}{sessions: make(map[string]*CodexOAuthSession)}

// CodexTokenResponse is the response from the token endpoint
type CodexTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// serveCodexAdmin routes Codex admin requests
func (h *proxyHandler) serveCodexAdmin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/codex")
	if path == "" {
		path = "/"
	}

	switch {
	case path == "/" && r.Method == http.MethodGet:
		h.handleCodexList(w, r)

	case path == "/add" && r.Method == http.MethodPost:
		h.handleCodexAdd(w, r)

	case path == "/exchange" && r.Method == http.MethodPost:
		h.handleCodexExchange(w, r)

	default:
		http.NotFound(w, r)
	}
}

// GET /admin/codex - list all Codex accounts
func (h *proxyHandler) handleCodexList(w http.ResponseWriter, r *http.Request) {
	accounts := h.pool.allAccounts()

	type accountInfo struct {
		ID          string    `json:"id"`
		PlanType    string    `json:"plan_type"`
		Dead        bool      `json:"dead"`
		Disabled    bool      `json:"disabled"`
		ExpiresAt   time.Time `json:"expires_at,omitempty"`
		LastRefresh time.Time `json:"last_refresh,omitempty"`
	}

	var result []accountInfo
	for _, acc := range accounts {
		if acc.Type == AccountTypeCodex {
			result = append(result, accountInfo{
				ID:          acc.ID,
				PlanType:    acc.PlanType,
				Dead:        acc.Dead,
				Disabled:    acc.Disabled,
				ExpiresAt:   acc.ExpiresAt,
				LastRefresh: acc.LastRefresh,
			})
		}
	}

	respondJSON(w, map[string]any{
		"accounts": result,
		"count":    len(result),
	})
}

// POST /admin/codex/add - start OAuth flow
func (h *proxyHandler) handleCodexAdd(w http.ResponseWriter, r *http.Request) {
	// Generate PKCE verifier and challenge
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		respondJSONError(w, http.StatusInternalServerError, "failed to generate verifier")
		return
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	challengeHash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	// Generate state
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		respondJSONError(w, http.StatusInternalServerError, "failed to generate state")
		return
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	// Build OAuth URL
	u, _ := url.Parse(CodexOAuthAuthorizeURL)
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", CodexOAuthClientID)
	q.Set("redirect_uri", CodexOAuthRedirectURI)
	q.Set("scope", "openid profile email offline_access")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("id_token_add_organizations", "true")
	q.Set("codex_cli_simplified_flow", "true")
	q.Set("state", state)
	q.Set("originator", "codex_cli_rs")
	u.RawQuery = q.Encode()

	// Store session
	session := &CodexOAuthSession{
		Verifier:  verifier,
		Challenge: challenge,
		State:     state,
		CreatedAt: time.Now(),
	}

	codexOAuthSessions.Lock()
	codexOAuthSessions.sessions[verifier] = session
	codexOAuthSessions.Unlock()

	// Clean up old sessions
	go cleanupOldCodexSessions()

	respondJSON(w, map[string]any{
		"oauth_url": u.String(),
		"verifier":  verifier,
		"state":     state,
	})
}

// POST /admin/codex/exchange - exchange OAuth code for tokens
func (h *proxyHandler) handleCodexExchange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code     string `json:"code"`
		Verifier string `json:"verifier"`
	}

	if r.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondJSONError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
	} else {
		req.Code = r.FormValue("code")
		req.Verifier = r.FormValue("verifier")
	}

	code := strings.TrimSpace(req.Code)
	verifier := strings.TrimSpace(req.Verifier)

	if code == "" || verifier == "" {
		respondJSONError(w, http.StatusBadRequest, "code and verifier are required")
		return
	}

	// Look up session
	codexOAuthSessions.RLock()
	_, ok := codexOAuthSessions.sessions[verifier]
	codexOAuthSessions.RUnlock()

	if !ok {
		respondJSONError(w, http.StatusBadRequest, "invalid or expired session")
		return
	}

	// Exchange code for tokens
	tokens, err := codexExchangeCode(code, verifier)
	if err != nil {
		log.Printf("Codex token exchange failed: %v", err)
		respondJSONError(w, http.StatusInternalServerError, "token exchange failed: "+err.Error())
		return
	}

	// Generate account ID from email in id_token
	accountID := generateCodexAccountID(tokens.IDToken)

	// Save the account
	poolDir := filepath.Join(h.cfg.poolDir, "codex")
	if err := saveNewCodexAccount(poolDir, accountID, tokens); err != nil {
		respondJSONError(w, http.StatusInternalServerError, "failed to save account: "+err.Error())
		return
	}

	// Remove session
	codexOAuthSessions.Lock()
	delete(codexOAuthSessions.sessions, verifier)
	codexOAuthSessions.Unlock()

	// Reload accounts
	h.reloadAccounts()

	respondJSON(w, map[string]any{
		"success":    true,
		"account_id": accountID,
	})
}

// codexExchangeCode exchanges an authorization code for tokens
func codexExchangeCode(code, verifier string) (*CodexTokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", CodexOAuthClientID)
	data.Set("code", code)
	data.Set("redirect_uri", CodexOAuthRedirectURI)
	data.Set("code_verifier", verifier)

	req, err := http.NewRequest(http.MethodPost, CodexOAuthTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s: %s", resp.Status, string(body))
	}

	var tokens CodexTokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokens.AccessToken == "" {
		return nil, fmt.Errorf("empty access token in response")
	}

	return &tokens, nil
}

// generateCodexAccountID generates an account ID from the id_token email
func generateCodexAccountID(idToken string) string {
	// Parse JWT to get email
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return fmt.Sprintf("codex_%d", time.Now().Unix())
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Sprintf("codex_%d", time.Now().Unix())
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return fmt.Sprintf("codex_%d", time.Now().Unix())
	}

	// Try to get email from profile claim
	email := ""
	if profile, ok := payload["https://api.openai.com/profile"].(map[string]interface{}); ok {
		if e, ok := profile["email"].(string); ok {
			email = e
		}
	}
	if email == "" {
		if e, ok := payload["email"].(string); ok {
			email = e
		}
	}

	if email == "" {
		return fmt.Sprintf("codex_%d", time.Now().Unix())
	}

	// Extract meaningful part from email
	// e.g., "dlssnetsec+1@gmail.com" -> "dlss_1"
	// e.g., "foo@bar.com" -> "foo"
	localPart := strings.Split(email, "@")[0]

	// Handle plus aliases: user+alias -> user_alias
	localPart = strings.ReplaceAll(localPart, "+", "_")

	// Truncate long prefixes, keep suffix
	// e.g., "dlssnetsec_1" -> "dlss_1"
	re := regexp.MustCompile(`^([a-zA-Z]{1,4})[a-zA-Z]*(_\d+)?$`)
	if matches := re.FindStringSubmatch(localPart); len(matches) > 0 {
		result := matches[1]
		if len(matches) > 2 && matches[2] != "" {
			result += matches[2]
		}
		return result
	}

	// Fallback: just use first 8 chars of local part
	if len(localPart) > 8 {
		localPart = localPart[:8]
	}
	return localPart
}

// saveNewCodexAccount saves a new Codex account to the pool directory
func saveNewCodexAccount(poolDir, accountID string, tokens *CodexTokenResponse) error {
	// Ensure pool directory exists
	if err := os.MkdirAll(poolDir, 0755); err != nil {
		return fmt.Errorf("create pool dir: %w", err)
	}

	filePath := filepath.Join(poolDir, accountID+".json")

	// Check if file already exists
	if _, err := os.Stat(filePath); err == nil {
		// File exists, append a number
		for i := 2; i <= 99; i++ {
			newPath := filepath.Join(poolDir, fmt.Sprintf("%s_%d.json", accountID, i))
			if _, err := os.Stat(newPath); os.IsNotExist(err) {
				filePath = newPath
				accountID = fmt.Sprintf("%s_%d", accountID, i)
				break
			}
		}
	}

	authJSON := map[string]any{
		"tokens": map[string]any{
			"id_token":      tokens.IDToken,
			"access_token":  tokens.AccessToken,
			"refresh_token": tokens.RefreshToken,
		},
	}

	data, err := json.MarshalIndent(authJSON, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	log.Printf("Saved new Codex account: %s -> %s", accountID, filePath)
	return nil
}

func cleanupOldCodexSessions() {
	codexOAuthSessions.Lock()
	defer codexOAuthSessions.Unlock()

	now := time.Now()
	for verifier, session := range codexOAuthSessions.sessions {
		if now.Sub(session.CreatedAt) > 10*time.Minute {
			delete(codexOAuthSessions.sessions, verifier)
		}
	}
}
