package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// ClaudeAuth provides OAuth functionality for Anthropic Claude accounts.
// Based on the opencode project's auth implementation.

const (
	ClaudeOAuthClientID    = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	ClaudeOAuthRedirectURI = "https://console.anthropic.com/oauth/code/callback"
	ClaudeOAuthTokenURL    = "https://console.anthropic.com/v1/oauth/token"
	ClaudeOAuthAuthorizeURL = "https://claude.ai/oauth/authorize"
)

// PKCE contains the code verifier and challenge for OAuth PKCE flow.
type PKCE struct {
	Verifier  string
	Challenge string
}

// GeneratePKCE generates a PKCE code verifier and challenge.
func GeneratePKCE() (*PKCE, error) {
	// Generate 32 random bytes for verifier
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return nil, fmt.Errorf("generate verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	// Generate SHA256 challenge
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return &PKCE{
		Verifier:  verifier,
		Challenge: challenge,
	}, nil
}

// ClaudeOAuthSession stores the state for an in-progress OAuth flow.
type ClaudeOAuthSession struct {
	PKCE      *PKCE
	CreatedAt time.Time
	AccountID string // Optional: identifier for this account
}

// ClaudeAuthorize generates the OAuth authorization URL.
// Returns the URL to redirect the user to and the PKCE session to store.
func ClaudeAuthorize(accountID string) (string, *ClaudeOAuthSession, error) {
	pkce, err := GeneratePKCE()
	if err != nil {
		return "", nil, err
	}

	u, _ := url.Parse(ClaudeOAuthAuthorizeURL)
	q := u.Query()
	q.Set("code", "true")
	q.Set("client_id", ClaudeOAuthClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", ClaudeOAuthRedirectURI)
	q.Set("scope", "org:create_api_key user:profile user:inference")
	q.Set("code_challenge", pkce.Challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", pkce.Verifier)
	u.RawQuery = q.Encode()

	session := &ClaudeOAuthSession{
		PKCE:      pkce,
		CreatedAt: time.Now(),
		AccountID: accountID,
	}

	return u.String(), session, nil
}

// ClaudeTokenResponse is the response from the OAuth token endpoint.
type ClaudeTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

// ClaudeExchange exchanges an authorization code for tokens.
func ClaudeExchange(code, verifier string) (*ClaudeTokenResponse, error) {
	// The code format from Anthropic is: code#state
	// We need to split it and use just the code part
	codeOnly := code
	state := ""
	if idx := indexOf(code, '#'); idx >= 0 {
		codeOnly = code[:idx]
		state = code[idx+1:]
	}

	body := map[string]string{
		"code":          codeOnly,
		"grant_type":    "authorization_code",
		"client_id":     ClaudeOAuthClientID,
		"redirect_uri":  ClaudeOAuthRedirectURI,
		"code_verifier": verifier,
	}
	if state != "" {
		body["state"] = state
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, ClaudeOAuthTokenURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("exchange failed: %s: %s", resp.Status, string(respBody))
	}

	var result ClaudeTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

// ClaudeRefresh refreshes an access token using the refresh token.
func ClaudeRefresh(refreshToken string) (*ClaudeTokenResponse, error) {
	body := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     ClaudeOAuthClientID,
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, ClaudeOAuthTokenURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("refresh failed: %s: %s", resp.Status, string(respBody))
	}

	var result ClaudeTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

// SaveClaudeAccount saves a Claude OAuth account to the pool directory.
func SaveClaudeAccount(poolDir, accountID string, tokens *ClaudeTokenResponse) error {
	claudeDir := filepath.Join(poolDir, "claude")
	if err := os.MkdirAll(claudeDir, 0700); err != nil {
		return fmt.Errorf("create claude dir: %w", err)
	}

	filename := accountID + ".json"
	path := filepath.Join(claudeDir, filename)

	data := ClaudeAuthJSON{
		ClaudeAiOauth: &ClaudeOAuthData{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
			ExpiresAt:    time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second).UnixMilli(),
			Scopes:       parseScopes(tokens.Scope),
		},
	}

	return atomicWriteJSON(path, data)
}

// saveClaudeAccount persists a Claude OAuth account back to its JSON file.
func saveClaudeAccount(a *Account) error {
	// Read existing file to preserve any extra fields
	raw, err := os.ReadFile(a.File)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	var root map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &root); err != nil {
			return fmt.Errorf("parse %s: %w", a.File, err)
		}
	} else {
		root = make(map[string]any)
	}

	// Update OAuth data
	oauth := map[string]any{
		"accessToken":  a.AccessToken,
		"refreshToken": a.RefreshToken,
		"expiresAt":    a.ExpiresAt.UnixMilli(),
	}

	// Preserve existing fields like scopes, subscriptionType
	if existing, ok := root["claudeAiOauth"].(map[string]any); ok {
		if scopes, ok := existing["scopes"]; ok {
			oauth["scopes"] = scopes
		}
		if subType, ok := existing["subscriptionType"]; ok {
			oauth["subscriptionType"] = subType
		}
		if tier, ok := existing["rateLimitTier"]; ok {
			oauth["rateLimitTier"] = tier
		}
	}

	root["claudeAiOauth"] = oauth

	// Save last_refresh at root level for rate limiting across restarts
	if !a.LastRefresh.IsZero() {
		root["last_refresh"] = a.LastRefresh.UTC().Format(time.RFC3339Nano)
	}

	return atomicWriteJSON(a.File, root)
}

// RefreshClaudeAccountTokens refreshes tokens for a Claude account and updates it.
func RefreshClaudeAccountTokens(acc *Account) error {
	if acc.RefreshToken == "" {
		return errors.New("no refresh token")
	}

	tokens, err := ClaudeRefresh(acc.RefreshToken)
	if err != nil {
		return err
	}

	acc.mu.Lock()
	acc.AccessToken = tokens.AccessToken
	if tokens.RefreshToken != "" {
		acc.RefreshToken = tokens.RefreshToken
	}
	acc.ExpiresAt = time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
	acc.LastRefresh = time.Now().UTC()
	acc.Dead = false
	acc.mu.Unlock()

	return saveClaudeAccount(acc)
}

func indexOf(s string, c rune) int {
	for i, r := range s {
		if r == c {
			return i
		}
	}
	return -1
}

func parseScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	var scopes []string
	start := 0
	for i, c := range scope {
		if c == ' ' {
			if i > start {
				scopes = append(scopes, scope[start:i])
			}
			start = i + 1
		}
	}
	if start < len(scope) {
		scopes = append(scopes, scope[start:])
	}
	return scopes
}
