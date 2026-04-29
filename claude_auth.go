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
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// ClaudeAuth provides OAuth functionality for Anthropic Claude accounts.
// Based on the opencode project's auth implementation.

const (
	ClaudeOAuthClientID      = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	ClaudeOAuthRedirectURI   = "https://platform.claude.com/oauth/code/callback"
	ClaudeOAuthTokenURL      = "https://platform.claude.com/v1/oauth/token"
	ClaudeOAuthAuthorizeURL  = "https://claude.com/cai/oauth/authorize"
	ClaudeOAuthProfileURL    = "https://api.anthropic.com/api/oauth/profile"
	ClaudeOAuthAllScopes     = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
	ClaudeOAuthRefreshScopes = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
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
	State     string
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

	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", nil, fmt.Errorf("generate state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	u, _ := url.Parse(ClaudeOAuthAuthorizeURL)
	q := u.Query()
	q.Set("code", "true")
	q.Set("client_id", ClaudeOAuthClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", ClaudeOAuthRedirectURI)
	q.Set("scope", ClaudeOAuthAllScopes)
	q.Set("code_challenge", pkce.Challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	u.RawQuery = q.Encode()

	session := &ClaudeOAuthSession{
		PKCE:      pkce,
		State:     state,
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
func ClaudeExchange(code, verifier, state string) (*ClaudeTokenResponse, error) {
	// Manual copy/paste can still provide code#state; prefer the explicit
	// session state from ClaudeAuthorize, but preserve compatibility.
	codeOnly := code
	if idx := indexOf(code, '#'); idx >= 0 {
		codeOnly = code[:idx]
		if state == "" {
			state = code[idx+1:]
		}
	}

	body := map[string]string{
		"code":          codeOnly,
		"grant_type":    "authorization_code",
		"client_id":     ClaudeOAuthClientID,
		"redirect_uri":  ClaudeOAuthRedirectURI,
		"code_verifier": verifier,
		"state":         state,
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
		"scope":         ClaudeOAuthRefreshScopes,
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

// ClaudeProfileInfo contains the plan info extracted from the OAuth profile API.
type ClaudeProfileInfo struct {
	SubscriptionType string // "max", "pro", "team", "enterprise", or ""
	RateLimitTier    string // e.g. "default_claude_max_20x"
}

// FetchClaudeProfile calls /api/oauth/profile to get the account's plan info.
func FetchClaudeProfile(accessToken string) (*ClaudeProfileInfo, error) {
	req, err := http.NewRequest(http.MethodGet, ClaudeOAuthProfileURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("anthropic-version", ccAnthropicVersion)
	req.Header.Set("anthropic-dangerous-direct-browser-access", "true")
	req.Header.Set("anthropic-beta", ccMinimalBetaHeader())
	req.Header.Set("User-Agent", ccClaudeCodeUserAgent())
	req.Header.Set("X-Claude-Code-Session-Id", ccAccountSessionID(accessToken))
	req.Header.Set("X-App", "cli")
	req.Header.Set("Accept", "application/json")
	ccStainlessHeaders(req.Header.Set)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("profile status=%s body=%s", resp.Status, string(body))
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	return extractProfileInfo(payload), nil
}

// extractProfileInfo extracts plan info from the OAuth profile response.
// The response has: organization.organization_type ("claude_max", "claude_pro", etc.)
// and organization.rate_limit_tier ("default_claude_max_20x", etc.)
func extractProfileInfo(profile map[string]any) *ClaudeProfileInfo {
	info := &ClaudeProfileInfo{}

	org, _ := profile["organization"].(map[string]any)
	if org == nil {
		return info
	}

	orgType, _ := org["organization_type"].(string)
	switch orgType {
	case "claude_max":
		info.SubscriptionType = "max"
	case "claude_pro":
		info.SubscriptionType = "pro"
	case "claude_enterprise":
		info.SubscriptionType = "enterprise"
	case "claude_team":
		info.SubscriptionType = "team"
	}

	info.RateLimitTier, _ = org["rate_limit_tier"].(string)
	return info
}

// SaveClaudeAccount saves a Claude OAuth account to the pool directory.
func SaveClaudeAccount(poolDir, accountID string, tokens *ClaudeTokenResponse) error {
	claudeDir := filepath.Join(poolDir, "claude")
	if err := os.MkdirAll(claudeDir, 0700); err != nil {
		return fmt.Errorf("create claude dir: %w", err)
	}

	filename := accountID + ".json"
	path := filepath.Join(claudeDir, filename)

	oauthData := &ClaudeOAuthData{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second).UnixMilli(),
		Scopes:       parseScopes(tokens.Scope),
	}

	// Fetch plan info from the profile API
	if profile, err := FetchClaudeProfile(tokens.AccessToken); err == nil && profile != nil {
		oauthData.SubscriptionType = profile.SubscriptionType
		oauthData.RateLimitTier = profile.RateLimitTier
		log.Printf("claude account %s: detected plan=%s tier=%s", accountID, profile.SubscriptionType, profile.RateLimitTier)
	} else if err != nil {
		log.Printf("claude account %s: failed to fetch profile: %v", accountID, err)
	}

	data := ClaudeAuthJSON{
		ClaudeAiOauth: oauthData,
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

	// Preserve existing fields like scopes, and carry forward subscriptionType/rateLimitTier
	if existing, ok := root["claudeAiOauth"].(map[string]any); ok {
		if scopes, ok := existing["scopes"]; ok {
			oauth["scopes"] = scopes
		}
		// Carry forward existing values as defaults
		if subType, ok := existing["subscriptionType"]; ok {
			oauth["subscriptionType"] = subType
		}
		if tier, ok := existing["rateLimitTier"]; ok {
			oauth["rateLimitTier"] = tier
		}
	}

	// Override with in-memory values if they're real (not the default "claude")
	if a.PlanType != "" && a.PlanType != "claude" {
		oauth["subscriptionType"] = a.PlanType
	}
	if a.RateLimitTier != "" {
		oauth["rateLimitTier"] = a.RateLimitTier
	}

	root["claudeAiOauth"] = oauth

	// Save last_refresh at root level for rate limiting across restarts
	if !a.LastRefresh.IsZero() {
		root["last_refresh"] = a.LastRefresh.UTC().Format(time.RFC3339Nano)
	}
	if len(a.AllowedSourceIPs) > 0 {
		root["allowed_source_ips"] = a.AllowedSourceIPs
		if len(a.AllowedSourceIPs) == 1 {
			root["allowed_ip"] = a.AllowedSourceIPs[0]
		} else {
			delete(root, "allowed_ip")
		}
	} else {
		delete(root, "allowed_source_ips")
		delete(root, "allowed_ip")
	}

	// Persist account state flags so disabled/dead accounts stay unavailable
	// across reloads and restarts.
	if a.Dead {
		root["dead"] = true
	} else {
		delete(root, "dead")
	}
	if a.Disabled {
		root["disabled"] = true
	} else {
		delete(root, "disabled")
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

	// Fetch updated plan info from the profile API
	if profile, err := FetchClaudeProfile(acc.AccessToken); err == nil && profile != nil {
		acc.mu.Lock()
		if profile.SubscriptionType != "" {
			acc.PlanType = profile.SubscriptionType
		}
		if profile.RateLimitTier != "" {
			acc.RateLimitTier = profile.RateLimitTier
		}
		acc.mu.Unlock()
		log.Printf("claude account %s: refreshed plan=%s tier=%s", acc.ID, profile.SubscriptionType, profile.RateLimitTier)
	} else if err != nil {
		log.Printf("claude account %s: failed to fetch profile on refresh: %v", acc.ID, err)
	}

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
