package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GeminiProvider handles Google Gemini accounts.
type GeminiProvider struct {
	geminiBase *url.URL
}

// NewGeminiProvider creates a new Gemini provider.
func NewGeminiProvider(geminiBase *url.URL) *GeminiProvider {
	return &GeminiProvider{
		geminiBase: geminiBase,
	}
}

func (p *GeminiProvider) Type() AccountType {
	return AccountTypeGemini
}

func (p *GeminiProvider) LoadAccount(name, path string, data []byte) (*Account, error) {
	// Only load files with gemini_ prefix
	if !strings.HasPrefix(name, "gemini_") {
		return nil, nil
	}

	var gj GeminiAuthJSON
	if err := json.Unmarshal(data, &gj); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if gj.AccessToken == "" {
		return nil, nil
	}
	acc := &Account{
		Type:         AccountTypeGemini,
		ID:           strings.TrimSuffix(name, filepath.Ext(name)),
		File:         path,
		AccessToken:  gj.AccessToken,
		RefreshToken: gj.RefreshToken,
		PlanType:     "gemini",
	}
	// expiry_date is Unix timestamp in milliseconds
	if gj.ExpiryDate > 0 {
		acc.ExpiresAt = time.UnixMilli(gj.ExpiryDate)
	}
	return acc, nil
}

func (p *GeminiProvider) SetAuthHeaders(req *http.Request, acc *Account) {
	// Gemini uses Bearer token
	req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
}

// Gemini OAuth token endpoint
const geminiOAuthTokenURL = "https://oauth2.googleapis.com/token"

// geminiOAuthClientID returns the OAuth client ID for Gemini.
// Uses GEMINI_OAUTH_CLIENT_ID env var if set, otherwise the public Gemini CLI client ID.
func geminiOAuthClientID() string {
	if v := os.Getenv("GEMINI_OAUTH_CLIENT_ID"); v != "" {
		return v
	}
	// Public client ID from Gemini CLI (safe per OAuth 2.0 spec for installed apps)
	return "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j" + ".apps.googleusercontent.com"
}

// geminiOAuthClientSecret returns the OAuth client secret for Gemini.
// Uses GEMINI_OAUTH_CLIENT_SECRET env var if set, otherwise the public Gemini CLI client secret.
func geminiOAuthClientSecret() string {
	if v := os.Getenv("GEMINI_OAUTH_CLIENT_SECRET"); v != "" {
		return v
	}
	// Public client secret from Gemini CLI (safe per OAuth 2.0 spec for installed apps)
	return "GOCSPX-" + "4uHgMPm-1o7Sk-geV6Cu5clXFsxl"
}

func (p *GeminiProvider) RefreshToken(ctx context.Context, acc *Account, transport *http.Transport) error {
	acc.mu.Lock()
	refreshTok := acc.RefreshToken
	acc.mu.Unlock()

	if refreshTok == "" {
		return errors.New("no refresh token")
	}

	// Google OAuth uses form-encoded body
	form := url.Values{}
	form.Set("client_id", geminiOAuthClientID())
	form.Set("client_secret", geminiOAuthClientSecret())
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshTok)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, geminiOAuthTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "codex-pool-proxy")

	resp, err := transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		if len(bytes.TrimSpace(msg)) > 0 {
			return fmt.Errorf("gemini refresh unauthorized: %s: %s", resp.Status, safeText(msg))
		}
		return fmt.Errorf("gemini refresh unauthorized: %s", resp.Status)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		if len(bytes.TrimSpace(msg)) > 0 {
			return fmt.Errorf("gemini refresh failed: %s: %s", resp.Status, safeText(msg))
		}
		return fmt.Errorf("gemini refresh failed: %s", resp.Status)
	}

	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"` // seconds until expiry
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if payload.AccessToken == "" {
		return errors.New("empty access token after gemini refresh")
	}

	acc.mu.Lock()
	acc.AccessToken = payload.AccessToken
	if payload.RefreshToken != "" {
		acc.RefreshToken = payload.RefreshToken
	}
	if payload.ExpiresIn > 0 {
		acc.ExpiresAt = time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second)
	}
	acc.LastRefresh = time.Now().UTC()
	acc.Dead = false
	acc.mu.Unlock()

	return saveAccount(acc)
}

func (p *GeminiProvider) ParseUsage(obj map[string]any) *RequestUsage {
	// Gemini format: {"usageMetadata": {"promptTokenCount": N, "candidatesTokenCount": N, "totalTokenCount": N, "cachedContentTokenCount": N}}
	usageMap, ok := obj["usageMetadata"].(map[string]any)
	if !ok || usageMap == nil {
		return nil
	}

	ru := &RequestUsage{Timestamp: time.Now()}
	ru.InputTokens = readInt64(usageMap, "promptTokenCount")
	ru.OutputTokens = readInt64(usageMap, "candidatesTokenCount")
	ru.CachedInputTokens = readInt64(usageMap, "cachedContentTokenCount")

	// Calculate billable tokens
	ru.BillableTokens = ru.InputTokens - ru.CachedInputTokens + ru.OutputTokens

	if ru.InputTokens == 0 && ru.OutputTokens == 0 {
		return nil
	}

	return ru
}

func (p *GeminiProvider) ParseUsageHeaders(acc *Account, headers http.Header) {
	// Gemini doesn't currently expose usage via response headers
	// This is a no-op for now
}

func (p *GeminiProvider) UpstreamURL() *url.URL {
	return p.geminiBase
}

func (p *GeminiProvider) MatchesPath(path string) bool {
	// Gemini paths: /v1internal:generateContent, /v1internal:streamGenerateContent, etc.
	return strings.HasPrefix(path, "/v1internal:")
}

func (p *GeminiProvider) NormalizePath(path string) string {
	// Gemini paths are already in the correct format
	return path
}

func (p *GeminiProvider) DetectsSSE(path string, contentType string) bool {
	// Gemini streaming uses streamGenerateContent
	return strings.Contains(path, "stream")
}
