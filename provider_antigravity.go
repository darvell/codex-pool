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
	"sync"
	"time"
)

const antigravityOAuthTokenURL = "https://oauth2.googleapis.com/token"

var (
	antigravityPublicClientIDXOR     = []byte{0x6b, 0x6a, 0x6d, 0x6b, 0x6a, 0x6a, 0x6c, 0x6a, 0x6c, 0x6a, 0x6f, 0x63, 0x6b, 0x77, 0x2e, 0x37, 0x32, 0x29, 0x29, 0x33, 0x34, 0x68, 0x32, 0x68, 0x6b, 0x36, 0x39, 0x28, 0x3f, 0x68, 0x69, 0x6f, 0x2c, 0x2e, 0x35, 0x36, 0x35, 0x30, 0x32, 0x6e, 0x3d, 0x6e, 0x6a, 0x69, 0x3f, 0x2a, 0x74, 0x3b, 0x2a, 0x2a, 0x29, 0x74, 0x3d, 0x35, 0x35, 0x3d, 0x36, 0x3f, 0x2f, 0x29, 0x3f, 0x28, 0x39, 0x35, 0x34, 0x2e, 0x3f, 0x34, 0x2e, 0x74, 0x39, 0x35, 0x37}
	antigravityPublicClientSecretXOR = []byte{0x1d, 0x15, 0x19, 0x09, 0x0a, 0x02, 0x77, 0x11, 0x6f, 0x62, 0x1c, 0x0d, 0x08, 0x6e, 0x62, 0x6c, 0x16, 0x3e, 0x16, 0x10, 0x6b, 0x37, 0x16, 0x18, 0x62, 0x29, 0x02, 0x19, 0x6e, 0x20, 0x6c, 0x2b, 0x1e, 0x1b, 0x3c}
)

// AntigravityProvider handles subscription accounts used by Google's
// Antigravity CLI. It is intentionally separate from Gemini API-key accounts.
type AntigravityProvider struct {
	dailyBase *url.URL
	prodBase  *url.URL
}

var antigravityAccountSaveLocks sync.Map

func NewAntigravityProvider(dailyBase, prodBase *url.URL) *AntigravityProvider {
	return &AntigravityProvider{dailyBase: dailyBase, prodBase: prodBase}
}

func (p *AntigravityProvider) Type() AccountType { return AccountTypeAntigravity }

func (p *AntigravityProvider) LoadAccount(name, path string, data []byte) (*Account, error) {
	var auth AntigravityAuthJSON
	if err := json.Unmarshal(data, &auth); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if auth.AccessToken == "" || auth.ProjectID == "" {
		return nil, nil
	}
	if auth.Type != "" && auth.Type != string(AccountTypeAntigravity) {
		return nil, nil
	}
	acc := &Account{
		Type:              AccountTypeAntigravity,
		ID:                strings.TrimSuffix(name, filepath.Ext(name)),
		File:              path,
		AccessToken:       auth.AccessToken,
		RefreshToken:      auth.RefreshToken,
		PlanType:          auth.PlanType,
		Email:             auth.Email,
		ProjectID:         auth.ProjectID,
		Disabled:          auth.Disabled,
		Dead:              auth.Dead,
		ModelRateLimits:   make(map[string]time.Time),
		NeedsVerification: auth.NeedsVerification,
		VerificationURL:   auth.VerificationURL,
		HealthError:       auth.HealthError,
	}
	if acc.PlanType == "" {
		acc.PlanType = "antigravity"
	}
	if auth.ExpiryDate > 0 {
		acc.ExpiresAt = time.UnixMilli(auth.ExpiryDate)
	} else if auth.ExpiresAt != "" {
		acc.ExpiresAt, _ = time.Parse(time.RFC3339Nano, auth.ExpiresAt)
	}
	if auth.LastRefresh != "" {
		acc.LastRefresh, _ = time.Parse(time.RFC3339Nano, auth.LastRefresh)
	}
	for model, raw := range auth.ModelCooldowns {
		if until, err := time.Parse(time.RFC3339Nano, raw); err == nil && until.After(time.Now()) {
			acc.ModelRateLimits[model] = until
		}
	}
	if auth.ModelSnapshot != nil {
		antigravityModels.ReplaceAccount(acc.ID, *auth.ModelSnapshot)
	} else {
		antigravityModels.MarkAccount(acc.ID)
	}
	return acc, nil
}

func (p *AntigravityProvider) SetAuthHeaders(req *http.Request, acc *Account) {
	req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", antigravityUserAgent())
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "close")
}

func antigravityOAuthClientID() string {
	if value := strings.TrimSpace(os.Getenv("ANTIGRAVITY_OAUTH_CLIENT_ID")); value != "" {
		return value
	}
	return decodeAntigravityPublicOAuthValue(antigravityPublicClientIDXOR)
}

func antigravityOAuthClientSecret() string {
	if value := strings.TrimSpace(os.Getenv("ANTIGRAVITY_OAUTH_CLIENT_SECRET")); value != "" {
		return value
	}
	return decodeAntigravityPublicOAuthValue(antigravityPublicClientSecretXOR)
}

func decodeAntigravityPublicOAuthValue(encoded []byte) string {
	decoded := make([]byte, len(encoded))
	for i, value := range encoded {
		decoded[i] = value ^ 0x5a
	}
	return string(decoded)
}

func antigravityUserAgent() string {
	return fmt.Sprintf("antigravity/hub/%s darwin/arm64", antigravityClientVersion())
}

func antigravityOnboardUserAgent() string {
	return antigravityUserAgent() + " google-api-nodejs-client/10.3.0"
}

func antigravityClientVersion() string {
	version := strings.TrimSpace(os.Getenv("ANTIGRAVITY_CLIENT_VERSION"))
	if version != "" {
		return version
	}
	return antigravityVersions.current(time.Now())
}

func (p *AntigravityProvider) RefreshToken(ctx context.Context, acc *Account, transport http.RoundTripper) error {
	acc.mu.Lock()
	refreshToken := acc.RefreshToken
	acc.mu.Unlock()
	if refreshToken == "" {
		return errors.New("antigravity account has no refresh token")
	}
	clientID := antigravityOAuthClientID()
	if clientID == "" {
		return errors.New("antigravity OAuth client ID is not configured")
	}
	form := url.Values{
		"client_id":     {clientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	if secret := antigravityOAuthClientSecret(); secret != "" {
		form.Set("client_secret", secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, antigravityOAuthTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Go-http-client/2.0")
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("antigravity token refresh failed: %s: %s", resp.Status, safeText(body))
	}
	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		return err
	}
	if token.AccessToken == "" {
		return errors.New("antigravity token refresh returned an empty access token")
	}
	acc.mu.Lock()
	acc.AccessToken = token.AccessToken
	if token.RefreshToken != "" {
		acc.RefreshToken = token.RefreshToken
	}
	acc.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	acc.LastRefresh = time.Now().UTC()
	acc.Dead = false
	acc.mu.Unlock()
	return saveAccount(acc)
}

func (p *AntigravityProvider) ParseUsage(obj map[string]any) *RequestUsage {
	if response, ok := obj["response"].(map[string]any); ok {
		obj = response
	}
	usage, ok := obj["usageMetadata"].(map[string]any)
	if !ok {
		return nil
	}
	result := &RequestUsage{
		Timestamp:         time.Now(),
		InputTokens:       readInt64(usage, "promptTokenCount"),
		CachedInputTokens: readInt64(usage, "cachedContentTokenCount"),
		OutputTokens:      readInt64(usage, "candidatesTokenCount"),
		ReasoningTokens:   readInt64(usage, "thoughtsTokenCount"),
	}
	result.BillableTokens = clampNonNegative(result.InputTokens - result.CachedInputTokens + result.OutputTokens)
	if result.InputTokens == 0 && result.OutputTokens == 0 && result.ReasoningTokens == 0 {
		return nil
	}
	return result
}

func (p *AntigravityProvider) ParseUsageHeaders(_ *Account, _ http.Header) {}

func (p *AntigravityProvider) UpstreamURL(_ string) *url.URL { return p.dailyBase }
func (p *AntigravityProvider) DailyURL() *url.URL            { return p.dailyBase }
func (p *AntigravityProvider) ProductionURL() *url.URL       { return p.prodBase }
func (p *AntigravityProvider) MatchesPath(_ string) bool     { return false }
func (p *AntigravityProvider) NormalizePath(path string) string {
	return path
}
func (p *AntigravityProvider) DetectsSSE(path, contentType string) bool {
	return strings.Contains(path, "streamGenerateContent") || strings.Contains(strings.ToLower(contentType), "text/event-stream")
}

func saveAntigravityAccount(acc *Account) error {
	lockValue, _ := antigravityAccountSaveLocks.LoadOrStore(acc.File, &sync.Mutex{})
	fileLock := lockValue.(*sync.Mutex)
	fileLock.Lock()
	defer fileLock.Unlock()
	raw, err := os.ReadFile(acc.File)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	root := make(map[string]any)
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &root); err != nil {
			return fmt.Errorf("parse existing antigravity account: %w", err)
		}
	}
	acc.mu.Lock()
	root["type"] = string(AccountTypeAntigravity)
	root["access_token"] = acc.AccessToken
	root["refresh_token"] = acc.RefreshToken
	root["token_type"] = "Bearer"
	root["expiry_date"] = acc.ExpiresAt.UnixMilli()
	root["expired"] = acc.ExpiresAt.UTC().Format(time.RFC3339Nano)
	root["last_refresh"] = acc.LastRefresh.UTC().Format(time.RFC3339Nano)
	root["email"] = acc.Email
	root["project_id"] = acc.ProjectID
	root["plan_type"] = acc.PlanType
	root["disabled"] = acc.Disabled
	root["dead"] = acc.Dead
	root["needs_verification"] = acc.NeedsVerification
	root["verification_url"] = acc.VerificationURL
	root["health_error"] = acc.HealthError
	cooldowns := make(map[string]string, len(acc.ModelRateLimits))
	for model, until := range acc.ModelRateLimits {
		if until.After(time.Now()) {
			cooldowns[model] = until.UTC().Format(time.RFC3339Nano)
		}
	}
	root["model_rate_limits"] = cooldowns
	persistAccountAddedAt(root, acc)
	acc.mu.Unlock()
	if snapshot, ok := antigravityModels.AccountSnapshot(acc.ID); ok {
		root["model_snapshot"] = snapshot
	}
	if err := os.MkdirAll(filepath.Dir(acc.File), 0o700); err != nil {
		return err
	}
	return atomicWriteJSON(acc.File, root)
}
