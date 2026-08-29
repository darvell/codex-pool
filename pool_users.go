package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PoolUser represents a generated pool user who can use the proxy.
type PoolUser struct {
	ID                 string    `json:"id"`
	Token              string    `json:"token"` // Download token for /config/codex/<token>
	Email              string    `json:"email"`
	PlanType           string    `json:"plan_type"` // pro, team, plus
	CreatedAt          time.Time `json:"created_at"`
	Disabled           bool      `json:"disabled"`
	credentialIssuedAt time.Time
}

func poolCredentialIssuedAt(user *PoolUser) time.Time {
	now := time.Now().UTC()
	if user != nil && user.credentialIssuedAt.After(now) {
		return user.credentialIssuedAt.UTC()
	}
	return now
}

// PoolUserStore manages pool user persistence.
type PoolUserStore struct {
	mu    sync.RWMutex
	path  string
	users map[string]*PoolUser // keyed by ID
	byTok map[string]*PoolUser // keyed by download token
}

func newPoolUserStore(path string) (*PoolUserStore, error) {
	s := &PoolUserStore{
		path:  path,
		users: make(map[string]*PoolUser),
		byTok: make(map[string]*PoolUser),
	}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *PoolUserStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var users []*PoolUser
	if err := json.Unmarshal(data, &users); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = make(map[string]*PoolUser, len(users))
	s.byTok = make(map[string]*PoolUser, len(users))
	for _, u := range users {
		s.users[u.ID] = u
		s.byTok[u.Token] = u
	}
	return nil
}

func (s *PoolUserStore) save() error {
	users := make([]*PoolUser, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

func (s *PoolUserStore) Create(u *PoolUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.ID] = u
	s.byTok[u.Token] = u
	return s.save()
}

func (s *PoolUserStore) Get(id string) *PoolUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[id]
}

func (s *PoolUserStore) GetByToken(token string) *PoolUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byTok[token]
}

func (s *PoolUserStore) List() []*PoolUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*PoolUser, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	return out
}

func (s *PoolUserStore) GetByEmail(email string) *PoolUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Email == email {
			return u
		}
	}
	return nil
}

func (s *PoolUserStore) Disable(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[id]; ok {
		u.Disabled = true
		return s.save()
	}
	return fmt.Errorf("user not found: %s", id)
}

// JWT generation

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func signJWT(secret string, claims map[string]any) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := header + "." + payload

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return signingInput + "." + signature, nil
}

// hmacSign creates an HMAC-SHA256 signature for arbitrary data.
func hmacSign(secret string, data []byte) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	return h.Sum(nil)
}

func generatePoolRefreshToken(secret, identity string, issuedAt time.Time) string {
	nonce := randomHex(16)
	issuedUnix := issuedAt.Unix()
	payload := fmt.Sprintf("%s|%d|%s", identity, issuedUnix, nonce)
	signature := hex.EncodeToString(hmacSign(secret, []byte(payload)))
	return fmt.Sprintf("poolrt_%s_%d_%s_%s", identity, issuedUnix, nonce, signature)
}

func parsePoolRefreshToken(secret, token string) (identity string, issuedAt time.Time, signed, ok bool) {
	if secret == "" || !strings.HasPrefix(token, "poolrt_") {
		return "", time.Time{}, false, false
	}
	parts := strings.Split(strings.TrimPrefix(token, "poolrt_"), "_")
	if len(parts) == 2 {
		return parts[0], time.Time{}, false, parts[0] != "" && parts[1] != ""
	}
	if len(parts) != 4 || parts[0] == "" || parts[2] == "" || parts[3] == "" {
		return "", time.Time{}, false, false
	}
	issuedUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || issuedUnix <= 0 {
		return "", time.Time{}, false, false
	}
	payload := fmt.Sprintf("%s|%d|%s", parts[0], issuedUnix, parts[2])
	provided, err := hex.DecodeString(parts[3])
	if err != nil || !hmac.Equal(hmacSign(secret, []byte(payload)), provided) {
		return "", time.Time{}, false, false
	}
	return parts[0], time.Unix(issuedUnix, 0).UTC(), true, true
}

// validatePoolUserJWT checks if a JWT was signed with our secret and returns the claims.
func validatePoolUserJWT(secret, token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	signingInput := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(signingInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return nil, fmt.Errorf("invalid signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}

	// Check expiry
	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			return nil, fmt.Errorf("token expired")
		}
	}

	return claims, nil
}

// parsePoolUserToken checks if the Authorization header contains a pool user JWT
// and returns its composite principal/client identity and signed issue time.
func parsePoolUserToken(secret, authHeader string) (string, time.Time, bool) {
	if secret == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return "", time.Time{}, false
	}
	claims, err := validatePoolUserJWT(secret, strings.TrimPrefix(authHeader, "Bearer "))
	if err != nil {
		return "", time.Time{}, false
	}
	iss, ok := claims["iss"].(string)
	if !ok || (iss != "https://auth.openai.com" && iss != "https://accounts.google.com" && iss != "https://auth.anthropic.com") {
		return "", time.Time{}, false
	}
	sub, ok := claims["sub"].(string)
	if !ok || !strings.HasPrefix(sub, "pool|") {
		return "", time.Time{}, false
	}
	iat, _ := claims["iat"].(float64)
	issuedAt := time.Time{}
	if iat > 0 {
		issuedAt = time.Unix(int64(iat), 0).UTC()
	}
	return strings.TrimPrefix(sub, "pool|"), issuedAt, true
}

// isPoolUserToken preserves the legacy parser contract for existing callers.
func isPoolUserToken(secret, authHeader string) (bool, string, error) {
	identity, _, ok := parsePoolUserToken(secret, authHeader)
	return ok, identity, nil
}

// hashUserIP creates a non-reversible ID from an IP address using SHA256.
// The salt ensures IDs are unique to this pool instance.
func hashUserIP(ip, salt string) string {
	h := sha256.New()
	h.Write([]byte(salt + "|" + ip))
	return hex.EncodeToString(h.Sum(nil))[:16] // 16 char hex ID
}

// PoolUserGeminiAuth matches the Gemini oauth_creds.json format for pool users.
// (Includes id_token which the base GeminiAuthJSON doesn't have)
type PoolUserGeminiAuth struct {
	AccessToken  string `json:"access_token"`
	ExpiryDate   int64  `json:"expiry_date"` // Unix ms
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

// generateCodexAuth creates the auth.json content for a pool user.
func generateCodexAuth(secret string, user *PoolUser) (*CodexAuthJSON, error) {
	now := poolCredentialIssuedAt(user)
	exp := now.Add(10 * 365 * 24 * time.Hour).Unix() // 10 years

	// Generate a UUID-like account ID to match OpenAI's format
	accountID := fmt.Sprintf("%s-%s-%s-%s-%s",
		user.ID[:8],
		randomHex(2),
		randomHex(2),
		randomHex(2),
		randomHex(6))

	// Generate unique IDs
	jtiID := fmt.Sprintf("%s-%s-%s-%s-%s", randomHex(4), randomHex(2), randomHex(2), randomHex(2), randomHex(6))
	sessionID := "authsess_pool" + randomHex(12)
	chatgptUserID := "user-pool-" + user.ID[:8]
	chatgptAccountUserID := chatgptUserID + "__" + accountID

	// ID token claims - match OpenAI's format closely
	idTokenClaims := map[string]any{
		"exp":            exp,
		"iat":            now.Unix(),
		"nbf":            now.Unix(),
		"iss":            "https://auth.openai.com",
		"sub":            "pool|" + user.ID,
		"aud":            []string{"app_EMoamEEZ73f0CkXaXp7hrann"},
		"jti":            jtiID,
		"client_id":      "app_EMoamEEZ73f0CkXaXp7hrann",
		"session_id":     sessionID,
		"email":          user.Email,
		"email_verified": true,
		"scp":            []string{"openid", "profile", "email", "offline_access"},
		"pwd_auth_time":  now.UnixMilli(),
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id":        accountID,
			"chatgpt_account_user_id":   chatgptAccountUserID,
			"chatgpt_compute_residency": "no_constraint",
			"chatgpt_plan_type":         user.PlanType,
			"chatgpt_user_id":           chatgptUserID,
			"user_id":                   chatgptUserID,
		},
		"https://api.openai.com/mfa": map[string]any{
			"required": "no",
		},
		"https://api.openai.com/profile": map[string]any{
			"email":          user.Email,
			"email_verified": true,
		},
	}

	idToken, err := signJWT(secret, idTokenClaims)
	if err != nil {
		return nil, err
	}

	// Access token claims - similar but different aud
	accessClaims := map[string]any{
		"exp":           exp,
		"iat":           now.Unix(),
		"nbf":           now.Unix(),
		"iss":           "https://auth.openai.com",
		"sub":           "pool|" + user.ID,
		"aud":           []string{"https://api.openai.com/v1"},
		"jti":           randomHex(8) + "-" + randomHex(4) + "-" + randomHex(4) + "-" + randomHex(4) + "-" + randomHex(12),
		"client_id":     "app_EMoamEEZ73f0CkXaXp7hrann",
		"session_id":    sessionID,
		"scp":           []string{"openid", "profile", "email", "offline_access"},
		"pwd_auth_time": now.UnixMilli(),
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id":        accountID,
			"chatgpt_account_user_id":   chatgptAccountUserID,
			"chatgpt_compute_residency": "no_constraint",
			"chatgpt_plan_type":         user.PlanType,
			"chatgpt_user_id":           chatgptUserID,
			"user_id":                   chatgptUserID,
		},
		"https://api.openai.com/mfa": map[string]any{
			"required": "no",
		},
		"https://api.openai.com/profile": map[string]any{
			"email":          user.Email,
			"email_verified": true,
		},
	}
	accessToken, err := signJWT(secret, accessClaims)
	if err != nil {
		return nil, err
	}

	refreshToken := generatePoolRefreshToken(secret, user.ID, now)

	return &CodexAuthJSON{
		// Codex Desktop resolves auth.json files with OPENAI_API_KEY as API-key
		// auth. Use the same pool JWT as the OAuth-shaped access token so both
		// Desktop and CLI authenticate to the configured pool provider.
		OpenAIKey: &accessToken,
		Tokens: &TokenData{
			IDToken:      idToken,
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			AccountID:    &accountID,
		},
		LastRefresh: &now, // Required by Codex CLI - must be non-null
	}, nil
}

// generateGeminiAuth creates the oauth_creds.json content for a pool user.
// Note: We use Google-like token formats (ya29.* and 1//*) so the Gemini CLI
// doesn't reject them during local validation. The pool validates these tokens.
func generateGeminiAuth(secret string, user *PoolUser) (*PoolUserGeminiAuth, error) {
	now := poolCredentialIssuedAt(user)
	exp := now.Add(365 * 24 * time.Hour).Unix() // 1 year
	expiryDateMs := now.Add(365 * 24 * time.Hour).UnixMilli()

	claims := map[string]any{
		"exp":            exp,
		"iat":            now.Unix(),
		"iss":            "https://accounts.google.com",
		"sub":            "pool|" + user.ID,
		"email":          user.Email,
		"email_verified": true,
	}

	// Create a JWT for id_token (this is expected to be a JWT)
	idToken, err := signJWT(secret, claims)
	if err != nil {
		return nil, err
	}

	// Create a Google-like access token (ya29.pool-<base64 payload>)
	// This format passes Gemini CLI's local validation while being verifiable by our pool
	payloadBytes, _ := json.Marshal(map[string]any{
		"user_id": user.ID,
		"exp":     exp,
		"iat":     now.Unix(),
	})
	sig := hmacSign(secret, payloadBytes)
	accessToken := fmt.Sprintf("ya29.pool-%s_%s", base64.RawURLEncoding.EncodeToString(payloadBytes), base64.RawURLEncoding.EncodeToString(sig))

	// Use a Google-like refresh token format
	refreshToken := fmt.Sprintf("1//pool_%s_%s", user.ID, randomHex(16))

	return &PoolUserGeminiAuth{
		AccessToken:  accessToken,
		ExpiryDate:   expiryDateMs,
		IDToken:      idToken,
		RefreshToken: refreshToken,
		Scope:        "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid",
		TokenType:    "Bearer",
	}, nil
}

// generateGeminiAPIKey creates a pool API key for Gemini CLI in API key mode.
// Format: AIzaSy-pool-<user_id>.<timestamp>.<signature>
// This bypasses OAuth completely and lets Gemini CLI work with our proxy.
func generateGeminiAPIKey(secret string, user *PoolUser) string {
	timestamp := poolCredentialIssuedAt(user).Unix()
	payload := fmt.Sprintf("%s.%d", user.ID, timestamp)
	sig := hmacSign(secret, []byte(payload))
	return fmt.Sprintf("AIzaSy-pool-%s.%d.%s", user.ID, timestamp, base64.RawURLEncoding.EncodeToString(sig)[:16])
}

// parseGeminiOAuthPoolToken checks a pool-generated Gemini OAuth token and
// returns its composite principal/client identity and signed issue time.
func parseGeminiOAuthPoolToken(secret, token string) (string, time.Time, bool) {
	if secret == "" || !strings.HasPrefix(token, "ya29.pool-") {
		return "", time.Time{}, false
	}
	rest := strings.TrimPrefix(token, "ya29.pool-")
	if rest == "" {
		return "", time.Time{}, false
	}
	tryParse := func(payloadB64, sigB64 string) (string, time.Time, bool) {
		payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
		if err != nil {
			return "", time.Time{}, false
		}
		providedSig, err := base64.RawURLEncoding.DecodeString(sigB64)
		if err != nil || !hmac.Equal(hmacSign(secret, payloadBytes), providedSig) {
			return "", time.Time{}, false
		}
		var payload struct {
			UserID string `json:"user_id"`
			Exp    int64  `json:"exp"`
			IAT    int64  `json:"iat"`
		}
		if json.Unmarshal(payloadBytes, &payload) != nil || payload.UserID == "" || payload.IAT <= 0 {
			return "", time.Time{}, false
		}
		if payload.Exp > 0 && payload.Exp < time.Now().Unix() {
			return "", time.Time{}, false
		}
		return payload.UserID, time.Unix(payload.IAT, 0).UTC(), true
	}
	// Base64url may contain underscores, so only HMAC verification identifies the split.
	for i := 0; i < len(rest); i++ {
		if rest[i] != '_' {
			continue
		}
		if identity, issuedAt, ok := tryParse(rest[:i], rest[i+1:]); ok {
			return identity, issuedAt, true
		}
	}
	return "", time.Time{}, false
}

func isGeminiOAuthPoolToken(secret, token string) (bool, string) {
	identity, _, ok := parseGeminiOAuthPoolToken(secret, token)
	return ok, identity
}

func parsePoolGeminiAPIKey(secret, apiKey string) (string, time.Time, bool) {
	if secret == "" || !strings.HasPrefix(apiKey, "AIzaSy-pool-") {
		return "", time.Time{}, false
	}
	parts := strings.Split(strings.TrimPrefix(apiKey, "AIzaSy-pool-"), ".")
	if len(parts) != 3 || parts[0] == "" {
		return "", time.Time{}, false
	}
	expectedSig := base64.RawURLEncoding.EncodeToString(hmacSign(secret, []byte(parts[0]+"."+parts[1])))[:16]
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return "", time.Time{}, false
	}
	issuedUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || issuedUnix <= 0 {
		return "", time.Time{}, false
	}
	return parts[0], time.Unix(issuedUnix, 0).UTC(), true
}

// isPoolGeminiAPIKey preserves the legacy parser contract for existing callers.
func isPoolGeminiAPIKey(secret, apiKey string) (bool, string, error) {
	identity, _, ok := parsePoolGeminiAPIKey(secret, apiKey)
	return ok, identity, nil
}

// getPoolJWTSecret returns the JWT signing secret from config or env.
func getPoolJWTSecret() string {
	if v := os.Getenv("POOL_JWT_SECRET"); v != "" {
		return v
	}
	if globalConfigFile != nil && globalConfigFile.PoolUsers.JWTSecret != "" {
		return globalConfigFile.PoolUsers.JWTSecret
	}
	return ""
}

// getPoolUsersPath returns the pool users storage path from config or env.
func getPoolUsersPath() string {
	if v := os.Getenv("POOL_USERS_PATH"); v != "" {
		return v
	}
	if globalConfigFile != nil && globalConfigFile.PoolUsers.StoragePath != "" {
		return globalConfigFile.PoolUsers.StoragePath
	}
	return "./data/pool_users.json"
}

// getPublicURL returns the public URL override from config or env.
// Returns empty string if not configured (use request host instead).
func getPublicURL() string {
	if v := os.Getenv("PUBLIC_URL"); v != "" {
		return strings.TrimSuffix(v, "/")
	}
	if globalConfigFile != nil && globalConfigFile.PublicURL != "" {
		return strings.TrimSuffix(globalConfigFile.PublicURL, "/")
	}
	return ""
}

// PoolUserClaudeAuth matches the Claude Code credentials format for pool users.
type PoolUserClaudeAuth struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Email        string `json:"email"`
}

// generateClaudeAuth creates the credentials JSON content for a Claude Code pool user.
// Uses a fake sk-ant-oat01-pool-* format that looks like a real Claude OAuth token
// (CLAUDE_CODE_OAUTH_TOKEN) but contains an embedded user ID and signature for pool
// authentication.
func generateClaudeAuth(secret string, user *PoolUser) (*PoolUserClaudeAuth, error) {
	issuedAt := poolCredentialIssuedAt(user)
	// Generate a fake sk-ant-oat01 token with embedded pool user info.
	// Format: sk-ant-oat01-pool-<base64url(userID.timestamp.signature)>
	accessToken := generateClaudePoolTokenAt(secret, user.ID, issuedAt)

	refreshToken := generatePoolRefreshToken(secret, user.ID, issuedAt)

	return &PoolUserClaudeAuth{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      "", // Claude doesn't use ID token
		Email:        user.Email,
	}, nil
}

// ClaudePoolTokenPrefix is the prefix for pool-generated Claude tokens.
// These look like real sk-ant-oat01 tokens but have a "pool" marker for detection.
//
// Note: we keep accepting the legacy sk-ant-api-pool-* prefix for backward compatibility
// with already-issued tokens.
const ClaudePoolTokenPrefix = "sk-ant-oat01-pool-"

const ClaudePoolTokenLegacyPrefix = "sk-ant-api-pool-"

// generateClaudePoolToken creates a fake Claude OAuth token with embedded pool user info.
// Format: sk-ant-oat01-pool-<base64url(userID.timestamp.signature)>
func generateClaudePoolToken(secret, userID string) string {
	return generateClaudePoolTokenAt(secret, userID, time.Now().UTC())
}

func generateClaudePoolTokenAt(secret, userID string, issuedAt time.Time) string {
	now := issuedAt.Unix()
	// Create payload: userID.timestamp
	payload := fmt.Sprintf("%s.%d", userID, now)
	// Sign it
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	sig := hex.EncodeToString(h.Sum(nil))[:16] // 16 char signature
	// Combine and encode
	data := fmt.Sprintf("%s.%s", payload, sig)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(data))
	return ClaudePoolTokenPrefix + encoded
}

func parseClaudePoolCredential(secret, token string) (string, time.Time, bool) {
	if secret == "" {
		return "", time.Time{}, false
	}
	var encoded string
	switch {
	case strings.HasPrefix(token, ClaudePoolTokenPrefix):
		encoded = strings.TrimPrefix(token, ClaudePoolTokenPrefix)
	case strings.HasPrefix(token, ClaudePoolTokenLegacyPrefix):
		encoded = strings.TrimPrefix(token, ClaudePoolTokenLegacyPrefix)
	default:
		return "", time.Time{}, false
	}
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", time.Time{}, false
	}
	parts := strings.Split(string(data), ".")
	if len(parts) != 3 || parts[0] == "" {
		return "", time.Time{}, false
	}
	payload := parts[0] + "." + parts[1]
	expectedSig := hex.EncodeToString(hmacSign(secret, []byte(payload)))[:16]
	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return "", time.Time{}, false
	}
	issuedUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || issuedUnix <= 0 {
		return "", time.Time{}, false
	}
	return parts[0], time.Unix(issuedUnix, 0).UTC(), true
}

// parseClaudePoolToken preserves the legacy parser contract for existing callers.
func parseClaudePoolToken(secret, token string) (string, bool) {
	identity, _, ok := parseClaudePoolCredential(secret, token)
	return identity, ok
}
