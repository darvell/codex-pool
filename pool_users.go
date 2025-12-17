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
	"strings"
	"sync"
	"time"
)

// PoolUser represents a generated pool user who can use the proxy.
type PoolUser struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"` // Download token for /config/codex/<token>
	Email     string    `json:"email"`
	PlanType  string    `json:"plan_type"` // pro, team, plus
	CreatedAt time.Time `json:"created_at"`
	Disabled  bool      `json:"disabled"`
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

// isPoolUserToken checks if the Authorization header contains a pool user JWT.
// Returns (isPoolUser, userID, error).
func isPoolUserToken(secret, authHeader string) (bool, string, error) {
	if secret == "" {
		return false, "", nil
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false, "", nil
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := validatePoolUserJWT(secret, token)
	if err != nil {
		return false, "", nil // Not a valid pool user token
	}

	// Check issuer
	if iss, ok := claims["iss"].(string); !ok || iss != "codex-pool-proxy" {
		return false, "", nil
	}

	// Extract user ID from sub claim
	if sub, ok := claims["sub"].(string); ok && strings.HasPrefix(sub, "pool_user:") {
		userID := strings.TrimPrefix(sub, "pool_user:")
		return true, userID, nil
	}

	return false, "", nil
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
	now := time.Now()
	exp := now.Add(365 * 24 * time.Hour).Unix() // 1 year

	accountID := "pool_" + user.ID[:8]

	claims := map[string]any{
		"exp": exp,
		"iat": now.Unix(),
		"iss": "codex-pool-proxy",
		"sub": "pool_user:" + user.ID,
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": accountID,
			"chatgpt_plan_type":  user.PlanType,
		},
		"https://api.openai.com/profile": map[string]any{
			"email":          user.Email,
			"email_verified": true,
		},
	}

	idToken, err := signJWT(secret, claims)
	if err != nil {
		return nil, err
	}

	accessClaims := map[string]any{
		"exp": exp,
		"iat": now.Unix(),
		"iss": "codex-pool-proxy",
		"sub": "pool_user:" + user.ID,
		"aud": []string{"https://api.openai.com/v1"},
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": accountID,
			"chatgpt_plan_type":  user.PlanType,
		},
	}
	accessToken, err := signJWT(secret, accessClaims)
	if err != nil {
		return nil, err
	}

	refreshToken := fmt.Sprintf("poolrt_%s_%s", user.ID, randomHex(16))

	return &CodexAuthJSON{
		OpenAIKey: nil,
		Tokens: &TokenData{
			IDToken:      idToken,
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			AccountID:    &accountID,
		},
	}, nil
}

// generateGeminiAuth creates the oauth_creds.json content for a pool user.
func generateGeminiAuth(secret string, user *PoolUser) (*PoolUserGeminiAuth, error) {
	now := time.Now()
	exp := now.Add(365 * 24 * time.Hour).Unix() // 1 year
	expiryDateMs := now.Add(365 * 24 * time.Hour).UnixMilli()

	claims := map[string]any{
		"exp":            exp,
		"iat":            now.Unix(),
		"iss":            "codex-pool-proxy",
		"sub":            "pool_user:" + user.ID,
		"email":          user.Email,
		"email_verified": true,
	}

	idToken, err := signJWT(secret, claims)
	if err != nil {
		return nil, err
	}

	accessToken, err := signJWT(secret, claims)
	if err != nil {
		return nil, err
	}

	refreshToken := fmt.Sprintf("poolrt_%s_%s", user.ID, randomHex(16))

	return &PoolUserGeminiAuth{
		AccessToken:  accessToken,
		ExpiryDate:   expiryDateMs,
		IDToken:      idToken,
		RefreshToken: refreshToken,
		Scope:        "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid",
		TokenType:    "Bearer",
	}, nil
}

// getPoolAdminPassword returns the admin password from config or env.
func getPoolAdminPassword() string {
	if v := os.Getenv("POOL_ADMIN_PASSWORD"); v != "" {
		return v
	}
	if globalConfigFile != nil && globalConfigFile.PoolUsers.AdminPassword != "" {
		return globalConfigFile.PoolUsers.AdminPassword
	}
	return ""
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
