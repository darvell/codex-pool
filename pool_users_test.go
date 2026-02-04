package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSignAndValidateJWT(t *testing.T) {
	secret := "test-secret-key-12345678901234567890"
	claims := map[string]any{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iss": "https://auth.openai.com",
		"sub": "pool|test123",
	}

	token, err := signJWT(secret, claims)
	if err != nil {
		t.Fatalf("signJWT failed: %v", err)
	}

	// Validate the token
	validated, err := validatePoolUserJWT(secret, token)
	if err != nil {
		t.Fatalf("validatePoolUserJWT failed: %v", err)
	}

	if validated["iss"] != "https://auth.openai.com" {
		t.Errorf("expected iss=https://auth.openai.com, got %v", validated["iss"])
	}
	if validated["sub"] != "pool|test123" {
		t.Errorf("expected sub=pool|test123, got %v", validated["sub"])
	}
}

func TestValidateJWTWrongSecret(t *testing.T) {
	claims := map[string]any{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iss": "https://auth.openai.com",
	}

	token, _ := signJWT("secret1", claims)
	_, err := validatePoolUserJWT("secret2", token)
	if err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestValidateExpiredJWT(t *testing.T) {
	secret := "test-secret"
	claims := map[string]any{
		"exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired
		"iss": "https://auth.openai.com",
	}

	token, _ := signJWT(secret, claims)
	_, err := validatePoolUserJWT(secret, token)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestIsPoolUserToken(t *testing.T) {
	secret := "test-secret-key"
	claims := map[string]any{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iss": "https://auth.openai.com",
		"sub": "pool|abc123",
	}

	token, _ := signJWT(secret, claims)
	authHeader := "Bearer " + token

	isPool, userID, err := isPoolUserToken(secret, authHeader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isPool {
		t.Error("expected isPool=true")
	}
	if userID != "abc123" {
		t.Errorf("expected userID=abc123, got %s", userID)
	}
}

func TestIsPoolUserTokenWrongIssuer(t *testing.T) {
	secret := "test-secret-key"
	claims := map[string]any{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iss": "https://example.com", // Wrong issuer (not https://auth.openai.com)
		"sub": "pool|abc123",
	}

	token, _ := signJWT(secret, claims)
	authHeader := "Bearer " + token

	isPool, _, _ := isPoolUserToken(secret, authHeader)
	if isPool {
		t.Error("expected isPool=false for wrong issuer")
	}
}

func TestGenerateCodexAuth(t *testing.T) {
	secret := "test-secret-key-12345678901234567890"
	user := &PoolUser{
		ID:        "abcdef1234567890abcdef1234567890",
		Email:     "test@example.com",
		PlanType:  "pro",
		CreatedAt: time.Now(),
	}

	auth, err := generateCodexAuth(secret, user)
	if err != nil {
		t.Fatalf("generateCodexAuth failed: %v", err)
	}

	if auth.Tokens == nil {
		t.Fatal("tokens is nil")
	}
	if auth.Tokens.AccessToken == "" {
		t.Error("access_token is empty")
	}
	if auth.Tokens.IDToken == "" {
		t.Error("id_token is empty")
	}
	if auth.Tokens.RefreshToken == "" {
		t.Error("refresh_token is empty")
	}
	if auth.Tokens.AccountID == nil || *auth.Tokens.AccountID == "" {
		t.Error("account_id is empty")
	}

	// Verify the tokens are valid JWTs we can parse
	claims, err := validatePoolUserJWT(secret, auth.Tokens.AccessToken)
	if err != nil {
		t.Fatalf("access token validation failed: %v", err)
	}
	if claims["iss"] != "https://auth.openai.com" {
		t.Errorf("expected iss=https://auth.openai.com, got %v", claims["iss"])
	}

	// Check JSON serialization
	data, err := json.MarshalIndent(auth, "", "  ")
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}
	t.Logf("Generated auth.json:\n%s", string(data))
}

func TestGenerateGeminiAuth(t *testing.T) {
	secret := "test-secret-key-12345678901234567890"
	user := &PoolUser{
		ID:        "abcdef1234567890abcdef1234567890",
		Email:     "test@example.com",
		PlanType:  "pro",
		CreatedAt: time.Now(),
	}

	auth, err := generateGeminiAuth(secret, user)
	if err != nil {
		t.Fatalf("generateGeminiAuth failed: %v", err)
	}

	if auth.AccessToken == "" {
		t.Error("access_token is empty")
	}
	if auth.IDToken == "" {
		t.Error("id_token is empty")
	}
	if auth.RefreshToken == "" {
		t.Error("refresh_token is empty")
	}
	if auth.TokenType != "Bearer" {
		t.Errorf("expected token_type=Bearer, got %s", auth.TokenType)
	}
	if auth.ExpiryDate == 0 {
		t.Error("expiry_date is 0")
	}

	// Verify ID token is a pool-signed JWT with Google issuer.
	claims, err := validatePoolUserJWT(secret, auth.IDToken)
	if err != nil {
		t.Fatalf("id token validation failed: %v", err)
	}
	if claims["iss"] != "https://accounts.google.com" {
		t.Errorf("expected iss=https://accounts.google.com, got %v", claims["iss"])
	}

	// Verify access token is a pool-generated Google-like token accepted by Gemini CLI.
	if ok, uid := isGeminiOAuthPoolToken(secret, auth.AccessToken); !ok {
		t.Fatalf("access token validation failed: not a pool token")
	} else if uid != user.ID {
		t.Fatalf("access token validation failed: expected user %q, got %q", user.ID, uid)
	}

	// Check JSON serialization
	data, err := json.MarshalIndent(auth, "", "  ")
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}
	t.Logf("Generated oauth_creds.json:\n%s", string(data))
}

func TestLooksLikeProviderCredential(t *testing.T) {
	tests := []struct {
		name         string
		authHeader   string
		wantIsValid  bool
		wantProvider AccountType
	}{
		{
			name:         "Claude API key",
			authHeader:   "Bearer sk-ant-api03-abc123xyz",
			wantIsValid:  true,
			wantProvider: AccountTypeClaude,
		},
		{
			name:         "Claude OAuth token",
			authHeader:   "Bearer sk-ant-oat01-abc123xyz",
			wantIsValid:  true,
			wantProvider: AccountTypeClaude,
		},
		{
			name:         "OpenAI project key",
			authHeader:   "Bearer sk-proj-abc123xyz",
			wantIsValid:  true,
			wantProvider: AccountTypeCodex,
		},
		{
			name:         "OpenAI legacy key",
			authHeader:   "Bearer sk-abc123xyz",
			wantIsValid:  true,
			wantProvider: AccountTypeCodex,
		},
		{
			name:         "Google OAuth token",
			authHeader:   "Bearer ya29.abc123xyz",
			wantIsValid:  true,
			wantProvider: AccountTypeGemini,
		},
		{
			name:        "Empty header",
			authHeader:  "",
			wantIsValid: false,
		},
		{
			name:        "No Bearer prefix",
			authHeader:  "sk-ant-api03-abc123",
			wantIsValid: false,
		},
		{
			name:        "Random JWT (pool user token)",
			authHeader:  "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJwb29sfGFiYzEyMyJ9.signature",
			wantIsValid: false,
		},
		{
			name:        "Unknown token format",
			authHeader:  "Bearer some-random-token",
			wantIsValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIsValid, gotProvider := looksLikeProviderCredential(tt.authHeader)
			if gotIsValid != tt.wantIsValid {
				t.Errorf("looksLikeProviderCredential() isValid = %v, want %v", gotIsValid, tt.wantIsValid)
			}
			if gotIsValid && gotProvider != tt.wantProvider {
				t.Errorf("looksLikeProviderCredential() provider = %v, want %v", gotProvider, tt.wantProvider)
			}
		})
	}
}

func TestClaudePoolToken_FormatAndBackwardCompatibility(t *testing.T) {
	secret := "test-secret-key-12345678901234567890"
	userID := "user123"

	tok := generateClaudePoolToken(secret, userID)
	if !strings.HasPrefix(tok, ClaudePoolTokenPrefix) {
		t.Fatalf("expected token to start with %q, got %q", ClaudePoolTokenPrefix, tok)
	}
	if !strings.HasPrefix(tok, "sk-ant-oat01-") {
		t.Fatalf("expected token to look like sk-ant-oat01-*, got %q", tok)
	}

	// Validate parse + auth header helper.
	if uid, ok := parseClaudePoolToken(secret, tok); !ok || uid != userID {
		t.Fatalf("parseClaudePoolToken failed: ok=%v uid=%q want=%q", ok, uid, userID)
	}
	if ok, uid := isClaudePoolToken(secret, "Bearer "+tok); !ok || uid != userID {
		t.Fatalf("isClaudePoolToken failed: ok=%v uid=%q want=%q", ok, uid, userID)
	}

	// Legacy prefix should continue to work for already-issued tokens.
	legacy := ClaudePoolTokenLegacyPrefix + strings.TrimPrefix(tok, ClaudePoolTokenPrefix)
	if uid, ok := parseClaudePoolToken(secret, legacy); !ok || uid != userID {
		t.Fatalf("legacy parseClaudePoolToken failed: ok=%v uid=%q want=%q", ok, uid, userID)
	}
	if ok, uid := isClaudePoolToken(secret, "Bearer "+legacy); !ok || uid != userID {
		t.Fatalf("legacy isClaudePoolToken failed: ok=%v uid=%q want=%q", ok, uid, userID)
	}
}
