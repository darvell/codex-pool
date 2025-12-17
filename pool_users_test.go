package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSignAndValidateJWT(t *testing.T) {
	secret := "test-secret-key-12345678901234567890"
	claims := map[string]any{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iss": "codex-pool-proxy",
		"sub": "pool_user:test123",
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

	if validated["iss"] != "codex-pool-proxy" {
		t.Errorf("expected iss=codex-pool-proxy, got %v", validated["iss"])
	}
	if validated["sub"] != "pool_user:test123" {
		t.Errorf("expected sub=pool_user:test123, got %v", validated["sub"])
	}
}

func TestValidateJWTWrongSecret(t *testing.T) {
	claims := map[string]any{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iss": "codex-pool-proxy",
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
		"iss": "codex-pool-proxy",
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
		"iss": "codex-pool-proxy",
		"sub": "pool_user:abc123",
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
		"iss": "https://auth.openai.com", // Real OpenAI issuer
		"sub": "pool_user:abc123",
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
	if claims["iss"] != "codex-pool-proxy" {
		t.Errorf("expected iss=codex-pool-proxy, got %v", claims["iss"])
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

	// Check JSON serialization
	data, err := json.MarshalIndent(auth, "", "  ")
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}
	t.Logf("Generated oauth_creds.json:\n%s", string(data))
}
