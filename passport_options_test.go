package main

import "testing"

func TestPassportExplicitOptions(t *testing.T) {
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "")
	t.Setenv("POOL_JWT_SECRET", "environment-fallback")
	store := testUsageStore(t)
	options := passportOptions{jwtSecret: "configured-secret", legacyAnalyticsSalt: " existing-origin-salt "}
	p, err := newPassportStore(store.db, nil, options)
	if err != nil {
		t.Fatal(err)
	}
	if p.jwtSecret != options.jwtSecret || p.analyticsSalt != "existing-origin-salt" {
		t.Fatal("explicit Passport options were not applied")
	}
	_, _, client, _, err := p.createGuest("operator", "Guest", "Guest", nil)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := generateClaudeAuth(options.jwtSecret, &PoolUser{ID: client.PrincipalID + "-c-" + client.ID, CreatedAt: client.CreatedAt})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.bootstrapOperator("operator", "operator@example.com", "Operator", "correct horse battery", credential.AccessToken); err != nil {
		t.Fatalf("configured-secret credential rejected: %v", err)
	}
	reloaded, err := newPassportStore(store.db, nil, passportOptions{jwtSecret: options.jwtSecret, legacyAnalyticsSalt: "replacement-salt"})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := reloaded.clientDownloadToken(reloaded.clients[client.ID])
	if err != nil || decrypted != client.DownloadToken || reloaded.analyticsSalt != "existing-origin-salt" {
		t.Fatal("reload changed credential decryption or the installed analytics salt")
	}
}

func TestPassportEncryptionOverride(t *testing.T) {
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "encryption-override")
	store := testUsageStore(t)
	p, err := newPassportStore(store.db, nil, passportOptions{jwtSecret: "first-secret"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, client, _, err := p.createGuest("operator", "Guest", "Guest", nil)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := newPassportStore(store.db, nil, passportOptions{jwtSecret: "second-secret"})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := reloaded.clientDownloadToken(reloaded.clients[client.ID])
	if err != nil || decrypted != client.DownloadToken {
		t.Fatal("configured JWT secret changed encryption despite the explicit encryption override")
	}
}
