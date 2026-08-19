package main

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func testUsageStore(t *testing.T) *usageStore {
	t.Helper()
	s, err := newUsageStore(filepath.Join(t.TempDir(), "proxy.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestPassportMigratesLegacyUserAndClient(t *testing.T) {
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "test-passport-encryption-key")
	s := testUsageStore(t)
	legacy := &PoolUserStore{users: map[string]*PoolUser{}, byTok: map[string]*PoolUser{}}
	u := &PoolUser{ID: "0123456789abcdef", Token: "download-old", Email: "friend@pool.local", PlanType: "pro", CreatedAt: time.Now()}
	legacy.users[u.ID] = u
	legacy.byTok[u.Token] = u
	p, err := newPassportStore(s.db, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.principal(u.ID); got == nil || got.Note != "legacy: friend@pool.local" {
		t.Fatalf("principal=%+v", got)
	}
	p.mu.RLock()
	c := p.clients["legacy-"+u.ID]
	p.mu.RUnlock()
	if c == nil || c.Label != "LEGACY DEFAULT" {
		t.Fatalf("client=%+v", c)
	}
	token, err := p.clientDownloadToken(c)
	if err != nil {
		t.Fatal(err)
	}
	if token != u.Token {
		t.Fatalf("download token = %q, want %q", token, u.Token)
	}
}

func TestMemberOnboardingAndRecoveryLinksAreSingleUse(t *testing.T) {
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "test-passport-encryption-key")
	store := testUsageStore(t)
	passport, err := newPassportStore(store.db, nil)
	if err != nil {
		t.Fatal(err)
	}

	onboarding, err := passport.createMemberLink("operator", "member@example.com", "Member", "onboard")
	if err != nil {
		t.Fatal(err)
	}
	member, oldSession, _, err := passport.redeemMemberLink(onboarding.Token, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if member.Kind != PrincipalMember || member.PasswordHash == "" {
		t.Fatalf("member=%+v", member)
	}
	if _, _, _, err := passport.redeemMemberLink(onboarding.Token, "another correct password"); err == nil {
		t.Fatal("onboarding link was reusable")
	}

	recovery, err := passport.createMemberLink("operator", member.Email, "", "recover")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := passport.redeemMemberLink(recovery.Token, "replacement password"); err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "/api/auth/me", nil)
	request.AddCookie(&http.Cookie{Name: "pool_session", Value: oldSession})
	if principal, _ := passport.authenticate(request); principal != nil {
		t.Fatal("recovery left a prior browser session active")
	}
	if _, _, _, err := passport.login(member.Email, "replacement password"); err != nil {
		t.Fatalf("replacement password rejected: %v", err)
	}
}

func TestLegacySignupClaimsExistingPrincipal(t *testing.T) {
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "test-passport-encryption-key")
	store := testUsageStore(t)
	legacy := &PoolUserStore{users: map[string]*PoolUser{}, byTok: map[string]*PoolUser{}}
	user := &PoolUser{ID: "legacy-person", Token: "legacy-download-token", Email: "legacy@pool.local", PlanType: "pro", CreatedAt: time.Now()}
	legacy.users[user.ID] = user
	legacy.byTok[user.Token] = user
	passport, err := newPassportStore(store.db, legacy)
	if err != nil {
		t.Fatal(err)
	}
	principal, _, _, err := passport.claimLegacyAccount("nicole", "NicoleLong2803!", user.Token)
	if err != nil {
		t.Fatal(err)
	}
	if principal.ID != user.ID || principal.Kind != PrincipalMember || principal.Username != "nicole" {
		t.Fatalf("claimed principal=%+v", principal)
	}
}

func TestBootstrapOperatorClaimsLegacyCredential(t *testing.T) {
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "test-passport-encryption-key")
	t.Setenv("POOL_JWT_SECRET", "test-jwt-secret-for-bootstrap")
	store := testUsageStore(t)
	legacy := &PoolUserStore{users: map[string]*PoolUser{}, byTok: map[string]*PoolUser{}}
	user := &PoolUser{ID: "operator-person", Token: "operator-download-token", Email: "operator@pool.local", PlanType: "pro", CreatedAt: time.Now()}
	legacy.users[user.ID] = user
	legacy.byTok[user.Token] = user
	passport, err := newPassportStore(store.db, legacy)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := generateClaudeAuth(getPoolJWTSecret(), user)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := passport.bootstrapOperator("operator", "", "Nicole", "NicoleLong2803!", credential.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if principal.ID != user.ID || principal.Kind != PrincipalOperator || principal.Username != "operator" {
		t.Fatalf("operator=%+v", principal)
	}
	if _, err := passport.bootstrapOperator("another", "", "", "another-long-password", ""); err == nil {
		t.Fatal("second operator bootstrap succeeded")
	}
}

func TestPasswordRoundTrip(t *testing.T) {
	h, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword(h, "correct horse battery staple") {
		t.Fatal("valid password rejected")
	}
	if verifyPassword(h, "wrong") {
		t.Fatal("wrong password accepted")
	}
}

func TestClientCredentialLimitAndLabel(t *testing.T) {
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "test-passport-encryption-key")
	s := testUsageStore(t)
	p, err := newPassportStore(s.db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.createClient("p1", "", nil); err == nil {
		t.Fatal("empty label accepted")
	}
	for i := 0; i < 20; i++ {
		if _, err = p.createClient("p1", "machine", nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = p.createClient("p1", "too many", nil); err == nil {
		t.Fatal("limit not enforced")
	}
}

func TestCredentialCutoffInvalidatesEveryEnvelope(t *testing.T) {
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "test-passport-encryption-key")
	s := testUsageStore(t)
	p, err := newPassportStore(s.db, nil)
	if err != nil {
		t.Fatal(err)
	}
	principal, _, client, _, err := p.createGuest("operator", "Dave from climbing", "Dave", nil)
	if err != nil {
		t.Fatal(err)
	}
	identity := principal.ID + "-c-" + client.ID
	oldUser := &PoolUser{ID: identity, Email: "dave@pool.local", PlanType: "pro", CreatedAt: time.Now()}
	oldCodex, err := generateCodexAuth("test-jwt-secret", oldUser)
	if err != nil {
		t.Fatal(err)
	}
	oldGemini, err := generateGeminiAuth("test-jwt-secret", oldUser)
	if err != nil {
		t.Fatal(err)
	}
	oldGeminiKey := generateGeminiAPIKey("test-jwt-secret", oldUser)
	oldClaude, err := generateClaudeAuth("test-jwt-secret", oldUser)
	if err != nil {
		t.Fatal(err)
	}
	oldDownload := client.DownloadToken

	if _, err = p.setPrincipalStatus("operator", principal.ID, PrincipalSuspended); err != nil {
		t.Fatal(err)
	}
	if _, err = p.setPrincipalStatus("operator", principal.ID, PrincipalActive); err != nil {
		t.Fatal(err)
	}

	assertDenied := func(name, parsedIdentity string, issuedAt time.Time, parsed bool) {
		t.Helper()
		if !parsed {
			t.Fatalf("%s credential did not parse", name)
		}
		if _, _, ok := p.authorizeIssuedCredential(parsedIdentity, issuedAt); ok {
			t.Fatalf("%s credential issued before cutoff was accepted", name)
		}
	}
	id, at, ok := parsePoolUserToken("test-jwt-secret", "Bearer "+oldCodex.Tokens.AccessToken)
	assertDenied("codex", id, at, ok)
	id, at, ok = parseGeminiOAuthPoolToken("test-jwt-secret", oldGemini.AccessToken)
	assertDenied("gemini oauth", id, at, ok)
	id, at, ok = parsePoolGeminiAPIKey("test-jwt-secret", oldGeminiKey)
	assertDenied("gemini api key", id, at, ok)
	id, at, ok = parseClaudePoolCredential("test-jwt-secret", oldClaude.AccessToken)
	assertDenied("claude", id, at, ok)
	if p.clientByDownloadToken(oldDownload) != nil {
		t.Fatal("old setup token survived principal suspension")
	}

	pr, activeClient, ok := p.credentialState(identity)
	if !ok {
		t.Fatal("restored credential is not active")
	}
	newUser := &PoolUser{ID: identity, Email: "dave@pool.local", PlanType: "pro", CreatedAt: time.Now(), credentialIssuedAt: pr.CredentialsValidAfter}
	if activeClient.ValidAfter.After(newUser.credentialIssuedAt) {
		newUser.credentialIssuedAt = activeClient.ValidAfter
	}
	newCodex, err := generateCodexAuth("test-jwt-secret", newUser)
	if err != nil {
		t.Fatal(err)
	}
	id, at, ok = parsePoolUserToken("test-jwt-secret", "Bearer "+newCodex.Tokens.AccessToken)
	if !ok {
		t.Fatal("fresh credential did not parse")
	}
	if _, _, allowed := p.authorizeIssuedCredential(id, at); !allowed {
		t.Fatal("fresh credential issued at cutoff was rejected")
	}
}

func TestSignedAndLegacyRefreshCutoffs(t *testing.T) {
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "test-passport-encryption-key")
	s := testUsageStore(t)
	p, err := newPassportStore(s.db, nil)
	if err != nil {
		t.Fatal(err)
	}
	principal, _, client, _, err := p.createGuest("operator", "Taylor", "Taylor", nil)
	if err != nil {
		t.Fatal(err)
	}
	identity := principal.ID + "-c-" + client.ID
	legacy := "poolrt_" + identity + "_legacy"
	parsedIdentity, _, signed, ok := parsePoolRefreshToken("test-jwt-secret", legacy)
	if !ok || signed || parsedIdentity != identity {
		t.Fatal("legacy refresh token did not parse")
	}
	if _, _, allowed := p.authorizeLegacyRefresh(identity); !allowed {
		t.Fatal("legacy refresh rejected before first cutoff")
	}
	old := generatePoolRefreshToken("test-jwt-secret", identity, time.Now().UTC())
	if _, err = p.setPrincipalStatus("operator", principal.ID, PrincipalSuspended); err != nil {
		t.Fatal(err)
	}
	if _, err = p.setPrincipalStatus("operator", principal.ID, PrincipalActive); err != nil {
		t.Fatal(err)
	}
	if _, _, allowed := p.authorizeLegacyRefresh(identity); allowed {
		t.Fatal("legacy refresh survived first cutoff")
	}
	parsedIdentity, issuedAt, signed, ok := parsePoolRefreshToken("test-jwt-secret", old)
	if !ok || !signed {
		t.Fatal("signed refresh token did not parse")
	}
	if _, _, allowed := p.authorizeIssuedCredential(parsedIdentity, issuedAt); allowed {
		t.Fatal("signed refresh survived cutoff")
	}
}

func TestDuckAnalyticsOutboxDrain(t *testing.T) {
	s := testUsageStore(t)
	d, err := newDuckAnalytics(filepath.Join(t.TempDir(), "usage.duckdb"), s.db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ru := RequestUsage{Timestamp: time.Now(), AccountID: "a", AccountType: AccountTypeCodex, UserID: "p1", ClientCredentialID: "mac", ProxyRequestID: "req-1", InputTokens: 10, OutputTokens: 5, BillableTokens: 15, Model: "gpt-test"}
	if err = s.recordWithCost(ru, 0.25); err != nil {
		t.Fatal(err)
	}
	d.Notify()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rows, err := d.UserHourly(context.Background(), "p1", time.Now().Add(-time.Hour))
		if err == nil && len(rows) == 1 {
			if rows[0].ClientCredentialID != "mac" || rows[0].BillableTokens != 15 {
				t.Fatalf("row=%+v", rows[0])
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("fact not drained")
}
