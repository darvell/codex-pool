package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"go.etcd.io/bbolt"
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
	p, err := newPassportStore(s.db, legacy, passportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.principal(u.ID); got == nil || got.Note != "legacy: friend@pool.local" || got.Source != SourceMigratedCredential {
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
	passport, err := newPassportStore(store.db, nil, passportOptions{})
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
	if member.Kind != PrincipalMember || member.PasswordHash == "" || member.Source != SourceOperatorInvite {
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
	passport, err := newPassportStore(store.db, legacy, passportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	principal, _, _, err := passport.claimLegacyAccount("nicole", "NicoleLong2803!", user.Token)
	if err != nil {
		t.Fatal(err)
	}
	// First legacy signup becomes operator when none exists.
	if principal.ID != user.ID || principal.Kind != PrincipalOperator || principal.Username != "nicole" {
		t.Fatalf("claimed principal=%+v", principal)
	}
	// Second signup should be a member since operator now exists.
	user2 := &PoolUser{ID: "legacy-person-2", Token: "legacy-download-token-2", Email: "legacy2@pool.local", PlanType: "pro", CreatedAt: time.Now()}
	legacy.users[user2.ID] = user2
	legacy.byTok[user2.Token] = user2
	principal2, _, _, err := passport.claimLegacyAccount("bob", "BobLong2803!!", user2.Token)
	if err != nil {
		t.Fatal(err)
	}
	if principal2.Kind != PrincipalMember || principal2.Source != SourceLegacyCodeSignup {
		t.Fatalf("second signup should be member, got %s", principal2.Kind)
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
	passport, err := newPassportStore(store.db, legacy, passportOptions{})
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
	p, err := newPassportStore(s.db, nil, passportOptions{})
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
	p, err := newPassportStore(s.db, nil, passportOptions{})
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
	p, err := newPassportStore(s.db, nil, passportOptions{})
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
	ru := RequestUsage{Timestamp: time.Now().UTC().Truncate(time.Microsecond), AccountID: "a", AccountType: AccountTypeCodex, UserID: "p1", ClientCredentialID: "mac", ProxyRequestID: "req-1", InputTokens: 10, CachedInputTokens: 3, OutputTokens: 5, ReasoningTokens: 2, BillableTokens: 15, Model: "gpt-test"}
	var ledgerHour time.Time
	if err := d.db.QueryRow("SELECT CAST(? AS TIMESTAMPTZ) AT TIME ZONE current_setting('TimeZone')", ru.Timestamp).Scan(&ledgerHour); err != nil {
		t.Fatal(err)
	}
	if err = s.recordWithCost(ru, 0.25); err != nil {
		t.Fatal(err)
	}
	var sequence uint64
	if err := s.db.View(func(tx *bbolt.Tx) error {
		sequence = tx.Bucket([]byte(bucketAnalyticsOutbox)).Sequence()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if sequence == 0 {
		t.Fatal("usage did not enqueue an analytics fact")
	}
	d.Notify()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	var acknowledged uint64
	var pending int
	for {
		rows, err := d.UserHourly(ctx, ru.UserID, ru.Timestamp.Add(-time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) > 1 {
			t.Fatalf("hourly rows=%+v, want one", rows)
		}
		if len(rows) == 1 {
			want := AnalyticsPoint{
				Hour: ledgerHour.Format("2006-01-02T15"), AccountType: string(ru.AccountType), ClientCredentialID: ru.ClientCredentialID,
				InputTokens: ru.InputTokens, CachedTokens: ru.CachedInputTokens, OutputTokens: ru.OutputTokens,
				ReasoningTokens: ru.ReasoningTokens, BillableTokens: ru.BillableTokens, RequestCount: 1, APIEquivalentCostUSD: 0.25,
			}
			if rows[0] != want {
				t.Fatalf("hourly row=%#v, want %#v", rows[0], want)
			}
		}
		if err := s.db.View(func(tx *bbolt.Tx) error {
			pending = tx.Bucket([]byte(bucketAnalyticsOutbox)).Stats().KeyN
			ack := tx.Bucket([]byte(bucketAnalyticsState)).Get([]byte(analyticsAckKey))
			if len(ack) == 8 {
				acknowledged = binary.BigEndian.Uint64(ack)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 && pending == 0 && acknowledged == sequence {
			var persistedAt time.Time
			if err := d.db.QueryRowContext(ctx, "SELECT observed_at FROM usage_events WHERE proxy_request_id = ?", ru.ProxyRequestID).Scan(&persistedAt); err != nil {
				t.Fatal(err)
			}
			if !persistedAt.Equal(ru.Timestamp) {
				t.Fatalf("persisted timestamp=%s, want %s", persistedAt, ru.Timestamp)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("worker did not drain and acknowledge fact: rows=%+v pending=%d acknowledged=%d want=%d", rows, pending, acknowledged, sequence)
		case <-tick.C:
		}
	}
}

func TestConsoleUsageHoursFollowsQuery(t *testing.T) {
	h, passport, _, session := testOperatorAPI(t)
	member := insertTestPrincipal(t, passport, "member", PrincipalMember, "member", "member@example.com")
	duck, err := newDuckAnalytics(filepath.Join(t.TempDir(), "hours.duckdb"), h.store.db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = duck.Close() })
	h.duckAnalytics = duck
	now := time.Now().UTC()
	for _, usage := range []RequestUsage{
		{Timestamp: now.Add(-time.Hour), AccountID: "a", UserID: member.ID, ProxyRequestID: "recent", BillableTokens: 10},
		{Timestamp: now.Add(-48 * time.Hour), AccountID: "a", UserID: member.ID, ProxyRequestID: "older", BillableTokens: 20},
	} {
		if err := h.store.recordWithCost(usage, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := duck.drain(10); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		query string
		rows  int
		total int64
	}{
		{"", 2, 30},
		{"?hours=24", 1, 10},
		{"?hours=invalid", 2, 30},
	} {
		t.Run(test.query, func(t *testing.T) {
			request := authorityRequest(http.MethodGet, "/api/console/principals/"+member.ID+"/usage"+test.query, session, "")
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d: %s", response.Code, response.Body.String())
			}
			var result struct {
				Principal Principal        `json:"principal"`
				Hourly    []AnalyticsPoint `json:"hourly"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			var total int64
			for _, row := range result.Hourly {
				total += row.BillableTokens
			}
			if result.Principal.ID != member.ID || len(result.Hourly) != test.rows || total != test.total {
				t.Fatalf("usage=%+v, want %d rows and %d tokens", result, test.rows, test.total)
			}
		})
	}
}

func TestPrincipalSourceBackfillPreservesMigratedIdentityAfterClaim(t *testing.T) {
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "test-passport-encryption-key")
	store := testUsageStore(t)
	legacy := &PoolUserStore{users: map[string]*PoolUser{}, byTok: map[string]*PoolUser{}}
	user := &PoolUser{ID: "migrated-person", Token: "old-download", Email: "old@pool.local", CreatedAt: time.Now()}
	legacy.users[user.ID] = user
	legacy.byTok[user.Token] = user
	passport, err := newPassportStore(store.db, legacy, passportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if passport.principal(user.ID).Source != SourceMigratedCredential {
		t.Fatal("migration source missing")
	}
	// Simulate records created before the source field existed, including a
	// claimed principal whose note/role no longer describe its original origin.
	old := *passport.principal(user.ID)
	old.Source = ""
	old.Kind = PrincipalMember
	old.Username = "friend"
	old.Note = "edited note"
	if err := store.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx.Bucket([]byte(bucketPrincipals)), old.ID, &old) }); err != nil {
		t.Fatal(err)
	}
	reloaded, err := newPassportStore(store.db, nil, passportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.principal(user.ID); got.Source != SourceMigratedCredential || got.Kind != PrincipalMember || got.Note != "edited note" {
		t.Fatalf("backfilled=%+v", got)
	}
}

func TestPrincipalSourceBackfillDoesNotGuessFromLegacyNote(t *testing.T) {
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "test-passport-encryption-key")
	store := testUsageStore(t)
	_, err := newPassportStore(store.db, nil, passportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	old := &Principal{ID: "unknown-person", Kind: PrincipalGuest, Status: PrincipalActive, Note: "legacy: unknown", CreatedAt: time.Now()}
	if err := store.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx.Bucket([]byte(bucketPrincipals)), old.ID, old) }); err != nil {
		t.Fatal(err)
	}
	reloaded, err := newPassportStore(store.db, nil, passportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.principal(old.ID).Source; got != "" {
		t.Fatalf("guessed source: %q", got)
	}
}
