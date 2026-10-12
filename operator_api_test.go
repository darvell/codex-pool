package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

func testOperatorAPI(t *testing.T) (*proxyHandler, *PassportStore, *Principal, authoritySession) {
	t.Helper()
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "test-operator-api-encryption-key")
	store := testUsageStore(t)
	passport, err := newPassportStore(store.db, nil)
	if err != nil {
		t.Fatal(err)
	}
	operator := &Principal{ID: "operator-one", Kind: PrincipalOperator, Status: PrincipalActive, Username: "operator", CreatedAt: time.Now().UTC()}
	if err := passport.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx.Bucket([]byte(bucketPrincipals)), operator.ID, operator) }); err != nil {
		t.Fatal(err)
	}
	passport.mu.Lock()
	passport.principals[operator.ID] = operator
	passport.mu.Unlock()
	sessionToken, csrf, err := passport.createAuthenticatedSession(operator.ID)
	if err != nil {
		t.Fatal(err)
	}
	h := &proxyHandler{cfg: &config{}, passport: passport, pool: newPoolState(nil, false), store: store, metrics: newMetrics(), startTime: time.Now()}
	return h, passport, operator, authoritySession{token: sessionToken, csrf: csrf}
}

func operatorBearerRequest(method, path, token string, body ...string) *http.Request {
	var input *bytes.Reader
	if len(body) > 0 {
		input = bytes.NewReader([]byte(body[0]))
	} else {
		input = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, path, input)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestOperatorTokenDigestLifecycleAndOwnerAuthority(t *testing.T) {
	_, passport, operator, _ := testOperatorAPI(t)
	token, secret, err := passport.createOperatorToken(operator.ID, operator.ID, "diagnostics", operatorScopeRead, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, "poolop_"+token.ID+"_") {
		t.Fatalf("unexpected secret format %q", secret)
	}
	if principal, authenticated := passport.authenticateOperatorToken(secret); principal == nil || authenticated.ID != token.ID {
		t.Fatal("issued token did not authenticate")
	}
	if err := passport.db.View(func(tx *bbolt.Tx) error {
		value := tx.Bucket([]byte(bucketOperatorTokens)).Get([]byte(token.ID))
		if bytes.Contains(value, []byte(secret)) || bytes.Contains(value, []byte(strings.TrimPrefix(secret, "poolop_"+token.ID+"_"))) {
			t.Fatal("operator secret persisted in plaintext")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A restart reloads authority from the same Bolt database without a recoverable secret.
	reloaded, err := newPassportStore(passport.db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if principal, _ := reloaded.authenticateOperatorToken(secret); principal == nil {
		t.Fatal("token did not survive Passport reload")
	}
	if err := reloaded.revokeOperatorToken(operator.ID, operator.ID, token.ID); err != nil {
		t.Fatal(err)
	}
	if principal, _ := reloaded.authenticateOperatorToken(secret); principal != nil {
		t.Fatal("revoked token authenticated")
	}

	write, writeSecret, err := reloaded.createOperatorToken(operator.ID, operator.ID, "automation", operatorScopeWrite, time.Now().Add(30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.db.Update(func(tx *bbolt.Tx) error {
		var record operatorTokenRecord
		bucket := tx.Bucket([]byte(bucketOperatorTokens))
		if err := json.Unmarshal(bucket.Get([]byte(write.ID)), &record); err != nil {
			return err
		}
		record.ExpiresAt = time.Now().Add(-time.Minute)
		return putJSON(bucket, write.ID, &record)
	}); err != nil {
		t.Fatal(err)
	}
	if principal, _ := reloaded.authenticateOperatorToken(writeSecret); principal != nil {
		t.Fatal("expired token authenticated")
	}

	_, ownerSecret, err := reloaded.createOperatorToken(operator.ID, operator.ID, "owner check", operatorScopeRead, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	owner := reloaded.principal(operator.ID)
	owner.Kind = PrincipalMember
	if err := reloaded.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx.Bucket([]byte(bucketPrincipals)), owner.ID, owner) }); err != nil {
		t.Fatal(err)
	}
	reloaded.mu.Lock()
	reloaded.principals[owner.ID] = owner
	reloaded.mu.Unlock()
	if principal, _ := reloaded.authenticateOperatorToken(ownerSecret); principal != nil {
		t.Fatal("demoted owner token authenticated")
	}
}

func TestOperatorBearerCapabilityMatrixAndNoFallback(t *testing.T) {
	h, passport, operator, session := testOperatorAPI(t)
	_, readSecret, err := passport.createOperatorToken(operator.ID, operator.ID, "read", operatorScopeRead, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, writeSecret, err := passport.createOperatorToken(operator.ID, operator.ID, "write", operatorScopeWrite, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, method, path, token string
		want                      int
	}{
		{"read discovery", http.MethodGet, "/api/operator/v1", readSecret, 200},
		{"read denied write", http.MethodPost, "/admin/reload", readSecret, 403},
		{"write allowed read", http.MethodGet, "/api/operator/v1/whoami", writeSecret, 200},
		{"unknown defaults deny", http.MethodGet, "/api/operator/v1/future", writeSecret, 403},
		{"inference defaults deny", http.MethodPost, "/v1/responses", writeSecret, 403},
		{"alias path defaults deny", http.MethodGet, "/api/pool/models", readSecret, 403},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			h.ServeHTTP(response, operatorBearerRequest(tc.method, tc.path, tc.token))
			if response.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, tc.want, response.Body.String())
			}
		})
	}

	// An explicit invalid operator token cannot borrow a valid browser cookie.
	r := operatorBearerRequest(http.MethodGet, "/api/operator/v1", "poolop_missing_invalid")
	r.AddCookie(&http.Cookie{Name: "pool_session", Value: session.token})
	response := httptest.NewRecorder()
	h.ServeHTTP(response, r)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid bearer fell back to cookie: %d", response.Code)
	}

	// Model/user bearer credentials and random bearer strings are not operator credentials.
	response = httptest.NewRecorder()
	h.ServeHTTP(response, operatorBearerRequest(http.MethodGet, "/api/operator/v1", "not-an-operator-model-key"))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("model-like key status=%d", response.Code)
	}
}

func TestOperatorTokenManagementRequiresRecentCookieAndCSRF(t *testing.T) {
	h, passport, _, session := testOperatorAPI(t)
	body := `{"label":"diagnostics","scope":"read"}`
	request := authorityRequest(http.MethodPost, "/api/operator-tokens", session, body)
	request.Header.Del("X-CSRF-Token")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status=%d", response.Code)
	}

	request = authorityRequest(http.MethodPost, "/api/operator-tokens", session, body)
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "poolop_") {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var issued struct {
		Token  OperatorToken `json:"token"`
		Secret string        `json:"secret"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	request = authorityRequest(http.MethodPost, "/api/operator-tokens/"+issued.Token.ID+"/replace", session, "")
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), issued.Secret) {
		t.Fatalf("replace status=%d body=%s", response.Code, response.Body.String())
	}
	if principal, _ := passport.authenticateOperatorToken(issued.Secret); principal != nil {
		t.Fatal("replaced token remained valid")
	}

	// Make the session stale and ensure CSRF alone is insufficient.
	digest := hashToken(session.token)
	if err := passport.db.Update(func(tx *bbolt.Tx) error {
		var stored passportSession
		bucket := tx.Bucket([]byte(bucketPassportSessions))
		if err := json.Unmarshal(bucket.Get(digest[:]), &stored); err != nil {
			return err
		}
		stored.AuthenticatedAt = time.Now().Add(-time.Hour)
		return putJSONBytes(bucket, digest[:], &stored)
	}); err != nil {
		t.Fatal(err)
	}
	request = authorityRequest(http.MethodPost, "/api/operator-tokens", session, body)
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "recent authentication") {
		t.Fatalf("stale session status=%d body=%s", response.Code, response.Body.String())
	}
	fresh, _, err := passport.createOperatorToken("operator-one", "operator-one", "replace stale", operatorScopeRead, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	request = authorityRequest(http.MethodPost, "/api/operator-tokens/"+fresh.ID+"/replace", session, "")
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "recent authentication") {
		t.Fatalf("stale replacement status=%d body=%s", response.Code, response.Body.String())
	}
}

func putJSONBytes(bucket *bbolt.Bucket, key []byte, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return bucket.Put(key, data)
}

func TestOperatorAccountingPaginationAndDashboardCoverage(t *testing.T) {
	h, passport, operator, _ := testOperatorAPI(t)
	duck, err := newDuckAnalytics(filepath.Join(t.TempDir(), "analytics.duckdb"), passport.db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = duck.Close() })
	h.duckAnalytics = duck
	analytics, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = analytics.Close() })
	h.analyticsStore = analytics
	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 3; i++ {
		fact := AnalyticsFact{EventID: "event-" + string(rune('a'+i)), ProxyRequestID: "request-" + string(rune('a'+i)), ObservedAt: now.Add(-time.Duration(i) * time.Minute), PrincipalID: "person", ClientCredentialID: "client", OriginID: "ip_hash", AccountID: "raw-account-secret", AccountType: "codex", PlanType: "pro", ModelReported: "gpt-reported", ModelNormalized: "gpt-normalized", NormalizationVersion: "model-id-v1", InputTokens: 100, CacheReadTokens: 20, CacheCreationTokens: 5, OutputTokens: 10, ReasoningTokens: 3, BillableTokens: 113, APIEquivalentCostUSD: .01, PricingVersion: analyticsPricingVersion, UsageCompleteness: "complete", Source: "live", SourceGrain: "request"}
		_, err = duck.db.Exec(`INSERT INTO usage_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, fact.EventID, fact.ProxyRequestID, 0, "upstream-secret", 0, fact.ObservedAt, fact.PrincipalID, fact.ClientCredentialID, fact.OriginID, fact.AccountID, fact.AccountType, fact.PlanType, fact.ModelReported, fact.ModelNormalized, fact.NormalizationVersion, fact.InputTokens, fact.CacheReadTokens, fact.CacheCreationTokens, fact.OutputTokens, fact.ReasoningTokens, fact.BillableTokens, fact.APIEquivalentCostUSD, fact.PricingVersion, fact.UsageCompleteness, fact.Source, fact.SourceGrain)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, secret, err := passport.createOperatorToken(operator.ID, operator.ID, "diagnostics", operatorScopeRead, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/operator/v1/accounting/requests?limit=2&from=" + now.Add(-time.Hour).Format(time.RFC3339) + "&to=" + now.Add(time.Hour).Format(time.RFC3339)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, operatorBearerRequest(http.MethodGet, path, secret))
	if response.Code != 200 {
		t.Fatalf("first page status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "raw-account-secret") || strings.Contains(response.Body.String(), "upstream-secret") {
		t.Fatalf("accounting response leaked raw identifier: %s", response.Body.String())
	}
	var page struct {
		Requests []OperatorAccountingRequest `json:"requests"`
		Next     string                      `json:"next_cursor"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Requests) != 2 || page.Next == "" {
		t.Fatalf("unexpected first page %+v", page)
	}
	for _, item := range page.Requests {
		if item.PricingProvenance != "version_only" {
			t.Fatalf("pricing version overstated provenance: %+v", item)
		}
	}
	response = httptest.NewRecorder()
	h.ServeHTTP(response, operatorBearerRequest(http.MethodGet, path+"&cursor="+page.Next, secret))
	if response.Code != 200 {
		t.Fatalf("second page status=%d body=%s", response.Code, response.Body.String())
	}
	var second struct {
		Requests []OperatorAccountingRequest `json:"requests"`
	}
	_ = json.Unmarshal(response.Body.Bytes(), &second)
	if len(second.Requests) != 1 || second.Requests[0].EventID == page.Requests[0].EventID {
		t.Fatalf("pagination did not advance: %+v", second)
	}

	for _, dashboard := range []string{"/api/pool/stats", "/api/pool/users", "/api/pool/origins", "/api/pool/daily-breakdown", "/api/pool/hourly", "/api/pool/signal", "/api/pool/catalog", "/api/me/usage", "/api/console/principals", "/api/console/analytics-health"} {
		response = httptest.NewRecorder()
		h.ServeHTTP(response, operatorBearerRequest(http.MethodGet, dashboard, secret))
		if response.Code != http.StatusOK {
			t.Fatalf("dashboard %s status=%d body=%s", dashboard, response.Code, response.Body.String())
		}
	}
}

func TestOperatorReadSanitizesPassesAndAudit(t *testing.T) {
	h, passport, operator, _ := testOperatorAPI(t)
	_, _, _, passSecret, err := passport.createGuest(operator.ID, "sensitive note", "Guest", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, operatorSecret, err := passport.createOperatorToken(operator.ID, operator.ID, "read", operatorScopeRead, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, operatorBearerRequest(http.MethodGet, "/api/passes", operatorSecret))
	if response.Code != 200 {
		t.Fatalf("passes status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), passSecret) || strings.Contains(response.Body.String(), "/join#") {
		t.Fatalf("pass read leaked usable link: %s", response.Body.String())
	}
	response = httptest.NewRecorder()
	h.ServeHTTP(response, operatorBearerRequest(http.MethodGet, "/api/console/audit", operatorSecret))
	if response.Code != 200 {
		t.Fatalf("audit status=%d body=%s", response.Code, response.Body.String())
	}
	var entries []AuditEntry
	if err := json.Unmarshal(response.Body.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Detail != "" {
			t.Fatalf("audit detail was not redacted: %+v", entry)
		}
	}
}

func TestOperatorOpenAPIRegistryAndSecretFreeExports(t *testing.T) {
	if err := validateOperatorOpenAPIRoutes(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUBLIC_URL", "https://pool.example.test")
	h, passport, operator, _ := testOperatorAPI(t)
	_, secret, err := passport.createOperatorToken(operator.ID, operator.ID, "read", operatorScopeRead, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/operator/v1/openapi.json", "/api/operator/v1/guide", "/api/operator/v1/models", "/api/operator/v1/config/pi"} {
		response := httptest.NewRecorder()
		h.ServeHTTP(response, operatorBearerRequest(http.MethodGet, path, secret))
		if response.Code != 200 {
			t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), secret) {
			t.Fatalf("%s leaked operator token", path)
		}
	}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, operatorBearerRequest(http.MethodGet, "/api/operator/v1/config/pi?catalog=full", secret))
	if !strings.Contains(response.Body.String(), "CODEX_POOL_MODEL_API_KEY") || strings.Contains(response.Body.String(), `"apiKey":"`+secret) {
		t.Fatalf("Pi export is not credential-free: %s", response.Body.String())
	}
}

func TestOperatorTokenCannotRecoverAccountsAndLegacySessionIsNotRecent(t *testing.T) {
	h, passport, operator, _ := testOperatorAPI(t)
	password := "correct horse battery staple"
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	operator.PasswordHash = hash
	operator.Email = "operator@example.test"
	member := &Principal{ID: "member-one", Kind: PrincipalMember, Status: PrincipalActive, Username: "member", Email: "member@example.test", CreatedAt: time.Now().UTC()}
	guest := &Principal{ID: "guest-one", Kind: PrincipalGuest, Status: PrincipalActive, Email: "guest@example.test", CreatedAt: time.Now().UTC()}
	if err := passport.db.Update(func(tx *bbolt.Tx) error {
		if err := putJSON(tx.Bucket([]byte(bucketPrincipals)), operator.ID, operator); err != nil {
			return err
		}
		if err := putJSON(tx.Bucket([]byte(bucketPrincipals)), member.ID, member); err != nil {
			return err
		}
		return putJSON(tx.Bucket([]byte(bucketPrincipals)), guest.ID, guest)
	}); err != nil {
		t.Fatal(err)
	}
	passport.mu.Lock()
	passport.principals[operator.ID] = operator
	passport.principals[member.ID] = member
	passport.principals[guest.ID] = guest
	passport.mu.Unlock()

	_, writeSecret, err := passport.createOperatorToken(operator.ID, operator.ID, "write", operatorScopeWrite, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{operator.Email, member.Email, guest.Email} {
		before := 0
		_ = passport.db.View(func(tx *bbolt.Tx) error {
			before = tx.Bucket([]byte(bucketMemberRecoveryLinks)).Stats().KeyN
			return nil
		})
		response := httptest.NewRecorder()
		h.ServeHTTP(response, operatorBearerRequest(http.MethodPost, "/api/console/members", writeSecret, `{"email":"`+email+`","purpose":"recover"}`))
		if response.Code != http.StatusForbidden {
			t.Fatalf("recover %s status=%d body=%s", email, response.Code, response.Body.String())
		}
		after := 0
		_ = passport.db.View(func(tx *bbolt.Tx) error {
			after = tx.Bucket([]byte(bucketMemberRecoveryLinks)).Stats().KeyN
			return nil
		})
		if after != before {
			t.Fatalf("recovery link persisted for %s", email)
		}
	}

	client, err := passport.createClient(operator.ID, "legacy setup", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/auth/legacy", strings.NewReader(`{"download_token":"`+client.DownloadToken+`"}`)))
	if response.Code != http.StatusOK {
		t.Fatalf("legacy exchange: %d %s", response.Code, response.Body.String())
	}
	var legacyBody struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &legacyBody); err != nil {
		t.Fatal(err)
	}
	legacy := authoritySession{csrf: legacyBody.CSRF}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == "pool_session" {
			legacy.token = cookie.Value
		}
	}
	issue := httptest.NewRecorder()
	h.ServeHTTP(issue, authorityRequest(http.MethodPost, "/api/operator-tokens", legacy, `{"label":"blocked","scope":"write"}`))
	if issue.Code != http.StatusForbidden || !strings.Contains(issue.Body.String(), "recent authentication") {
		t.Fatalf("legacy session minted token: %d %s", issue.Code, issue.Body.String())
	}

	_, loginToken, loginCSRF, err := passport.login(operator.Username, password)
	if err != nil {
		t.Fatal(err)
	}
	issue = httptest.NewRecorder()
	h.ServeHTTP(issue, authorityRequest(http.MethodPost, "/api/operator-tokens", authoritySession{token: loginToken, csrf: loginCSRF}, `{"label":"allowed","scope":"read"}`))
	if issue.Code != http.StatusOK {
		t.Fatalf("password session issue: %d %s", issue.Code, issue.Body.String())
	}
}

func TestOperatorAuthorizationHeaderPrecedenceAndAuditFailClosed(t *testing.T) {
	h, passport, operator, session := testOperatorAPI(t)
	h.cfg.adminToken = "break-glass"
	_, readSecret, err := passport.createOperatorToken(operator.ID, operator.ID, "read", operatorScopeRead, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, writeSecret, err := passport.createOperatorToken(operator.ID, operator.ID, "write", operatorScopeWrite, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	r := operatorBearerRequest(http.MethodPost, "/admin/clear-rate-limits", readSecret)
	r.Header.Set("Authorization", "bearer "+readSecret)
	r.Header.Set("X-Admin-Token", "break-glass")
	r.AddCookie(&http.Cookie{Name: "pool_session", Value: session.token})
	response := httptest.NewRecorder()
	h.ServeHTTP(response, r)
	if response.Code != http.StatusForbidden {
		t.Fatalf("lowercase read borrowed authority: %d %s", response.Code, response.Body.String())
	}

	for _, auth := range []string{"Bearer model-key", "Random value"} {
		r = httptest.NewRequest(http.MethodGet, "/api/pool/stats", nil)
		r.Header.Set("Authorization", auth)
		r.Header.Set("X-Admin-Token", "break-glass")
		r.AddCookie(&http.Cookie{Name: "pool_session", Value: session.token})
		response = httptest.NewRecorder()
		h.ServeHTTP(response, r)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%q fell through ambient authority: %d", auth, response.Code)
		}
	}
	r = httptest.NewRequest(http.MethodPost, "/api/operator-tokens", strings.NewReader(`{"label":"ambient","scope":"write"}`))
	r.Header.Set("Authorization", "Bearer model-key")
	r.AddCookie(&http.Cookie{Name: "pool_session", Value: session.token})
	r.AddCookie(&http.Cookie{Name: "pool_csrf", Value: session.csrf})
	r.Header.Set("X-CSRF-Token", session.csrf)
	response = httptest.NewRecorder()
	h.ServeHTTP(response, r)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("model bearer borrowed token-management cookie: %d", response.Code)
	}

	r = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	r.Header.Set("Authorization", "Basic poolop_malformed")
	response = httptest.NewRecorder()
	h.ServeHTTP(response, r)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("malformed operator credential reached proxy: %d", response.Code)
	}

	account := &Account{ID: "audit-account", Type: AccountTypeCodex, RateLimitUntil: time.Now().Add(time.Hour)}
	h.pool = newPoolState([]*Account{account}, false)
	if err := passport.db.Update(func(tx *bbolt.Tx) error { return tx.DeleteBucket([]byte(bucketPassportAudit)) }); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	h.ServeHTTP(response, operatorBearerRequest(http.MethodPost, "/admin/clear-rate-limits", writeSecret))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("audit failure did not fail closed: %d %s", response.Code, response.Body.String())
	}
	account.mu.Lock()
	stillLimited := account.RateLimitUntil.After(time.Now())
	account.mu.Unlock()
	if !stillLimited {
		t.Fatal("mutation ran despite audit failure")
	}
}

func TestOperatorPricingAndConfiguredPiSemantics(t *testing.T) {
	now := time.Now().UTC()
	if cost, ok := operatorAdvertisedModelCost("definitely-unknown-model", now); ok || cost != nil {
		t.Fatalf("unknown pricing reported known: %+v %v", cost, ok)
	}
	if cost, ok := operatorAdvertisedModelCost("gpt-5.5", now); !ok || cost == nil || cost.CacheWrite != 0 {
		t.Fatal("known pricing (including a legitimate zero-valued component) reported unknown")
	}
	foundCodex := false
	for _, model := range operatorModelManifest(nil, now) {
		if model.Provider == string(AccountTypeCodex) && model.PiSupported {
			foundCodex = true
			if model.PiProviderKey != "codex" || model.PiAPI != "openai-codex-responses" {
				t.Fatalf("Pi provider/protocol identity lost: %+v", model)
			}
			break
		}
	}
	if !foundCodex {
		t.Fatal("manifest did not join Codex Pi metadata by provider and model")
	}
	if got := piProviderKeyForDescriptor(string(AccountTypeOpencodeGo)); got != "opencode-go" {
		t.Fatalf("OpenCode provider key=%q", got)
	}

	t.Setenv("PUBLIC_URL", "https://pool.example.test")
	h, passport, operator, _ := testOperatorAPI(t)
	_, secret, err := passport.createOperatorToken(operator.ID, operator.ID, "read", operatorScopeRead, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, operatorBearerRequest(http.MethodGet, "/api/operator/v1/config/pi", secret))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"providers": {}`) {
		t.Fatalf("empty configured export: %d %s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	h.ServeHTTP(response, operatorBearerRequest(http.MethodGet, "/api/operator/v1/config/pi?catalog=full", secret))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"codex"`) {
		t.Fatalf("full export missing catalog: %d %s", response.Code, response.Body.String())
	}

	h.pool = newPoolState([]*Account{{ID: "configured-dead", Type: AccountTypeCodex, Dead: true}}, false)
	response = httptest.NewRecorder()
	h.ServeHTTP(response, operatorBearerRequest(http.MethodGet, "/api/operator/v1/config/pi", secret))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"codex"`) {
		t.Fatalf("configured unavailable provider was dropped: %d %s", response.Code, response.Body.String())
	}
}

func TestOperatorTokenItemControlsAndWriteHandlers(t *testing.T) {
	h, passport, operator, session := testOperatorAPI(t)
	create := func(scope string) OperatorToken {
		response := httptest.NewRecorder()
		h.ServeHTTP(response, authorityRequest(http.MethodPost, "/api/operator-tokens", session, `{"label":"`+scope+`","scope":"`+scope+`"}`))
		if response.Code != http.StatusOK {
			t.Fatalf("create %s: %d %s", scope, response.Code, response.Body.String())
		}
		var result struct {
			Token  OperatorToken `json:"token"`
			Secret string        `json:"secret"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		want := 90 * 24 * time.Hour
		if scope == operatorScopeWrite {
			want = 30 * 24 * time.Hour
		}
		if delta := result.Token.ExpiresAt.Sub(result.Token.CreatedAt); delta < want-time.Minute || delta > want+time.Minute {
			t.Fatalf("%s default expiry %s", scope, delta)
		}
		return result.Token
	}
	read := create(operatorScopeRead)
	_ = create(operatorScopeWrite)

	r := authorityRequest(http.MethodDelete, "/api/operator-tokens/"+read.ID, session, "")
	r.Header.Del("X-CSRF-Token")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, r)
	if response.Code != http.StatusForbidden {
		t.Fatalf("revoke without csrf: %d", response.Code)
	}

	other := &Principal{ID: "operator-two", Kind: PrincipalOperator, Status: PrincipalActive, Username: "two", CreatedAt: time.Now().UTC()}
	if err := passport.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx.Bucket([]byte(bucketPrincipals)), other.ID, other) }); err != nil {
		t.Fatal(err)
	}
	passport.mu.Lock()
	passport.principals[other.ID] = other
	passport.mu.Unlock()
	otherToken, otherCSRF, err := passport.createAuthenticatedSession(other.ID)
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	h.ServeHTTP(response, authorityRequest(http.MethodDelete, "/api/operator-tokens/"+read.ID, authoritySession{token: otherToken, csrf: otherCSRF}, ""))
	if response.Code != http.StatusNotFound {
		t.Fatalf("cross-owner revoke: %d %s", response.Code, response.Body.String())
	}

	response = httptest.NewRecorder()
	h.ServeHTTP(response, authorityRequest(http.MethodDelete, "/api/operator-tokens/"+read.ID, session, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", response.Code, response.Body.String())
	}
	stored, err := passport.operatorToken(operator.ID, read.ID)
	if err != nil || stored.Status != "revoked" {
		t.Fatalf("not revoked: %+v %v", stored, err)
	}

	_, writeSecret, err := passport.createOperatorToken(operator.ID, operator.ID, "writes", operatorScopeWrite, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	h.ServeHTTP(response, operatorBearerRequest(http.MethodPost, "/api/passes", writeSecret, `{"note":"automation pass","display_name":"Bot"}`))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "setup_token") {
		t.Fatalf("write pass handler: %d %s", response.Code, response.Body.String())
	}
}

func TestOperatorResponsesRedactRawAccountIdentifiers(t *testing.T) {
	h, passport, operator, _ := testOperatorAPI(t)
	rawID := "raw-account-sentinel"
	account := &Account{ID: rawID, Type: AccountTypeCodex, PlanType: "pro", Dead: true, Totals: AccountUsage{RequestCount: 1, TotalBillableTokens: 99}}
	h.pool = newPoolState([]*Account{account}, false)
	h.metrics.incCyberPolicy(rawID, "suppressed_ws")
	if err := h.store.db.Update(func(tx *bbolt.Tx) error {
		usage, _ := json.Marshal(AccountUsage{RequestCount: 2})
		if err := tx.Bucket([]byte(bucketAccountUsage)).Put([]byte(rawID), usage); err != nil {
			return err
		}
		sample, _ := json.Marshal(CapacitySample{Timestamp: time.Now().UTC(), AccountID: rawID, PlanType: "pro"})
		return tx.Bucket([]byte(bucketCapacitySamples)).Put([]byte("sample-sentinel"), sample)
	}); err != nil {
		t.Fatal(err)
	}
	_, readSecret, err := passport.createOperatorToken(operator.ID, operator.ID, "read", operatorScopeRead, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/pool/stats", "/admin/accounts", "/admin/tokens"} {
		response := httptest.NewRecorder()
		h.ServeHTTP(response, operatorBearerRequest(http.MethodGet, path, readSecret))
		if response.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), rawID) {
			t.Fatalf("%s leaked raw ID: %s", path, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), hashAccountID(rawID)) {
			t.Fatalf("%s omitted public ID: %s", path, response.Body.String())
		}
	}

	_, writeSecret, err := passport.createOperatorToken(operator.ID, operator.ID, "write", operatorScopeWrite, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	publicID := hashAccountID(rawID)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, operatorBearerRequest(http.MethodPost, "/admin/accounts/"+publicID+"/resurrect", writeSecret))
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), rawID) || !strings.Contains(response.Body.String(), publicID) {
		t.Fatalf("mutation ID redaction: %d %s", response.Code, response.Body.String())
	}

	agRaw := "antigravity-raw-sentinel"
	h.pool = newPoolState([]*Account{{ID: agRaw, Type: AccountTypeAntigravity, AccessToken: "upstream-secret"}}, false)
	ag := NewAntigravityProvider(mustParse("http://127.0.0.1:1"), mustParse("http://127.0.0.1:1"))
	h.registry = &ProviderRegistry{byType: map[AccountType]Provider{AccountTypeAntigravity: ag}}
	h.transport = http.DefaultTransport
	h.antigravityTransport = http.DefaultTransport
	response = httptest.NewRecorder()
	h.ServeHTTP(response, operatorBearerRequest(http.MethodPost, "/admin/antigravity/models/sync", writeSecret))
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), agRaw) || strings.Contains(response.Body.String(), "upstream-secret") || !strings.Contains(response.Body.String(), hashAccountID(agRaw)) {
		t.Fatalf("Antigravity sync redaction: %d %s", response.Code, response.Body.String())
	}
}

func TestOperatorOpenAPIHasExecutableClientContract(t *testing.T) {
	var spec struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(operatorOpenAPI, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Info.Version == "" {
		t.Fatal("missing bundled API version")
	}
	payloadWrites := map[string]bool{"POST /admin/economics": true, "POST /api/console/members": true, "POST /api/passes": true, "PATCH /api/passes/{id}": true, "PATCH /api/principals/{id}": true}
	for path, item := range spec.Paths {
		for method, raw := range item {
			if method != "get" && method != "post" && method != "patch" && method != "delete" {
				continue
			}
			var op struct {
				Parameters []struct {
					Name, In string
					Required bool
				} `json:"parameters"`
				RequestBody json.RawMessage            `json:"requestBody"`
				Responses   map[string]json.RawMessage `json:"responses"`
			}
			if err := json.Unmarshal(raw, &op); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"id"} {
				if !strings.Contains(path, "{"+name+"}") {
					continue
				}
				found := false
				for _, p := range op.Parameters {
					if p.Name == name && p.In == "path" && p.Required {
						found = true
					}
				}
				if !found {
					t.Fatalf("%s %s lacks required path parameter", method, path)
				}
			}
			if op.Responses["200"] == nil || op.Responses["401"] == nil || op.Responses["403"] == nil {
				t.Fatalf("%s %s lacks success/auth responses", method, path)
			}
			key := strings.ToUpper(method) + " " + path
			if payloadWrites[key] && len(op.RequestBody) == 0 {
				t.Fatalf("%s lacks request body", key)
			}
		}
	}
	for _, schema := range []string{"OperatorToken", "ModelManifest", "ModelEntry", "PiConfig", "PiProvider", "AccountingRecord", "AccountingPage", "PoolStats", "Signal"} {
		if len(spec.Components.Schemas[schema]) == 0 {
			t.Fatalf("missing schema %s", schema)
		}
	}
}

func validateOperatorResponseSchema(t *testing.T, method, path string, body []byte) {
	t.Helper()
	python := os.Getenv("OPERATOR_SCHEMA_PYTHON")
	if python == "" {
		python = "python3"
	}
	if err := exec.Command(python, "-c", "import jsonschema").Run(); err != nil {
		t.Skip("development-only Python jsonschema package is unavailable")
	}
	cmd := exec.Command(python, "scripts/validate_operator_api_payload.py", "docs/openapi/operator-v1.openapi.json", method, path)
	cmd.Stdin = bytes.NewReader(body)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %s does not conform to deployed OpenAPI: %v\n%s\npayload: %s", method, path, err, output, body)
	}
}

func TestOperatorOpenAPIConformsToRealResponses(t *testing.T) {
	t.Setenv("PUBLIC_URL", "https://pool.example.test")
	h, passport, operator, _ := testOperatorAPI(t)
	duck, err := newDuckAnalytics(filepath.Join(t.TempDir(), "schema.duckdb"), passport.db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = duck.Close() })
	h.duckAnalytics = duck
	rawID := "schema-raw-account"
	h.pool = newPoolState([]*Account{{
		ID: rawID, Type: AccountTypeCodex, PlanType: "pro", NeedsVerification: true, CyberAccess: true,
		ExpiresAt: time.Now().UTC().Add(time.Hour), LastRefresh: time.Now().UTC(), HealthError: "must be redacted",
		Usage:  UsageSnapshot{PrimaryUsed: .2, HasCredits: true, RetrievedAt: time.Now().UTC(), Source: "test"},
		Totals: AccountUsage{TotalInputTokens: 10, TotalBillableTokens: 12, RequestCount: 1, LastUpdated: time.Now().UTC()},
	}}, false)
	_, secret, err := passport.createOperatorToken(operator.ID, operator.ID, "schema", operatorScopeRead, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/api/console/principals", "/admin/accounts", "/api/operator/v1/whoami",
		"/api/operator/v1/models", "/api/operator/v1/config/pi", "/api/operator/v1/accounting/requests",
	} {
		response := httptest.NewRecorder()
		h.ServeHTTP(response, operatorBearerRequest(http.MethodGet, path, secret))
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), rawID) || strings.Contains(response.Body.String(), "must be redacted") {
			t.Fatalf("%s leaked account diagnostics: %s", path, response.Body.String())
		}
		validateOperatorResponseSchema(t, http.MethodGet, path, response.Body.Bytes())
	}
}

func TestOperatorMutationErrorsDoNotLeakBackendDetails(t *testing.T) {
	h, passport, operator, _ := testOperatorAPI(t)
	analytics, err := newAnalyticsStore(filepath.Join(t.TempDir(), "economics.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = analytics.Close() })
	h.analyticsStore = analytics
	rawID := "raw-account-error-sentinel"
	upstreamSecret := "upstream-body-secret-sentinel"
	account := &Account{ID: rawID, Type: AccountTypeCodex, RefreshToken: "refresh", AccessToken: "old", File: filepath.Join(t.TempDir(), "account.json")}
	credential, _ := json.Marshal(CodexAuthJSON{Tokens: &TokenData{AccessToken: account.AccessToken, RefreshToken: account.RefreshToken}})
	if err := os.WriteFile(account.File, credential, 0o600); err != nil {
		t.Fatal(err)
	}
	h.pool = newPoolState([]*Account{account}, false)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, upstreamSecret, http.StatusBadGateway)
	}))
	defer upstream.Close()
	codex := NewCodexProvider(mustParse(upstream.URL), mustParse(upstream.URL), mustParse(upstream.URL))
	h.registry = &ProviderRegistry{byType: map[AccountType]Provider{AccountTypeCodex: codex}}
	h.refreshTransport = http.DefaultTransport
	_, secret, err := passport.createOperatorToken(operator.ID, operator.ID, "write", operatorScopeWrite, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	publicID := hashAccountID(rawID)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, operatorBearerRequest(http.MethodPost, "/admin/economics", secret,
		`{"kind":"link","account_id":"`+publicID+`","subscription_id":"seat"}`))
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), rawID) || response.Body.String() != "economics update failed\n" {
		t.Fatalf("economics error was not sanitized: %d %q", response.Code, response.Body.String())
	}
	breakGlassEconomics := httptest.NewRequest(http.MethodPost, "/admin/economics", strings.NewReader(
		`{"kind":"link","account_id":"`+rawID+`","subscription_id":"seat"}`))
	breakGlassEconomics.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	h.handleEconomicsAdmin(response, breakGlassEconomics)
	if !strings.Contains(response.Body.String(), rawID) {
		t.Fatalf("break-glass economics detail was unexpectedly removed: %q", response.Body.String())
	}

	response = httptest.NewRecorder()
	h.ServeHTTP(response, operatorBearerRequest(http.MethodPost, "/admin/accounts/"+publicID+"/refresh", secret))
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), rawID) || strings.Contains(response.Body.String(), upstreamSecret) || response.Body.String() != `{"error":"refresh failed"}`+"\n" {
		t.Fatalf("refresh error was not sanitized: %d %q", response.Code, response.Body.String())
	}
	account.mu.Lock()
	account.RefreshBlocked = false
	account.refreshAttemptAt = time.Time{}
	account.mu.Unlock()
	if err := os.WriteFile(account.File, credential, 0o600); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	h.forceRefreshAccount(response, rawID)
	if !strings.Contains(response.Body.String(), upstreamSecret) {
		t.Fatalf("break-glass refresh detail was unexpectedly removed: %q", response.Body.String())
	}
}

func TestOperatorTokenPersistsAcrossDatabaseReopen(t *testing.T) {
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "operator-reopen-encryption-key")
	path := filepath.Join(t.TempDir(), "passport.db")
	db, err := bbolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketAnalyticsState))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	passport, err := newPassportStore(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	operator := &Principal{ID: "reopen-operator", Kind: PrincipalOperator, Status: PrincipalActive, Username: "reopen", CreatedAt: time.Now().UTC()}
	if err := db.Update(func(tx *bbolt.Tx) error { return putJSON(tx.Bucket([]byte(bucketPrincipals)), operator.ID, operator) }); err != nil {
		t.Fatal(err)
	}
	passport.mu.Lock()
	passport.principals[operator.ID] = operator
	passport.mu.Unlock()
	_, secret, err := passport.createOperatorToken(operator.ID, operator.ID, "reopen", operatorScopeRead, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = bbolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	passport, err = newPassportStore(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if principal, _ := passport.authenticateOperatorToken(secret); principal == nil || principal.ID != operator.ID {
		t.Fatal("token did not survive actual close/reopen")
	}
}
