package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type chatGPTFixture struct {
	h          *proxyHandler
	account    *Account
	ownerToken string
	otherToken string
	upstream   *httptest.Server
	calls      atomic.Int64
}

func chatGPTTest(t *testing.T, upstream http.HandlerFunc) *chatGPTFixture {
	t.Helper()
	t.Setenv("POOL_JWT_SECRET", "chatgpt-test-secret")
	t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "chatgpt-test-encryption")
	f := &chatGPTFixture{}
	f.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.calls.Add(1); upstream(w, r) }))
	t.Cleanup(f.upstream.Close)
	store := testUsageStore(t)
	passport, err := newPassportStore(store.db, nil)
	if err != nil {
		t.Fatal(err)
	}
	addAuthorityPrincipal(t, passport, "desktop", PrincipalMember)
	addAuthorityPrincipal(t, passport, "other", PrincipalMember)
	makeToken := func(principal string) string {
		client, err := passport.createClient(principal, "desktop-test", nil)
		if err != nil {
			t.Fatal(err)
		}
		identity := principal + "-c-" + client.ID
		token, err := signJWT(getPoolJWTSecret(), map[string]any{"iss": "https://auth.openai.com", "sub": "pool|" + identity, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	f.ownerToken = makeToken("desktop")
	f.otherToken = makeToken("other")
	idToken, err := signJWT("provider-signing-key", map[string]any{"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "real-account", "chatgpt_user_id": "real-user"}})
	if err != nil {
		t.Fatal(err)
	}
	f.account = &Account{Type: AccountTypeCodex, ID: "cont", AccountID: "real-account", ChatGPTUserID: "real-user", AccessToken: "provider-secret", IDToken: idToken, PlanType: "promax"}
	pool := newPoolState([]*Account{f.account}, false)
	g, err := newChatGPTGateway(store.db, pool, f.upstream.URL, "https://codex.ppflix.net", f.upstream.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	f.h = &proxyHandler{cfg: &config{adminToken: "test-admin"}, pool: pool, passport: passport, chatGPT: g, metrics: newMetrics()}
	return f
}

func (f *chatGPTFixture) request(method, path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if token == "admin" {
		r.Header.Set("X-Admin-Token", "test-admin")
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}

func chatGPTMembership(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/backend-api/accounts/check/v4-2023-04-27" {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"accounts":{"real-account":{"account":{"account_id":"real-account","plan_type":"pro"}}}}`)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Set-Cookie", "secret-cookie")
	w.Header().Set("Authorization", "Bearer provider-secret")
	io.WriteString(w, "data: result\n\n")
}

func (f *chatGPTFixture) reserve(t *testing.T) {
	t.Helper()
	w := f.request("PUT", chatGPTPrefix+"/admin/reservation", "admin", `{"alias":"cont","principal_id":"desktop","enabled":true}`)
	if w.Code != 200 {
		t.Fatalf("reservation %d %s", w.Code, w.Body.String())
	}
}

func (f *chatGPTFixture) session(t *testing.T) (string, string) {
	t.Helper()
	w := f.request("POST", chatGPTPrefix+"/sessions", f.ownerToken, "")
	if w.Code != 200 {
		t.Fatalf("session %d %s", w.Code, w.Body.String())
	}
	var result struct {
		SessionID string            `json:"session_id"`
		Token     string            `json:"delegation_token"`
		Base      string            `json:"backend_api_base"`
		Metadata  map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Base != "https://codex.ppflix.net/pool/chatgpt/backend-api" || result.Metadata["account_id"] != "real-account" || result.Metadata["user_id"] != "real-user" || result.Metadata["plan_type"] != "pro" {
		t.Fatalf("incorrect real metadata: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "provider-secret") {
		t.Fatal("provider token leaked")
	}
	return result.Token, result.SessionID
}

func TestChatGPTIsolationAndForwarding(t *testing.T) {
	var body string
	f := chatGPTTest(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer provider-secret" || r.Header.Get("ChatGPT-Account-ID") != "real-account" {
			t.Errorf("wrong upstream identity %v", r.Header)
		}
		if r.Header.Get("X-Untrusted") != "" || r.Header.Get("X-Admin-Token") != "" {
			t.Error("uncontrolled headers forwarded")
		}
		if r.URL.Path == "/backend-api/f/conversation/prepare" {
			if r.Header.Get("OpenAI-Sentinel-Chat-Requirements-Token") != "integrity-test" || r.Header.Get("X-Conduit-Token") != "conduit-test" {
				t.Error("conversation integrity headers lost")
			}
			raw, _ := io.ReadAll(r.Body)
			body = string(raw)
			if r.URL.RawQuery != "mode=test" {
				t.Error("query changed")
			}
		}
		chatGPTMembership(w, r)
	})
	if w := f.request("GET", chatGPTPrefix+"/identity", f.ownerToken, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"principal_id":"desktop"`) {
		t.Fatalf("identity %s", w.Body.String())
	}
	f.reserve(t)
	if f.h.pool.candidate("", nil, AccountTypeCodex, "", "") != nil || f.h.pool.candidateByID("cont", AccountTypeCodex, "", "") != nil || f.h.pool.candidateWithCyberAccess(nil, AccountTypeCodex, "", "") != nil {
		t.Fatal("reserved account leaked to generic selectors")
	}
	f.h.pool.pin("conversation", "cont")
	if f.h.pool.candidate("conversation", nil, AccountTypeCodex, "", "") != nil {
		t.Fatal("reserved conversation pin leaked")
	}
	if w := f.request("POST", chatGPTPrefix+"/sessions", f.otherToken, ""); w.Code != 403 {
		t.Fatalf("other principal %d", w.Code)
	}
	if f.calls.Load() != 0 {
		t.Fatal("other principal reached upstream")
	}
	token, sid := f.session(t)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, _, _, ok := parsePoolCredentialRequest(req, getPoolJWTSecret()); ok {
		t.Fatal("delegation accepted as privileged pool credential")
	}
	payload := `{"messages":[{"arbitrary":true}],"model":"gpt-6-pro","nested":{"opaque":"unchanged"}}`
	r := httptest.NewRequest("POST", chatGPTPrefix+"/backend-api/f/conversation/prepare?mode=test", strings.NewReader(payload))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Untrusted", "discard")
	r.Header.Set("OpenAI-Sentinel-Chat-Requirements-Token", "integrity-test")
	r.Header.Set("X-Conduit-Token", "conduit-test")
	r.Header.Set("ChatGPT-Account-ID", "real-account")
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != 200 || body != payload || w.Body.String() != "data: result\n\n" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Authorization") != "" {
		t.Fatalf("forward mismatch %d %s body=%s headers=%v", w.Code, w.Body.String(), body, w.Header())
	}
	if w = f.request("DELETE", chatGPTPrefix+"/sessions/"+sid, token, ""); w.Code != 204 {
		t.Fatalf("delete %d", w.Code)
	}
	if w = f.request("GET", chatGPTPrefix+"/backend-api/models", token, ""); w.Code != 401 {
		t.Fatalf("revoked session %d", w.Code)
	}
}

func TestChatGPTRequiresLivePro(t *testing.T) {
	for _, plan := range []string{"free", "plus", "prolite"} {
		t.Run(plan, func(t *testing.T) {
			f := chatGPTTest(t, func(w http.ResponseWriter, r *http.Request) {
				respondJSON(w, map[string]any{"accounts": map[string]any{"real-account": map[string]any{"account": map[string]any{"account_id": "real-account", "plan_type": plan}}}})
			})
			f.reserve(t)
			w := f.request("POST", chatGPTPrefix+"/sessions", f.ownerToken, "")
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "Pro membership required") {
				t.Fatalf("non-Pro membership accepted: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestChatGPTPersistenceCollisionsAndReplacement(t *testing.T) {
	f := chatGPTTest(t, chatGPTMembership)
	f.reserve(t)
	token, _ := f.session(t)
	duplicate := &Account{Type: AccountTypeCodex, ID: "duplicate", AccountID: "real-account", ChatGPTUserID: "real-user", AccessToken: "provider-secret", PlanType: "promax"}
	f.h.pool.replace([]*Account{f.account, duplicate})
	if f.h.pool.candidateByID("duplicate", AccountTypeCodex, "", "") != nil {
		t.Fatal("duplicate physical account leaked")
	}
	if _, err := f.h.chatGPT.reserve("duplicate", "other", true); err == nil {
		t.Fatal("physical collision allowed")
	}
	if _, err := f.h.chatGPT.reserve("cont", "other", true); err == nil {
		t.Fatal("owner reassignment allowed")
	}
	replacementPool := newPoolState([]*Account{duplicate, f.account}, false)
	gateway, err := newChatGPTGateway(f.h.chatGPT.db, replacementPool, f.upstream.URL, "https://codex.ppflix.net", f.upstream.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	f.h.pool = replacementPool
	f.h.chatGPT = gateway
	if replacementPool.candidate("", nil, AccountTypeCodex, "", "") != nil {
		t.Fatal("durable reservation lost on reload")
	}
	if w := f.request("GET", chatGPTPrefix+"/backend-api/models", token, ""); w.Code != 200 {
		t.Fatalf("durable session lost %d %s", w.Code, w.Body.String())
	}
	replacement := &Account{Type: AccountTypeCodex, ID: "cont", AccountID: "different-account", ChatGPTUserID: "different-user", AccessToken: "wrong-secret", PlanType: "promax"}
	replacementPool.replace([]*Account{replacement})
	before := f.calls.Load()
	if w := f.request("GET", chatGPTPrefix+"/backend-api/models", token, ""); w.Code != 503 || !strings.Contains(w.Body.String(), "identity changed") {
		t.Fatalf("replacement %d %s", w.Code, w.Body.String())
	}
	if replacementPool.candidateByID("cont", AccountTypeCodex, "", "") != nil || before != f.calls.Load() {
		t.Fatal("replacement leaked")
	}
}

func TestChatGPTRejectsChangedClaims(t *testing.T) {
	f := chatGPTTest(t, chatGPTMembership)
	f.reserve(t)
	token, _ := f.session(t)
	changed, err := signJWT("provider-signing-key", map[string]any{"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "another-account", "chatgpt_user_id": "real-user"}})
	if err != nil {
		t.Fatal(err)
	}
	f.account.mu.Lock()
	f.account.AccessToken = changed
	f.account.mu.Unlock()
	before := f.calls.Load()
	w := f.request("GET", chatGPTPrefix+"/backend-api/models", token, "")
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "identity changed") || f.calls.Load() != before {
		t.Fatalf("changed token account reached upstream: %d %s", w.Code, w.Body.String())
	}
}

func TestChatGPTRevocationRefreshAndHealth(t *testing.T) {
	f := chatGPTTest(t, chatGPTMembership)
	f.reserve(t)
	token, _ := f.session(t)
	f.account.mu.Lock()
	f.account.ExpiresAt = time.Now().Add(-time.Second)
	f.account.mu.Unlock()
	refreshes := 0
	f.h.chatGPT.refresh = func(_ context.Context, a *Account) error {
		refreshes++
		a.mu.Lock()
		a.ExpiresAt = time.Now().Add(time.Hour)
		a.mu.Unlock()
		return nil
	}
	if w := f.request("GET", chatGPTPrefix+"/backend-api/models", token, ""); w.Code != 200 || refreshes != 1 {
		t.Fatalf("same account refresh %d %s calls %d", w.Code, w.Body.String(), refreshes)
	}
	for _, state := range []string{"disabled", "authentication failed", "cooling down"} {
		f.account.mu.Lock()
		f.account.Disabled = state == "disabled"
		f.account.Dead = state == "authentication failed"
		f.account.RateLimitUntil = time.Time{}
		if state == "cooling down" {
			f.account.RateLimitUntil = time.Now().Add(time.Hour)
		}
		f.account.mu.Unlock()
		before := f.calls.Load()
		w := f.request("GET", chatGPTPrefix+"/backend-api/models", token, "")
		if w.Code != 503 || !strings.Contains(w.Body.String(), state) || f.calls.Load() != before {
			t.Fatalf("health %s %d %s", state, w.Code, w.Body.String())
		}
	}
	f.account.mu.Lock()
	f.account.RateLimitUntil = time.Time{}
	f.account.mu.Unlock()
	f.h.passport.mu.Lock()
	f.h.passport.principals["desktop"].Status = PrincipalSuspended
	f.h.passport.mu.Unlock()
	if w := f.request("GET", chatGPTPrefix+"/backend-api/models", token, ""); w.Code != 401 {
		t.Fatalf("principal revocation %d", w.Code)
	}
	f.h.passport.mu.Lock()
	f.h.passport.principals["desktop"].Status = PrincipalActive
	f.h.passport.mu.Unlock()
	if _, err := f.h.chatGPT.reserve("cont", "desktop", false); err != nil {
		t.Fatal(err)
	}
	if w := f.request("GET", chatGPTPrefix+"/backend-api/models", token, ""); w.Code != 503 {
		t.Fatalf("reservation revocation %d", w.Code)
	}
	if f.h.pool.candidateByID("cont", AccountTypeCodex, "", "") != nil {
		t.Fatal("disabled reservation released private account")
	}
}

func TestChatGPTResponseCredentialRedaction(t *testing.T) {
	f := chatGPTTest(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/backend-api/echo-credential" {
			io.WriteString(w, `{"error":"provider-secret"}`)
			return
		}
		chatGPTMembership(w, r)
	})
	f.reserve(t)
	token, _ := f.session(t)
	response := f.request("GET", chatGPTPrefix+"/backend-api/echo-credential", token, "")
	if response.Code != 200 || strings.Contains(response.Body.String(), "provider-secret") || !strings.Contains(response.Body.String(), "[credential removed]") {
		t.Fatalf("provider credential leaked: %d %s", response.Code, response.Body.String())
	}
	chunks := io.MultiReader(strings.NewReader("data: provider-"), strings.NewReader("secret and refresh-"), strings.NewReader("secret\n\n"))
	w := httptest.NewRecorder()
	copyChatGPT(w, chunks, []string{"provider-secret", "refresh-secret", ""})
	if w.Body.String() != "data: [credential removed] and [credential removed]\n\n" {
		t.Fatalf("split provider credentials leaked: %s", w.Body.String())
	}
}

func TestChatGPTCapabilitiesAndWorkspace(t *testing.T) {
	for _, available := range []bool{false, true} {
		t.Run(map[bool]string{false: "unavailable", true: "available"}[available], func(t *testing.T) {
			f := chatGPTTest(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/backend-api/accounts/check/v4-2023-04-27" {
					json.NewEncoder(w).Encode(map[string]any{"accounts": map[string]any{"real-account": map[string]any{"account": map[string]any{"account_id": "real-account", "plan_type": "pro", "tbo_config": map[string]bool{"tbo_available": available}}}}})
					return
				}
				if r.URL.Path == "/backend-api/wham/accounts/check" {
					io.WriteString(w, `{"accounts":[{"id":"other-account","account_user_id":"other-seat","plan_type":"pro"},{"id":"real-account","account_user_id":"real-seat","account_user_role":"owner","structure":"personal","plan_type":"pro","is_zdr":false,"workspace_backend_origin":"https://outside.invalid","account_routing_override":"other"}],"default_account_id":"other-account"}`)
					return
				}
				http.NotFound(w, r)
			})
			f.reserve(t)
			created := f.request("POST", chatGPTPrefix+"/sessions", f.ownerToken, "")
			var session struct {
				Token        string `json:"delegation_token"`
				Capabilities struct {
					Dots bool `json:"dots"`
				} `json:"capabilities"`
			}
			if err := json.Unmarshal(created.Body.Bytes(), &session); err != nil {
				t.Fatal(err)
			}
			if created.Code != 200 || session.Capabilities.Dots != available {
				t.Fatalf("dots not derived from actual membership: %d %s", created.Code, created.Body.String())
			}
			routing := f.request("GET", chatGPTPrefix+"/backend-api/wham/accounts/check", session.Token, "")
			var result struct {
				Accounts []map[string]any `json:"accounts"`
				Default  string           `json:"default_account_id"`
			}
			if err := json.Unmarshal(routing.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if routing.Code != 200 || len(result.Accounts) != 1 || result.Default != "real-account" || result.Accounts[0]["account_user_id"] != "real-seat" || result.Accounts[0]["workspace_backend_origin"] != "NO_CONSTRAINT" || result.Accounts[0]["account_routing_override"] != "NO_CONSTRAINT" || strings.Contains(routing.Body.String(), "other-account") {
				t.Fatalf("unsafe native routing %d %s", routing.Code, routing.Body.String())
			}
		})
	}
}

func TestChatGPTMembershipFailsClosed(t *testing.T) {
	for _, response := range []string{`{}`, `{"accounts":{"other":{"account":{"account_id":"other","plan_type":"pro"}}}}`, `{"accounts":{"real-account":{"account":{"account_id":"other","plan_type":"pro"}}}}`, `{"accounts":{"real-account":{"account":{"account_id":"real-account"}}}}`} {
		t.Run(response, func(t *testing.T) {
			f := chatGPTTest(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, response) })
			f.reserve(t)
			if w := f.request("POST", chatGPTPrefix+"/sessions", f.ownerToken, ""); w.Code != 503 || strings.Contains(w.Body.String(), "delegation_token") {
				t.Fatalf("unverified membership activated %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestChatGPTRefreshIdentityAndNativeContext(t *testing.T) {
	f := chatGPTTest(t, chatGPTMembership)
	f.reserve(t)
	token, _ := f.session(t)
	owner, _, err := contextIdentity(f.account)
	if err != nil {
		t.Fatal(err)
	}
	native := &nativeContext{pool: f.h.pool}
	if _, _, err := native.credentials(owner, ""); err == nil {
		t.Fatal("legacy native context bypassed reservation")
	}
	f.account.mu.Lock()
	f.account.ExpiresAt = time.Now().Add(-time.Second)
	f.account.mu.Unlock()
	f.h.chatGPT.refresh = func(_ context.Context, a *Account) error {
		newToken, err := signJWT("provider-signing-key", map[string]any{"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "real-account", "chatgpt_user_id": "replacement-user"}})
		if err != nil {
			return err
		}
		a.mu.Lock()
		a.AccessToken = newToken
		a.ExpiresAt = time.Now().Add(time.Hour)
		a.mu.Unlock()
		return nil
	}
	before := f.calls.Load()
	w := f.request("GET", chatGPTPrefix+"/backend-api/models", token, "")
	if w.Code != 503 || !strings.Contains(w.Body.String(), "identity changed") || f.calls.Load() != before {
		t.Fatalf("changed refresh identity reached upstream %d %s", w.Code, w.Body.String())
	}
}

func TestChatGPTConcurrentReloadIsolation(t *testing.T) {
	f := chatGPTTest(t, chatGPTMembership)
	f.reserve(t)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iteration := 0; iteration < 100; iteration++ {
				if f.h.pool.candidate("conversation", nil, AccountTypeCodex, "", "") != nil || f.h.pool.candidateByID("cont", AccountTypeCodex, "", "") != nil {
					t.Error("reserved account selected during reload")
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for iteration := 0; iteration < 100; iteration++ {
			f.h.pool.replace([]*Account{f.account})
		}
	}()
	wg.Wait()
}

func TestChatGPTPathAndRedirectGuards(t *testing.T) {
	f := chatGPTTest(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/backend-api/redirect" {
			w.Header().Set("Location", "https://outside.invalid/private")
			w.WriteHeader(302)
			return
		}
		chatGPTMembership(w, r)
	})
	f.reserve(t)
	token, _ := f.session(t)
	for _, path := range []string{chatGPTPrefix + "/unknown", chatGPTPrefix + "/backend-api/../models", chatGPTPrefix + "/backend-api/%2fmodels", chatGPTPrefix + "/backend-api/%252fmodels", chatGPTPrefix + "/backend-api//models", chatGPTPrefix + "/backend-api/\\models", chatGPTPrefix + "/backend-api/models?account_id=other", chatGPTPrefix + "/backend-api/auth/token"} {
		before := f.calls.Load()
		w := f.request("GET", path, token, "")
		if w.Code < 400 || f.calls.Load() != before {
			t.Fatalf("poison path %s %d %s", path, w.Code, w.Body.String())
		}
	}
	for _, header := range []string{"Cookie", "ChatGPT-Account-ID", "OpenAI-Account-ID", "X-OpenAI-User-ID", "X-Api-Key"} {
		r := httptest.NewRequest("GET", chatGPTPrefix+"/backend-api/models", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set(header, "override")
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("override %s accepted %d", header, w.Code)
		}
	}
	if w := f.request("GET", chatGPTPrefix+"/backend-api/redirect", token, ""); w.Code != 503 || w.Header().Get("Location") != "" {
		t.Fatalf("redirect %d %v", w.Code, w.Header())
	}
	// Fixed-origin construction rejects URLs that could change resolution semantics.
	for _, origin := range []string{"http://chatgpt.com", "https://chatgpt.com/base", "https://user@chatgpt.com", "https://chatgpt.com?origin=other"} {
		if _, err := newChatGPTGateway(f.h.chatGPT.db, f.h.pool, origin, "https://codex.ppflix.net", f.upstream.Client().Transport); err == nil {
			t.Fatalf("unsafe origin accepted %s", origin)
		}
	}
}
