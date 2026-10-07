package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func vibeTestHandler(t *testing.T, plan string) (*proxyHandler, *atomic.Int32) {
	t.Helper()
	base, _ := url.Parse("https://api.mistral.ai")
	var challenge string
	var exchanges atomic.Int32
	process := randomHex(8)
	h := &proxyHandler{
		cfg:  &config{poolDir: t.TempDir(), mistralBase: base, usageRefresh: time.Minute},
		pool: newPoolState(nil, false), metrics: newMetrics(), recent: newRecentErrors(5),
		registry: NewProviderRegistry(&CodexProvider{}, &ClaudeProvider{}, &GeminiProvider{}, NewMistralProvider(base), newMistralVibeProvider(base)),
	}
	h.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var output any
		switch r.URL.Path {
		case "/api/vibe/sign-in":
			var input map[string]string
			if json.NewDecoder(r.Body).Decode(&input) != nil || input["code_challenge_method"] != "S256" {
				t.Error("missing PKCE challenge")
			}
			challenge = input["code_challenge"]
			output = map[string]any{"process_id": process, "sign_in_url": vibeConsoleURL + "/vibe/sign-in/" + process, "poll_url": vibeConsoleURL + "/api/vibe/sign-in/" + process, "expires_at": time.Now().Add(time.Minute)}
		case "/api/vibe/sign-in/" + process:
			output = map[string]string{"status": "completed", "exchange_token": "test-exchange"}
		case "/api/vibe/sign-in/" + process + "/exchange":
			exchanges.Add(1)
			var input map[string]string
			if json.NewDecoder(r.Body).Decode(&input) != nil {
				t.Error("invalid exchange request")
			}
			digest := sha256.Sum256([]byte(input["code_verifier"]))
			if input["exchange_token"] != "test-exchange" || base64.RawURLEncoding.EncodeToString(digest[:]) != challenge {
				t.Error("exchange does not match PKCE challenge")
			}
			output = map[string]string{"api_key": "test-vibe-key"}
		case "/api/vibe/whoami":
			if r.Header.Get("Authorization") != "Bearer test-vibe-key" {
				t.Error("whoami did not validate the exchanged key")
			}
			output = map[string]string{"plan_type": plan, "plan_name": "INDIVIDUAL", "api_base": "https://api.mistral.ai"}
		case "/v1/models":
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer test-vibe-key" {
				t.Error("model admission must use GET and the exchanged key")
			}
			output = map[string]any{"data": []any{map[string]any{"id": "mistral-large-latest", "max_context_length": 128000, "capabilities": map[string]bool{"completion_chat": true, "function_calling": true}}}}
		default:
			t.Errorf("unexpected upstream call: %s", r.URL.Path)
			output = map[string]string{}
		}
		body, _ := json.Marshal(output)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})
	return h, &exchanges
}

func vibeTestRequest(body, actor string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/pool/accounts/mistral-vibe/status", strings.NewReader(body))
	return r.WithContext(context.WithValue(r.Context(), providerContributionActorKey{}, actor))
}

func vibeTestSession(t *testing.T, h *proxyHandler) string {
	t.Helper()
	w := httptest.NewRecorder()
	h.startVibeSignIn(w, vibeTestRequest("{}", "member-a"))
	var response struct {
		ID  string `json:"session_id"`
		URL string `json:"oauth_url"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.ID == "" || !vibeAuthURL(response.URL, "/") {
		t.Fatalf("start failed: %s", w.Body.String())
	}
	t.Cleanup(func() { vibeSignIns.Lock(); delete(vibeSignIns.sessions, response.ID); vibeSignIns.Unlock() })
	return response.ID
}

func TestVibeSignInCompletesOnce(t *testing.T) {
	h, exchanges := vibeTestHandler(t, "CHAT")
	id := vibeTestSession(t, h)
	body := `{"session_id":"` + id + `"}`
	var wait sync.WaitGroup
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			w := httptest.NewRecorder()
			h.vibeSignInStatus(w, vibeTestRequest(body, "member-a"))
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"complete"`) {
				t.Errorf("completion: %s", w.Body.String())
			}
			if strings.Contains(w.Body.String(), "test-vibe-key") {
				t.Error("credential exposed to browser")
			}
		}()
	}
	wait.Wait()
	if exchanges.Load() != 1 {
		t.Fatalf("exchanged %d times", exchanges.Load())
	}
	files, err := os.ReadDir(filepath.Join(h.cfg.poolDir, "mistral_vibe"))
	if err != nil || len(files) != 1 {
		t.Fatalf("account files: %v %v", files, err)
	}
	fileInfo, err := os.Stat(filepath.Join(h.cfg.poolDir, "mistral_vibe", files[0].Name()))
	if err != nil || fileInfo.Mode().Perm() != 0600 {
		t.Fatalf("credential permissions: %v %v", fileInfo, err)
	}
	accounts, err := loadPool(h.cfg.poolDir, h.registry)
	if err != nil {
		t.Fatal(err)
	}
	for _, pool := range []*poolState{h.pool, newPoolState(accounts, false)} {
		if pool.candidateForModel("conversation", nil, AccountTypeMistralVibe, "", "", "mistral-vibe/mistral-large-latest") == nil {
			t.Error("validated subscription must be immediately routable and survive reload")
		}
		if pool.candidateForModel("", nil, AccountTypeMistral, "", "", "mistral/mistral-large-latest") != nil {
			t.Error("subscription credential leaked to the API pool")
		}
	}
	for _, account := range accounts {
		account.vibeAccount.ValidatedAt = time.Now().Add(-vibePlanTTL)
	}
	if newPoolState(accounts, false).candidateForModel("", nil, AccountTypeMistralVibe, "", "", "mistral-vibe/mistral-large-latest") != nil {
		t.Error("expired entitlement remained routable")
	}
}

func TestVibeSignInRejectsAPIPlan(t *testing.T) {
	h, _ := vibeTestHandler(t, "API")
	id := vibeTestSession(t, h)
	w := httptest.NewRecorder()
	h.vibeSignInStatus(w, vibeTestRequest(`{"session_id":"`+id+`"}`, "member-a"))
	if !strings.Contains(w.Body.String(), `"status":"error"`) {
		t.Fatalf("API plan admitted: %s", w.Body.String())
	}
	if h.pool.count() != 0 {
		t.Error("API credential added to subscription pool")
	}
	if _, err := os.Stat(filepath.Join(h.cfg.poolDir, "mistral_vibe")); !os.IsNotExist(err) {
		t.Fatal("rejected credential was persisted")
	}
}

func TestVibeSessionOwnerAndExpiry(t *testing.T) {
	h, exchanges := vibeTestHandler(t, "CHAT")
	id := vibeTestSession(t, h)
	body := `{"session_id":"` + id + `"}`
	w := httptest.NewRecorder()
	h.vibeSignInStatus(w, vibeTestRequest(body, "member-b"))
	if w.Code != http.StatusForbidden || exchanges.Load() != 0 {
		t.Error("another member advanced the session")
	}
	vibeSignIns.Lock()
	session := vibeSignIns.sessions[id]
	vibeSignIns.Unlock()
	session.ExpiresAt = time.Now().Add(-time.Second)
	w = httptest.NewRecorder()
	h.vibeSignInStatus(w, vibeTestRequest(body, "member-a"))
	if !strings.Contains(w.Body.String(), `"status":"expired"`) || exchanges.Load() != 0 || session.Verifier != "" {
		t.Error("expired session retained or exchanged its verifier")
	}
}

func TestVibeURLsAndPlanBoundary(t *testing.T) {
	for _, value := range []string{"http://console.mistral.ai/api/vibe/poll", "https://console.mistral.ai.evil.invalid/api/vibe/poll", "https://user@console.mistral.ai/api/vibe/poll", "https://console.mistral.ai/api/vibe/../other", "https://console.mistral.ai/api/vibe/%2e%2e/other", "https://console.mistral.ai/other"} {
		if vibeAuthURL(value, "/api/vibe/") {
			t.Errorf("unsafe poll URL accepted: %s", value)
		}
	}
	for _, plan := range []string{"FREE", "UNKNOWN", ""} {
		if (&vibeAccountInfo{PlanType: "CHAT", PlanName: plan, ValidatedAt: time.Now()}).current() {
			t.Errorf("unsupported plan accepted: %q", plan)
		}
	}
	h, _ := vibeTestHandler(t, "CHAT")
	model := "mistral-vibe/mistral-large-latest"
	provider, _, rewritten := h.modelRouteOverride("/v1/messages", model, []byte(`{"model":"`+model+`"}`))
	if provider == nil || provider.Type() != AccountTypeMistralVibe || rewritten != nil {
		t.Error("Vibe must route separately and normalize only after translation")
	}
	apiAccount := &Account{ID: "api", Type: AccountTypeMistral, Models: map[string]DiscoveredModel{"mistral-large-latest": {ID: "mistral-large-latest"}}}
	if newPoolState([]*Account{apiAccount}, false).candidateForModel("", nil, AccountTypeMistralVibe, "", "", model) != nil {
		t.Error("Vibe silently fell back to a paid API account")
	}
}
