package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestCodexWebSocketBridgesAntigravityTurns(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	var chatGPTFrames int
	var mu sync.Mutex
	chatGPT := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for {
			if _, _, err := conn.Read(r.Context()); err != nil {
				return
			}
			mu.Lock()
			chatGPTFrames++
			mu.Unlock()
		}
	}))
	defer chatGPT.Close()

	var antigravityBodies []string
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		mu.Lock()
		antigravityBodies = append(antigravityBodies, string(body))
		mu.Unlock()
		resp := antigravityHTTPResponse(http.StatusOK, antigravitySuccessSSE)
		resp.Header.Set("Content-Type", "text/event-stream")
		return resp, nil
	})

	codexAccount := &Account{Type: AccountTypeCodex, ID: "codex", AccessToken: "codex-token", AccountID: "acct", PlanType: "pro"}
	agAccount := &Account{Type: AccountTypeAntigravity, ID: "ag", AccessToken: "ag", ProjectID: "project", ModelRateLimits: map[string]time.Time{}, ModelBackoffLevels: map[string]int{}}
	model := "gemini-3.8-flash-medium"
	pool := newPoolState([]*Account{codexAccount, agAccount}, false)
	pool.antigravityModels.ReplaceAccount(agAccount.ID, AntigravityAccountSnapshot{FetchedAt: time.Now(), Models: map[string]AntigravityModelInfo{model: {ID: model}}})

	baseURL, _ := url.Parse(chatGPT.URL)
	daily, _ := url.Parse("https://daily.test")
	production, _ := url.Parse("https://production.test")
	h := &proxyHandler{
		cfg:                  &config{maxAttempts: 1, websocketReadLimit: 1 << 20, disableRefresh: true, maxInMemoryBodyBytes: 1 << 20, maxSpoolBodyBytes: 16 << 20},
		transport:            transport,
		antigravityTransport: transport,
		pool:                 pool,
		registry:             NewProviderRegistry(NewCodexProvider(baseURL, baseURL, baseURL), NewClaudeProvider(baseURL), NewGeminiProvider(baseURL, baseURL), NewAntigravityProvider(daily, production)),
		metrics:              newMetrics(),
		recent:               newRecentErrors(5),
		aliases:              newModelAliases(nil),
	}
	proxy := httptest.NewServer(h)
	defer proxy.Close()

	wsURL, _ := url.Parse(proxy.URL)
	wsURL.Scheme = "ws"
	wsURL.Path = "/responses"
	auth := "Bearer " + generateClaudePoolToken("test-secret", "ws-antigravity-user")
	client, _, err := websocket.Dial(context.Background(), wsURL.String(), &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {auth}}})
	if err != nil {
		t.Fatalf("dial proxy websocket: %v", err)
	}
	defer client.CloseNow()

	turn := func(frame string) map[string]any {
		t.Helper()
		if err := client.Write(context.Background(), websocket.MessageText, []byte(frame)); err != nil {
			t.Fatalf("write: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for {
			_, data, err := client.Read(ctx)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			var event map[string]any
			_ = json.Unmarshal(data, &event)
			switch event["type"] {
			case "response.completed":
				return event
			case "error", "response.failed":
				t.Fatalf("turn failed: %s", data)
			}
		}
	}

	first := turn(`{"type":"response.create","model":"antigravity/` + model + `","input":"hello"}`)
	responseID, _ := first["response"].(map[string]any)["id"].(string)
	if responseID == "" {
		t.Fatalf("completed event has no response id: %v", first)
	}
	turn(`{"type":"response.create","model":"antigravity/` + model + `","previous_response_id":"` + responseID + `","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"again"}]}]}`)

	mu.Lock()
	defer mu.Unlock()
	if chatGPTFrames != 0 {
		t.Fatalf("chatgpt.com received %d frames for an Antigravity model", chatGPTFrames)
	}
	if len(antigravityBodies) != 2 {
		t.Fatalf("antigravity requests = %d, want 2", len(antigravityBodies))
	}
	second := antigravityBodies[1]
	for _, want := range []string{"hello", "ok", "again"} {
		if !strings.Contains(second, want) {
			t.Fatalf("second turn is missing %q from the replayed conversation: %s", want, second)
		}
	}
}

func TestProviderWSTranscriptRejectsUnknownPrevious(t *testing.T) {
	transcript := &providerWSTranscript{turns: map[string][]json.RawMessage{}}
	if _, ok := transcript.expand([]byte(`{"model":"m","previous_response_id":"resp_elsewhere","input":[]}`)); ok {
		t.Fatal("expanded a previous_response_id this socket never produced")
	}
}
