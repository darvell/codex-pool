package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fakeCodexUpstream lets each test script per-account behavior on a
// single httptest server. The handler dispatches to a script based on
// the ChatGPT-Account-ID header so we can simulate both the flagged and
// the cyber-access account behind one upstream URL.
type fakeCodexUpstream struct {
	server *httptest.Server
	mu     sync.Mutex
	hits   map[string]int
	scripts map[string]func(ctx context.Context, conn *websocket.Conn)
	wg      sync.WaitGroup
}

func newFakeCodexUpstream(t *testing.T) *fakeCodexUpstream {
	t.Helper()
	f := &fakeCodexUpstream{
		hits:    map[string]int{},
		scripts: map[string]func(context.Context, *websocket.Conn){},
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acctID := r.Header.Get("ChatGPT-Account-ID")
		f.mu.Lock()
		f.hits[acctID]++
		script, ok := f.scripts[acctID]
		f.mu.Unlock()
		if !ok {
			http.Error(w, "no script for account "+acctID, http.StatusBadRequest)
			return
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			t.Logf("upstream accept error: %v", err)
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		f.wg.Add(1)
		defer f.wg.Done()
		script(ctx, conn)
	}))
	t.Cleanup(func() {
		f.server.Close()
		f.wg.Wait()
	})
	return f
}

func (f *fakeCodexUpstream) on(acctID string, script func(context.Context, *websocket.Conn)) {
	f.mu.Lock()
	f.scripts[acctID] = script
	f.mu.Unlock()
}

func (f *fakeCodexUpstream) hitCount(acctID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[acctID]
}

type codexProxyFixture struct {
	server  *httptest.Server
	handler *proxyHandler
}

func newCodexProxyFixture(t *testing.T, base *url.URL, accounts []*Account) *codexProxyFixture {
	t.Helper()
	codex := NewCodexProvider(base, base, base)
	claude := NewClaudeProvider(base)
	gemini := NewGeminiProvider(base, base)
	registry := NewProviderRegistry(codex, claude, gemini)

	h := &proxyHandler{
		cfg: &config{
			requestTimeout:             5 * time.Second,
			maxInMemoryBodyBytes:       1024,
			websocketReadLimit:         128 * 1024 * 1024,
			websocketHeartbeatInterval: 0,
			disableRefresh:             true,
		},
		transport: http.DefaultTransport,
		pool:      newPoolState(accounts, false),
		registry:  registry,
		metrics:   newMetrics(),
		recent:    newRecentErrors(8),
	}
	h.cfg.debug.Store(true)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &codexProxyFixture{server: srv, handler: h}
}

func dialClientWS(t *testing.T, fx *codexProxyFixture, headers http.Header) *websocket.Conn {
	t.Helper()
	u, _ := url.Parse(fx.server.URL)
	u.Scheme = "ws"
	u.Path = "/responses"
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	conn, _, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	conn.SetReadLimit(64 * 1024 * 1024)
	t.Cleanup(func() { conn.CloseNow() })
	return conn
}

func mustReadUntil(t *testing.T, conn *websocket.Conn, marker string, timeout time.Duration) []string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var seen []string
	for time.Now().Before(deadline) {
		readCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, data, err := conn.Read(readCtx)
		cancel()
		if err != nil {
			break
		}
		seen = append(seen, string(data))
		if strings.Contains(string(data), "cyber_policy") || strings.Contains(string(data), "cybersecurity") {
			t.Fatalf("client received cybersecurity-risk frame: %s", string(data))
		}
		if strings.Contains(string(data), marker) {
			return seen
		}
	}
	return seen
}

// 1) Cyber policy mid-stream triggers a silent swap. Client never sees
// the policy frame; the cyber upstream receives a replayed
// response.create; the conversation gets pinned to the cyber account.
func TestCyberPolicyMidStreamSwapsSilently(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	upstream := newFakeCodexUpstream(t)

	upstream.on("acct_shiv", func(ctx context.Context, conn *websocket.Conn) {
		_, _, err := conn.Read(ctx)
		if err != nil {
			return
		}
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.created","response":{"id":"resp_a"}}`))
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.in_progress","response":{"id":"resp_a"}}`))
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.output_text.delta","delta":"hello"}`))
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"error","error":{"type":"invalid_request","code":"cyber_policy","message":"This content was flagged for possible cybersecurity risk."}}`))
	})

	var darvSawReplay atomic.Bool
	upstream.on("acct_darv", func(ctx context.Context, conn *websocket.Conn) {
		_, data, err := conn.Read(ctx)
		if err != nil {
			t.Logf("darv read err: %v", err)
			return
		}
		if strings.Contains(string(data), `"response.create"`) {
			darvSawReplay.Store(true)
		}
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.created","response":{"id":"resp_b"}}`))
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.completed","response":{"id":"resp_b","status":"completed"}}`))
	})

	upURL, _ := url.Parse(upstream.server.URL)
	shiv := &Account{Type: AccountTypeCodex, ID: "shiv", AccessToken: "shiv-token", AccountID: "acct_shiv", PlanType: "pro"}
	darv := &Account{Type: AccountTypeCodex, ID: "darv", AccessToken: "darv-token", AccountID: "acct_darv", PlanType: "pro", CyberAccess: true}
	fx := newCodexProxyFixture(t, upURL, []*Account{shiv, darv})
	fx.handler.pool.pin("conv-mid", "shiv")

	conn := dialClientWS(t, fx, http.Header{
		"Authorization": []string{"Bearer " + generateClaudePoolToken("test-secret", "mid-user")},
		"session_id":    []string{"conv-mid"},
	})
	if err := conn.Write(context.Background(), websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-5.5"}`)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	frames := mustReadUntil(t, conn, `"response.completed"`, 5*time.Second)
	if len(frames) == 0 {
		t.Fatalf("client got no frames")
	}
	if !darvSawReplay.Load() {
		t.Fatalf("cyber account never got the replayed response.create")
	}

	fx.handler.pool.mu.RLock()
	pinned := fx.handler.pool.convPin["conv-mid"]
	fx.handler.pool.mu.RUnlock()
	if pinned != "darv" {
		t.Fatalf("conversation pin = %q, want darv", pinned)
	}

	snap := fx.handler.metrics.cyberPolicySnapshot()
	if snap[cyberPolicyKey{"shiv", "suppressed_ws"}] == 0 {
		t.Errorf("expected suppressed_ws counter for shiv, got snapshot %v", snap)
	}
	if snap[cyberPolicyKey{"darv", "swap_succeeded"}] == 0 {
		t.Errorf("expected swap_succeeded counter for darv, got snapshot %v", snap)
	}
	if got := snap[cyberPolicyKey{"shiv", "synthetic_refusal_ws"}]; got != 0 {
		t.Errorf("synthetic refusal must NOT fire when swap succeeded; got %d", got)
	}
	// Inflight on both accounts must settle to zero, and the relay must
	// not have logged a tunnel error.
	waitForZeroInflight(t, fx.handler, []*Account{shiv, darv})
	if got := fx.handler.recent.snapshot(); len(got) != 0 {
		t.Fatalf("expected no recent errors after suppressed swap, got %v", got)
	}
}

// 2) The metadata recommendation by itself is just noise. We pass it
// through unchanged and we do not dial the cyber account.
func TestMetadataRecommendationIsNoOp(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	upstream := newFakeCodexUpstream(t)
	upstream.on("acct_shiv", func(ctx context.Context, conn *websocket.Conn) {
		_, _, err := conn.Read(ctx)
		if err != nil {
			return
		}
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.created","response":{"id":"resp_meta"}}`))
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.metadata","response_id":"resp_meta","metadata":{"openai_verification_recommendation":["trusted_access_for_cyber"]}}`))
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.output_text.delta","delta":"ok"}`))
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.completed","response":{"id":"resp_meta","status":"completed"}}`))
	})
	upstream.on("acct_darv", func(ctx context.Context, conn *websocket.Conn) {
		t.Errorf("cyber account dialed but no cyber_policy was sent")
		_, _, _ = conn.Read(ctx)
	})

	upURL, _ := url.Parse(upstream.server.URL)
	shiv := &Account{Type: AccountTypeCodex, ID: "shiv", AccessToken: "shiv-token", AccountID: "acct_shiv", PlanType: "pro"}
	darv := &Account{Type: AccountTypeCodex, ID: "darv", AccessToken: "darv-token", AccountID: "acct_darv", PlanType: "pro", CyberAccess: true}
	fx := newCodexProxyFixture(t, upURL, []*Account{shiv, darv})
	fx.handler.pool.pin("conv-meta", "shiv")

	conn := dialClientWS(t, fx, http.Header{
		"Authorization": []string{"Bearer " + generateClaudePoolToken("test-secret", "meta-user")},
		"session_id":    []string{"conv-meta"},
	})
	if err := conn.Write(context.Background(), websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-5.5"}`)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	frames := mustReadUntil(t, conn, `response.completed`, 4*time.Second)
	joined := strings.Join(frames, "\n")
	if !strings.Contains(joined, "trusted_access_for_cyber") {
		t.Fatalf("metadata recommendation should pass through to client; got %q", joined)
	}
	if !strings.Contains(joined, "response.output_text.delta") {
		t.Fatalf("expected delta passthrough; got %q", joined)
	}
	if hits := upstream.hitCount("acct_darv"); hits != 0 {
		t.Fatalf("cyber account dial count = %d, want 0", hits)
	}

	fx.handler.pool.mu.RLock()
	pinned := fx.handler.pool.convPin["conv-meta"]
	fx.handler.pool.mu.RUnlock()
	if pinned != "shiv" {
		t.Fatalf("pin = %q, want shiv (no swap)", pinned)
	}
}

// 3) cyber_policy that arrives on an account already marked
// CyberAccess: drop it silently, no swap, no error reported. The
// client must see a synthetic terminal turn (response.completed) so
// the codex CLI doesn't loop on reconnects.
func TestCyberPolicyOnCyberAccountSuppressedWithoutSwap(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	upstream := newFakeCodexUpstream(t)
	upstream.on("acct_darv", func(ctx context.Context, conn *websocket.Conn) {
		_, _, err := conn.Read(ctx)
		if err != nil {
			return
		}
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.created","response":{"id":"resp_d"}}`))
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"error","error":{"type":"invalid_request","code":"cyber_policy","message":"This content was flagged for possible cybersecurity risk."}}`))
	})

	upURL, _ := url.Parse(upstream.server.URL)
	darv := &Account{Type: AccountTypeCodex, ID: "darv", AccessToken: "darv-token", AccountID: "acct_darv", PlanType: "pro", CyberAccess: true}
	fx := newCodexProxyFixture(t, upURL, []*Account{darv})
	fx.handler.pool.pin("conv-cy", "darv")

	conn := dialClientWS(t, fx, http.Header{
		"Authorization": []string{"Bearer " + generateClaudePoolToken("test-secret", "cy-user")},
		"session_id":    []string{"conv-cy"},
	})
	if err := conn.Write(context.Background(), websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-5.5"}`)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	frames := readUntilCompletedOrClose(t, conn, 5*time.Second)
	if !anyFrame(frames, func(f string) bool { return strings.Contains(f, `"response.completed"`) }) {
		t.Fatalf("client did not receive synthetic response.completed; got %d frames: %v", len(frames), summaries(frames))
	}
	for _, f := range frames {
		if strings.Contains(f, "cyber_policy") || strings.Contains(f, "cybersecurity") {
			t.Fatalf("client received policy text: %s", f)
		}
	}

	// Account stayed at darv — no swap occurred. The "websocket done"
	// log line in production should report cyber_swapped=false here.
	// We assert the equivalent invariant: pool pin is unchanged.
	fx.handler.pool.mu.RLock()
	pinned := fx.handler.pool.convPin["conv-cy"]
	fx.handler.pool.mu.RUnlock()
	if pinned != "darv" {
		t.Fatalf("pool pin = %q, want darv (no swap)", pinned)
	}

	if got := fx.handler.recent.snapshot(); len(got) != 0 {
		t.Fatalf("expected no recent errors, got %v", got)
	}
	waitForZeroInflight(t, fx.handler, []*Account{darv})

	snap := fx.handler.metrics.cyberPolicySnapshot()
	if snap[cyberPolicyKey{"darv", "suppressed_ws"}] == 0 {
		t.Errorf("expected suppressed_ws on darv, snap=%v", snap)
	}
	if snap[cyberPolicyKey{"darv", "swap_no_candidate"}] == 0 {
		t.Errorf("expected swap_no_candidate counter (already on cyber, no other candidate); snap=%v", snap)
	}
	if snap[cyberPolicyKey{"darv", "synthetic_refusal_ws"}] == 0 {
		t.Errorf("expected synthetic_refusal_ws counter when no swap target; snap=%v", snap)
	}
}

// 4) cyber_policy when no cyber candidate exists in the pool: the
// frame is dropped, the client gets a synthetic refusal turn rather
// than an abrupt close, and no tunnel error is reported.
func TestCyberPolicyWithoutCyberCandidateSuppresses(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")

	upstream := newFakeCodexUpstream(t)
	upstream.on("acct_shiv", func(ctx context.Context, conn *websocket.Conn) {
		_, _, err := conn.Read(ctx)
		if err != nil {
			return
		}
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.created","response":{"id":"resp_x"}}`))
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"error","error":{"type":"invalid_request","code":"cyber_policy","message":"This content was flagged for possible cybersecurity risk."}}`))
	})

	upURL, _ := url.Parse(upstream.server.URL)
	shiv := &Account{Type: AccountTypeCodex, ID: "shiv", AccessToken: "shiv-token", AccountID: "acct_shiv", PlanType: "pro"}
	fx := newCodexProxyFixture(t, upURL, []*Account{shiv})
	fx.handler.pool.pin("conv-no-cy", "shiv")

	conn := dialClientWS(t, fx, http.Header{
		"Authorization": []string{"Bearer " + generateClaudePoolToken("test-secret", "nocy-user")},
		"session_id":    []string{"conv-no-cy"},
	})
	if err := conn.Write(context.Background(), websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-5.5"}`)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	frames := readUntilCompletedOrClose(t, conn, 5*time.Second)
	if !anyFrame(frames, func(f string) bool { return strings.Contains(f, `"response.completed"`) }) {
		t.Fatalf("client did not receive synthetic response.completed; got %d frames: %v", len(frames), summaries(frames))
	}
	for _, f := range frames {
		if strings.Contains(f, "cyber_policy") || strings.Contains(f, "cybersecurity") {
			t.Fatalf("client received policy text: %s", f)
		}
	}

	if got := fx.handler.recent.snapshot(); len(got) != 0 {
		t.Fatalf("expected no recent errors, got %v", got)
	}
	waitForZeroInflight(t, fx.handler, []*Account{shiv})
}

// TestCyberSwapResultSwappedFlagIsActiveAccountChange verifies the
// `swapped` field on codexCyberSwapResult is strictly derived from
// activeAccount != initialAccount, even when the relay terminates
// because of suppression. Regression: an earlier version hardcoded
// `swapped=true` whenever errCyberPolicySuppressed bubbled up, which
// produced misleading `cyber_swapped=true` log lines and broke the
// "skip the post-relay pin because we already pinned to a different
// account" optimisation.
func TestCyberSwapResultSwappedFlagIsActiveAccountChange(t *testing.T) {
	a := &Account{ID: "a"}
	b := &Account{ID: "b"}
	cases := []struct {
		name        string
		active      *Account
		initial     *Account
		relayErr    error
		wantSwapped bool
	}{
		{"clean close on initial", a, a, nil, false},
		{"suppressed on initial", a, a, errCyberPolicySuppressed, false},
		{"suppressed after swap", b, a, errCyberPolicySuppressed, true},
		{"clean close after swap", b, a, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &codexRelayState{
				opts:          codexCyberSwapOptions{InitialAccount: tc.initial},
				activeAccount: tc.active,
			}
			got := s.result(101, tc.relayErr)
			if got.swapped != tc.wantSwapped {
				t.Fatalf("swapped = %v, want %v", got.swapped, tc.wantSwapped)
			}
			if got.finalAccount != tc.active {
				t.Fatalf("finalAccount = %v, want %v", got.finalAccount, tc.active)
			}
		})
	}
}

func TestStripPreviousResponseIDLeavesUnrelatedFields(t *testing.T) {
	in := []byte(`{"type":"response.create","model":"gpt-5.5","previous_response_id":"resp_abc","input":[{"type":"message","role":"user"}]}`)
	out := stripPreviousResponseID(in)
	if bytes.Contains(out, []byte(`previous_response_id`)) {
		t.Fatalf("previous_response_id not stripped: %s", string(out))
	}
	if !bytes.Contains(out, []byte(`"model":"gpt-5.5"`)) {
		t.Fatalf("model field lost: %s", string(out))
	}
	if !bytes.Contains(out, []byte(`"type":"response.create"`)) {
		t.Fatalf("type field lost: %s", string(out))
	}
}

func TestStripPreviousResponseIDNoOp(t *testing.T) {
	in := []byte(`{"type":"response.create","model":"gpt-5.5","input":[]}`)
	out := stripPreviousResponseID(in)
	// Pointer-equal: no rewrite when the field is absent.
	if &in[0] != &out[0] {
		t.Fatalf("expected no-rewrite for payload without previous_response_id")
	}
}

// readUntilCompletedOrClose reads frames until response.completed is
// seen, the connection closes, or timeout elapses. Used by suppression
// tests that assert the synthetic terminal turn was written.
func readUntilCompletedOrClose(t *testing.T, conn *websocket.Conn, timeout time.Duration) []string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var frames []string
	for time.Now().Before(deadline) {
		readCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, data, err := conn.Read(readCtx)
		cancel()
		if err != nil {
			return frames
		}
		s := string(data)
		frames = append(frames, s)
		if strings.Contains(s, `"response.completed"`) {
			return frames
		}
	}
	return frames
}

func anyFrame(frames []string, pred func(string) bool) bool {
	for _, f := range frames {
		if pred(f) {
			return true
		}
	}
	return false
}

func summaries(frames []string) []string {
	out := make([]string, 0, len(frames))
	for _, f := range frames {
		if len(f) > 120 {
			f = f[:120] + "..."
		}
		out = append(out, f)
	}
	return out
}

// TestSyntheticRefusalTurnIsWellFormed unit-checks the synthesized
// frames so we know they parse and are in the order the codex CLI
// expects (created → in_progress → output_item.added → … →
// response.completed).
func TestSyntheticRefusalTurnIsWellFormed(t *testing.T) {
	pair, srv := newSyntheticTurnFixture(t)
	defer srv.Close()
	defer pair.client.CloseNow()

	state := &codexRelayState{
		opts:          codexCyberSwapOptions{ReqID: "synth-test", LogLabel: "synth-test"},
		ctx:           context.Background(),
		clientConn:    pair.server, // relay code writes into the server side
		activeAccount: &Account{ID: "synth"},
	}
	state.writeSyntheticRefusalTurn()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var seen []string
	for {
		_, data, err := pair.client.Read(ctx)
		if err != nil {
			break
		}
		seen = append(seen, string(data))
		if strings.Contains(string(data), `"response.completed"`) {
			break
		}
	}
	expectedTypes := []string{
		`"type":"response.created"`,
		`"type":"response.in_progress"`,
		`"type":"response.output_item.added"`,
		`"type":"response.content_part.added"`,
		`"type":"response.output_text.delta"`,
		`"type":"response.output_text.done"`,
		`"type":"response.content_part.done"`,
		`"type":"response.output_item.done"`,
		`"type":"response.completed"`,
	}
	joined := strings.Join(seen, "\n")
	for _, want := range expectedTypes {
		if !strings.Contains(joined, want) {
			t.Errorf("missing frame %s in: %v", want, summaries(seen))
		}
	}
	if strings.Contains(joined, "cyber_policy") || strings.Contains(joined, "cybersecurity") {
		t.Errorf("synthetic turn must not contain policy text")
	}
}

type syntheticTurnPair struct {
	client *websocket.Conn
	server *websocket.Conn
}

func newSyntheticTurnFixture(t *testing.T) (syntheticTurnPair, *httptest.Server) {
	t.Helper()
	pair := syntheticTurnPair{}
	srvCh := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			t.Logf("server accept: %v", err)
			return
		}
		srvCh <- c
		<-r.Context().Done()
	}))
	u, _ := url.Parse(srv.URL)
	u.Scheme = "ws"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, u.String(), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	pair.client = c
	pair.server = <-srvCh
	return pair, srv
}

func waitForZeroInflight(t *testing.T, h *proxyHandler, accts []*Account) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ok := atomic.LoadInt64(&h.inflight) == 0
		for _, a := range accts {
			if atomic.LoadInt64(&a.Inflight) != 0 {
				ok = false
			}
		}
		if ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, a := range accts {
		if got := atomic.LoadInt64(&a.Inflight); got != 0 {
			t.Errorf("account %s inflight = %d, want 0", a.ID, got)
		}
	}
	if got := atomic.LoadInt64(&h.inflight); got != 0 {
		t.Errorf("h.inflight = %d, want 0", got)
	}
}
