package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestAuditWebSocketTurnRace(t *testing.T) {
	s := &codexRelayState{h: &proxyHandler{cfg: &config{}}, opts: codexCyberSwapOptions{Provider: &CodexProvider{}}, activeAccount: &Account{ID: "audit", Type: AccountTypeCodex}}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_, _ = s.inspectClient([]byte(fmt.Sprintf(`{"type":"response.create","model":"gpt-5.4","input":"%d"}`, i)))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_, _ = s.inspectUpstream([]byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":"r%d","usage":{"input_tokens":1,"output_tokens":1}}}`, i)))
		}
	}()
	wg.Wait()
}

func TestAuditWebSocketHandshakeStatus(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooManyRequests) }))
	defer upstream.Close()
	base, _ := url.Parse(upstream.URL)
	_, resp, _, err := dialUpstreamWebSocket(context.Background(), base, nil, nil, 1024, false)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected rejected handshake")
	}
	if resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("upstream status discarded: resp=%v err=%v", resp, err)
	}
}

func TestAuditWebSocketTurnAttribution(t *testing.T) {
	analytics, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer analytics.Close()
	s := &codexRelayState{h: &proxyHandler{cfg: &config{}, analyticsStore: analytics}, opts: codexCyberSwapOptions{Provider: &CodexProvider{}}, activeAccount: &Account{ID: "audit", Type: AccountTypeCodex}}
	for _, frame := range []string{`{"type":"response.create","model":"gpt-5.4"}`, `{"type":"response.create","model":"gpt-5.5"}`} {
		if _, err := s.inspectClient([]byte(frame)); err != nil {
			t.Fatal(err)
		}
	}
	for _, frame := range []string{`{"type":"response.created","response":{"id":"first"}}`, `{"type":"response.created","response":{"id":"second"}}`, `{"type":"response.completed","response":{"id":"second","usage":{"input_tokens":1,"output_tokens":1}}}`, `{"type":"response.completed","response":{"id":"first","usage":{"input_tokens":1,"output_tokens":1}}}`} {
		if _, err := s.inspectUpstream([]byte(frame)); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := analytics.db.QueryRow(`SELECT COUNT(*) FROM request_costs WHERE model = 'gpt-5.4'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("first turn model overwritten: count=%d", count)
	}
}

func TestAuditWebSocketRejectionRelay(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "17")
		http.Error(w, "private upstream diagnostic", http.StatusTooManyRequests)
	}))
	defer upstream.Close()
	base, _ := url.Parse(upstream.URL)
	account := &Account{ID: "rejected", Type: AccountTypeCodex, AccountID: "acct_rejected", AccessToken: "token", PlanType: "pro"}
	fx := newCodexProxyFixture(t, base, []*Account{account})
	finished := make(chan struct{})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fx.handler.ServeHTTP(w, r); close(finished) }))
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, proxy.URL+"/responses", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + generateClaudePoolToken("test-secret", "ws-user")}}})
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("rejection response=%v err=%v", resp, err)
	}
	if resp.Header.Get("Retry-After") != "17" {
		t.Fatalf("Retry-After = %q", resp.Header.Get("Retry-After"))
	}
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	account.mu.Lock()
	penalty := account.Penalty
	account.mu.Unlock()
	if penalty != 1 {
		t.Fatalf("rejected account penalty=%v, want 1", penalty)
	}
}

func TestAuditWebSocketOverlappingTurns(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")
	analytics, err := newAnalyticsStore(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer analytics.Close()
	upstream := newFakeCodexUpstream(t)
	upstream.on("acct_overlap", func(ctx context.Context, conn *websocket.Conn) {
		for _, id := range []string{"first", "second"} {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
			if err := conn.Write(ctx, websocket.MessageText, []byte(fmt.Sprintf(`{"type":"response.created","response":{"id":%q}}`, id))); err != nil {
				return
			}
		}
		for _, id := range []string{"second", "first"} {
			if err := conn.Write(ctx, websocket.MessageText, []byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":%q,"usage":{"input_tokens":1,"output_tokens":1}}}`, id))); err != nil {
				return
			}
		}
		_, _, _ = conn.Read(ctx)
	})
	base, _ := url.Parse(upstream.server.URL)
	account := &Account{ID: "overlap", Type: AccountTypeCodex, AccountID: "acct_overlap", AccessToken: "token", PlanType: "pro"}
	fx := newCodexProxyFixture(t, base, []*Account{account})
	fx.handler.analyticsStore = analytics
	conn := dialClientWS(t, fx, http.Header{"Authorization": {"Bearer " + generateClaudePoolToken("test-secret", "ws-user")}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, model := range []string{"gpt-5.4", "gpt-5.5"} {
		if err := conn.Write(ctx, websocket.MessageText, []byte(fmt.Sprintf(`{"type":"response.create","model":%q}`, model))); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		if _, _, err := conn.Read(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, model := range []string{"gpt-5.4", "gpt-5.5"} {
		var count int
		if err := analytics.db.QueryRow("SELECT COUNT(*) FROM request_costs WHERE model = ? AND account_id = ?", model, account.ID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("%s count=%d, want 1", model, count)
		}
	}
}

func TestAuditWebSocketSwapWithPending(t *testing.T) {
	s := &codexRelayState{turns: []*codexRelayTurn{{request: []byte("first")}, {request: []byte("second")}}}
	if err := s.doSwap(&Account{ID: "next"}); err == nil {
		t.Fatal("swapped multiple outstanding turns")
	}
}

func TestAuditWebSocketPolicyTurn(t *testing.T) {
	s := &codexRelayState{activeAccount: &Account{ID: "audit", Type: AccountTypeCodex}}
	for _, conversation := range []string{"first", "second"} {
		if _, err := s.inspectClient([]byte(fmt.Sprintf(`{"type":"response.create","model":"gpt-5.4","conversation_id":%q}`, conversation))); err != nil {
			t.Fatal(err)
		}
		if _, err := s.inspectUpstream([]byte(fmt.Sprintf(`{"type":"response.created","response":{"id":%q}}`, conversation))); err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.inspectUpstream([]byte(`{"type":"error","response_id":"first","error":{"code":"cyber_policy","message":"This content was flagged for possible cybersecurity risk."}}`))
	var swap *swapPendingErr
	if !errors.As(err, &swap) {
		t.Fatalf("policy result=%v", err)
	}
	if swap.next != nil || swap.conversationID != "first" {
		t.Fatalf("wrong pending turn: %+v", swap)
	}
	if s.activeConversationID != "second" {
		t.Fatalf("latest client conversation changed to %q", s.activeConversationID)
	}
}

type auditHandshakeBody struct {
	io.Reader
	closed bool
}

func (b *auditHandshakeBody) Close() error { b.closed = true; return nil }

func TestAuditWebSocketRejectionBody(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		body := &auditHandshakeBody{Reader: strings.NewReader("private upstream diagnostic")}
		response := &http.Response{StatusCode: status, Header: make(http.Header), Body: body}
		out := httptest.NewRecorder()
		got := writeWebSocketRejection(out, response)
		if got != status || out.Code != status || !body.closed {
			t.Fatalf("status=%d response=%d body closed=%v", got, out.Code, body.closed)
		}
		if strings.Contains(out.Body.String(), "private") {
			t.Fatal("forwarded private diagnostic")
		}
	}
}
