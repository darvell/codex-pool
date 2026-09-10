package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestNativeContextWSSwap(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "context-proxy-secret")
	for _, tc := range []struct {
		name           string
		revoke, nested bool
	}{
		{"register swap", false, false},
		{"nested swap", false, true},
		{"revalidate source", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			revoke := tc.revoke
			a, b := contextTestAccount("a", "user-a"), contextTestAccount("b", "user-b")
			b.CyberAccess = true
			var mu sync.Mutex
			var seenA, seenB [][]byte
			var h *proxyHandler
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !isWebSocketUpgradeRequest(r) {
					_, _ = io.WriteString(w, `{"encrypted_output":"native-a"}`)
					return
				}
				conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.CloseNow()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				isA := r.Header.Get("Authorization") == "Bearer "+a.AccessToken
				for {
					_, frame, err := conn.Read(ctx)
					if err != nil {
						return
					}
					mu.Lock()
					if isA {
						seenA = append(seenA, frame)
					} else {
						seenB = append(seenB, frame)
					}
					count := len(seenA)
					mu.Unlock()
					if bytes.Contains(frame, []byte("native-a")) {
						alias := "b"
						if isA {
							alias = "a"
						}
						assertContextParticipant(t, h, alias)
					}
					if isA && count == 1 {
						if !bytes.Contains(frame, []byte("native-a")) || bytes.Contains(frame, []byte(contextEnvelopePrefix)) {
							t.Errorf("unexpanded upstream frame %s", frame)
						}
						if revoke {
							a.mu.Lock()
							a.Disabled = true
							a.mu.Unlock()
						}
						_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"error","error":{"code":"cyber_policy","message":"cyber_policy"}}`))
						continue
					}
					_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.completed","response":{"id":"response-context","status":"completed","output":[]}}`))
				}
			}))
			defer upstream.Close()
			h, proxy := contextProxyFixture(t, upstream.URL, a, b)
			h.cfg.websocketReadLimit = 4 << 20
			h.pool.pin(contextProxySession, a.ID)
			nativeBody := []byte(`{"context":{"session_id":"` + contextProxySession + `","current_agent_name":"/root"}}`)
			status, body := contextProxyCall(t, proxy, http.MethodPost, "/alpha/notes/v2/read_file", "context-user", nativeBody, nil)
			if status != http.StatusOK {
				t.Fatalf("notes %d %s", status, body)
			}
			var envelope map[string]string
			_ = json.Unmarshal(body, &envelope)
			headers := http.Header{"Authorization": {"Bearer " + generateClaudePoolToken("context-proxy-secret", "context-user")}, "Conversation_id": {contextProxySession}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(proxy.URL, "http")+"/backend-api/codex/responses", &websocket.DialOptions{HTTPHeader: headers})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseNow()
			if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-5.5","reasoning":{"context":"all_turns"}}`)); err != nil {
				t.Fatal(err)
			}
			_, invalid, err := conn.Read(ctx)
			if err != nil || !bytes.Contains(invalid, []byte("invalid_context")) {
				t.Fatalf("invalid frame result %s %v", invalid, err)
			}
			var obj map[string]any
			_ = json.Unmarshal(contextProxyInference(envelope["encrypted_output"]), &obj)
			obj["type"] = "response.create"
			obj["previous_response_id"] = "response-from-a"
			if tc.nested {
				delete(obj, "type")
				obj = map[string]any{"type": "response.create", "response": obj}
			}
			frame, _ := json.Marshal(obj)
			if err := conn.Write(ctx, websocket.MessageText, frame); err != nil {
				t.Fatal(err)
			}
			_, result, err := conn.Read(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if revoke {
				if !bytes.Contains(result, []byte("context_unavailable")) {
					t.Fatalf("source revocation result %s", result)
				}
				// A rejected replay removes only its own pending turn; this socket can recover.
				if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-5.5","input":[]}`)); err != nil {
					t.Fatal(err)
				}
				_, result, err = conn.Read(ctx)
				if err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Contains(result, []byte("response.completed")) {
				t.Fatalf("completion %s", result)
			}
			stored, err := h.nativeContext.store.lookup("context-user", contextProxySession)
			if err != nil || stored == nil {
				t.Fatalf("stored session=%v err=%v", stored, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if revoke {
				if len(seenA) != 2 || len(seenB) != 0 || len(stored.Participants) != 1 {
					t.Fatalf("rejected replay dispatched: a=%d b=%d participants=%v", len(seenA), len(seenB), stored.Participants)
				}
				return
			}
			if len(seenA) != 1 || len(seenB) != 1 || len(stored.Participants) != 2 {
				t.Fatalf("swap dispatches a=%d b=%d participants=%v", len(seenA), len(seenB), stored.Participants)
			}
			if !bytes.Contains(seenB[0], []byte("native-a")) || bytes.Contains(seenB[0], []byte(contextEnvelopePrefix)) || bytes.Contains(seenB[0], []byte("previous_response_id")) {
				t.Fatalf("invalid swapped wire %s", seenB[0])
			}
		})
	}
}

func TestNativeContextWSInvalid(t *testing.T) {
	for _, pending := range []int{0, 1} {
		h := preflightHandler(nil)
		s := &codexRelayState{h: h, ctx: context.Background(), activeAccount: h.pool.allAccounts()[0], opts: codexCyberSwapOptions{RequestPath: "/responses"}}
		prior := &codexRelayTurn{responseID: "prior-response"}
		if pending != 0 {
			s.turns = append(s.turns, prior)
		}
		wire, err := s.inspectClient([]byte(`{"type":"response.create","model":"gpt-5.5","reasoning":{"context":"all_turns"},"input":[]}`))
		if err != nil || wire == nil || len(wire) != 0 || len(s.turns) != pending {
			t.Fatalf("invalid context forwarded: wire=%s err=%v turns=%d", wire, err, len(s.turns))
		}
		if pending != 0 && s.turns[0] != prior {
			t.Fatal("invalid context replaced the pending turn")
		}
	}
}

func TestNativeContextWSEncoding(t *testing.T) {
	for _, frame := range []string{
		`{"type":"response.\u0063reate","reasoning":{"context":"all_turns"}}`,
		" \n" + `{"type":"response.create","reasoning":{"context":"all_turns"}}`,
	} {
		h := preflightHandler(nil)
		s := &codexRelayState{h: h, ctx: context.Background(), activeAccount: h.pool.allAccounts()[0], opts: codexCyberSwapOptions{RequestPath: "/responses"}}
		wire, err := s.inspectClient([]byte(frame))
		if err != nil || wire == nil || len(wire) != 0 || len(s.turns) != 0 {
			t.Fatalf("encoded context bypassed inspection: wire=%s err=%v", wire, err)
		}
	}
}

func TestNativeContextWSRealtime(t *testing.T) {
	h := preflightHandler(nil)
	s := &codexRelayState{h: h, ctx: context.Background(), activeAccount: h.pool.allAccounts()[0], opts: codexCyberSwapOptions{RequestPath: "/v1/realtime"}}
	frame := []byte(`{"type":"response.create","model":"gpt-5.5","reasoning":{"context":"all_turns"},"input":[]}`)
	wire, err := s.inspectClient(frame)
	if err != nil || !bytes.Equal(wire, frame) || len(s.turns) != 1 {
		t.Fatalf("native context intercepted Realtime: wire=%s err=%v", wire, err)
	}
}
