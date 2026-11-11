package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestWebSocketCompressionMatrix(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "compression-matrix")
	for _, clientCompression := range []websocket.CompressionMode{websocket.CompressionDisabled, websocket.CompressionNoContextTakeover} {
		for _, poolCompression := range []bool{false, true} {
			for _, upstreamCompression := range []websocket.CompressionMode{websocket.CompressionDisabled, websocket.CompressionNoContextTakeover} {
				name := fmt.Sprintf("client=%d/pool=%t/upstream=%d", clientCompression, poolCompression, upstreamCompression)
				t.Run(name, func(t *testing.T) {
					upstreamHeaders := make(chan http.Header, 1)
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("X-Codex-Turn-State", "compression-turn-state")
						conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: upstreamCompression})
						if err != nil {
							t.Error(err)
							return
						}
						defer conn.CloseNow()
						upstreamHeaders <- w.Header().Clone()
						for turn := 0; turn < 2; turn++ {
							_, data, err := conn.Read(r.Context())
							if err != nil {
								t.Error(err)
								return
							}
							if !json.Valid(data) || !strings.Contains(string(data), "Unicode π") {
								t.Errorf("upstream received changed request: %s", data)
								return
							}
							text, _ := json.Marshal(strings.Repeat("Unicode π response; ", 80))
							for _, frame := range []string{
								fmt.Sprintf(`{"type":"response.created","response":{"id":"resp_%d"}}`, turn),
								fmt.Sprintf(`{"type":"response.output_text.delta","delta":%s}`, text),
								fmt.Sprintf(`{"type":"response.completed","response":{"id":"resp_%d","status":"completed"}}`, turn),
							} {
								if err := conn.Write(r.Context(), websocket.MessageText, []byte(frame)); err != nil {
									t.Error(err)
									return
								}
							}
						}
						_, _, _ = conn.Read(r.Context())
					}))
					defer upstream.Close()
					base, _ := url.Parse(upstream.URL)
					fixture := newCodexProxyFixture(t, base, []*Account{{ID: "compression", Type: AccountTypeCodex, AccessToken: "test-token", AccountID: "test-account", PlanType: "pro"}})
					fixture.handler.cfg.websocketCompression = poolCompression
					fixture.handler.cfg.debug.Store(false)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					conn, resp, err := websocket.Dial(ctx, fixture.server.URL+"/responses", &websocket.DialOptions{
						CompressionMode: clientCompression,
						HTTPHeader:      http.Header{"Authorization": {"Bearer " + generateClaudePoolToken("compression-matrix", "matrix-user")}},
					})
					if err != nil {
						t.Fatal(err)
					}
					defer conn.CloseNow()
					if resp.Header.Get("X-Codex-Turn-State") != "compression-turn-state" {
						t.Fatal("negotiation lost the upstream turn-state header")
					}
					clientAccepted := strings.Contains(resp.Header.Get("Sec-WebSocket-Extensions"), "permessage-deflate")
					if clientAccepted != (poolCompression && clientCompression != websocket.CompressionDisabled) {
						t.Fatalf("unexpected downstream extension: %q", resp.Header.Get("Sec-WebSocket-Extensions"))
					}
					select {
					case headers := <-upstreamHeaders:
						upstreamAccepted := strings.Contains(headers.Get("Sec-WebSocket-Extensions"), "permessage-deflate")
						if upstreamAccepted != (poolCompression && upstreamCompression != websocket.CompressionDisabled) {
							t.Fatalf("unexpected upstream extension: %q", headers.Get("Sec-WebSocket-Extensions"))
						}
					case <-ctx.Done():
						t.Fatal("upstream did not finish negotiating")
					}
					for turn := 0; turn < 2; turn++ {
						body, _ := json.Marshal(map[string]any{"type": "response.create", "model": "gpt-5.6", "input": strings.Repeat("Unicode π request; ", 100)})
						if err := conn.Write(ctx, websocket.MessageText, body); err != nil {
							t.Fatal(err)
						}
						var text strings.Builder
						for {
							_, data, err := conn.Read(ctx)
							if err != nil {
								t.Fatal(err)
							}
							var event struct {
								Type  string `json:"type"`
								Delta string `json:"delta"`
							}
							if err := json.Unmarshal(data, &event); err != nil {
								t.Fatalf("client received undecoded bytes: %v", err)
							}
							text.WriteString(event.Delta)
							if event.Type == "response.completed" {
								break
							}
						}
						if text.String() != strings.Repeat("Unicode π response; ", 80) {
							t.Fatalf("turn %d response changed: %s", turn, text.String())
						}
					}
				})
			}
		}
	}
}

func TestWebSocketCompressedSwap(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "compressed-swap")
	replayed := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionNoContextTakeover})
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.CloseNow()
		if !strings.Contains(w.Header().Get("Sec-WebSocket-Extensions"), "permessage-deflate") {
			t.Error("upstream replacement did not negotiate compression")
			return
		}
		_, body, err := conn.Read(r.Context())
		if err != nil {
			t.Error(err)
			return
		}
		if !json.Valid(body) || !strings.Contains(string(body), "compressed replay π") {
			t.Error("upstream received a damaged replay")
			return
		}
		account := r.Header.Get("ChatGPT-Account-ID")
		replayed <- account
		if account == "ordinary" {
			_ = conn.Write(r.Context(), websocket.MessageText, []byte(`{"type":"error","error":{"type":"invalid_request","code":"cyber_policy","message":"This content was flagged for possible cybersecurity risk."}}`))
			return
		}
		text, _ := json.Marshal(strings.Repeat("compressed replay π result; ", 80))
		_ = conn.Write(r.Context(), websocket.MessageText, []byte(fmt.Sprintf(`{"type":"response.output_text.delta","delta":%s}`, text)))
		_ = conn.Write(r.Context(), websocket.MessageText, []byte(`{"type":"response.completed","response":{"id":"resp_replayed","status":"completed"}}`))
		_, _, _ = conn.Read(r.Context())
	}))
	defer upstream.Close()
	base, _ := url.Parse(upstream.URL)
	ordinary := &Account{Type: AccountTypeCodex, ID: "ordinary", AccessToken: "ordinary-token", AccountID: "ordinary", PlanType: "pro"}
	cyber := &Account{Type: AccountTypeCodex, ID: "cyber", AccessToken: "cyber-token", AccountID: "cyber", PlanType: "pro", CyberAccess: true}
	fixture := newCodexProxyFixture(t, base, []*Account{ordinary, cyber})
	fixture.handler.cfg.websocketCompression = true
	fixture.handler.cfg.debug.Store(false)
	fixture.handler.pool.pin("compressed-swap-session", ordinary.ID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, fixture.server.URL+"/responses", &websocket.DialOptions{
		CompressionMode: websocket.CompressionNoContextTakeover,
		HTTPHeader: http.Header{
			"Authorization": {"Bearer " + generateClaudePoolToken("compressed-swap", "swap-user")},
			"Session_id":    {"compressed-swap-session"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	body, _ := json.Marshal(map[string]any{"type": "response.create", "model": "gpt-5.6", "input": strings.Repeat("compressed replay π context; ", 100)})
	if err := conn.Write(ctx, websocket.MessageText, body); err != nil {
		t.Fatal(err)
	}
	frames := mustReadUntil(t, conn, `"response.completed"`, 5*time.Second)
	if !strings.Contains(strings.Join(frames, ""), "resp_replayed") || !strings.Contains(strings.Join(frames, ""), "compressed replay π result") {
		t.Fatalf("compressed replacement did not complete: %v", frames)
	}
	for _, expected := range []string{ordinary.ID, cyber.ID} {
		select {
		case account := <-replayed:
			if account != expected {
				t.Fatalf("replay account = %s, want %s", account, expected)
			}
		case <-ctx.Done():
			t.Fatal("replacement request was not received")
		}
	}
}
