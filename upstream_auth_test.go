package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func rejectExpiredToken(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	w.Header().Set("X-OpenAI-Authorization-Error", "401")
	w.Header().Set("X-OpenAI-Ide-Error-Code", "token_expired")
	w.Header().Set("X-Error-JSON", "upstream-auth-diagnostic")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, `{"error":{"code":"token_expired","message":"upstream token expired"}}`)
}

func assertPoolAuthFailure(t *testing.T, resp *http.Response) {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable || !bytes.Contains(body, []byte(upstreamAuthErrorCode)) {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	for _, name := range []string{"WWW-Authenticate", "X-OpenAI-Authorization-Error", "X-OpenAI-Ide-Error-Code", "X-Error-JSON"} {
		if resp.Header.Get(name) != "" {
			t.Errorf("upstream auth header leaked: %s", name)
		}
	}
	if bytes.Contains(body, []byte("token_expired")) {
		t.Fatal("upstream expiration leaked into client auth response")
	}
}

func TestStreamedPoolAuthRecovery(t *testing.T) {
	for _, mode := range []string{"chunked", "oversized"} {
		for _, recovery := range []string{"unavailable", "refreshed", "still-rejected", "refresh-failed"} {
			t.Run(mode+"/"+recovery, func(t *testing.T) {
				t.Setenv("POOL_JWT_SECRET", "test-secret")
				var attempts, refreshes atomic.Int32
				var firstBody []byte
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/oauth/token" {
						refreshes.Add(1)
						if recovery == "refresh-failed" {
							http.Error(w, "refresh unavailable", http.StatusServiceUnavailable)
							return
						}
						_, _ = io.WriteString(w, `{"access_token":"fresh-access","refresh_token":"fresh-refresh"}`)
						return
					}
					body, _ := io.ReadAll(r.Body)
					if attempts.Add(1) == 1 {
						firstBody = append([]byte(nil), body...)
					} else if !bytes.Equal(firstBody, body) {
						t.Error("replayed request body changed or was truncated")
					}
					if r.Header.Get("Authorization") != "Bearer fresh-access" || recovery == "still-rejected" {
						rejectExpiredToken(w)
						return
					}
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\"}\n\n")
				}))
				defer upstream.Close()
				base, _ := url.Parse(upstream.URL)
				account := &Account{ID: "expired", Type: AccountTypeCodex, AccessToken: "old-access", RefreshToken: "refresh", AccountID: "upstream", PlanType: "pro", File: filepath.Join(t.TempDir(), "account.json")}
				if err := os.WriteFile(account.File, []byte(`{"tokens":{"access_token":"old-access"}}`), 0o600); err != nil {
					t.Fatal(err)
				}
				fx := newCodexProxyFixture(t, base, []*Account{account})
				fx.handler.cfg.disableRefresh = recovery == "unavailable"
				fx.handler.cfg.maxSpoolBodyBytes = 1 << 20
				fx.handler.cfg.maxAttempts = 1
				fx.handler.refreshTransport = http.DefaultTransport
				fx.handler.aliases = newModelAliases(nil)
				payload := `{"model":"gpt-6-astra","stream":true,"input":[{"role":"user","content":"` + strings.Repeat("x", 4096) + `"}]}`
				req, _ := http.NewRequest(http.MethodPost, fx.server.URL+"/v1/responses", strings.NewReader(payload))
				req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("test-secret", "test-user"))
				req.Header.Set("Content-Type", "application/json")
				if mode == "chunked" {
					req.ContentLength = -1
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				if recovery != "refreshed" {
					assertPoolAuthFailure(t, resp)
					wantAttempts, wantRefreshes := int32(1), int32(1)
					if recovery == "unavailable" {
						wantRefreshes = 0
					}
					if recovery == "still-rejected" {
						wantAttempts = 2
					}
					if attempts.Load() != wantAttempts || refreshes.Load() != wantRefreshes {
						t.Fatalf("attempts=%d refreshes=%d", attempts.Load(), refreshes.Load())
					}
					return
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("response.completed")) || attempts.Load() != 2 || refreshes.Load() != 1 {
					t.Fatalf("status=%d body=%s attempts=%d refreshes=%d", resp.StatusCode, body, attempts.Load(), refreshes.Load())
				}
			})
		}
	}
}

func TestWebSocketPoolAuthFailure(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { rejectExpiredToken(w) }))
	defer upstream.Close()
	base, _ := url.Parse(upstream.URL)
	fx := newCodexProxyFixture(t, base, []*Account{{ID: "expired", Type: AccountTypeCodex, AccessToken: "old-access", AccountID: "upstream", PlanType: "pro"}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, fx.server.URL+"/v1/responses", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + generateClaudePoolToken("test-secret", "test-user")}}})
	if err == nil || resp == nil {
		t.Fatalf("expected rejected handshake, response=%v err=%v", resp, err)
	}
	assertPoolAuthFailure(t, resp)
}

func TestWebSocketPoolAuthRecovery(t *testing.T) {
	for _, recovery := range []string{"refresh", "failover"} {
		t.Run(recovery, func(t *testing.T) {
			t.Setenv("POOL_JWT_SECRET", "test-secret")
			var attempts, refreshes atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth/token" {
					refreshes.Add(1)
					_, _ = io.WriteString(w, `{"access_token":"fresh-access"}`)
					return
				}
				attempts.Add(1)
				if r.Header.Get("Authorization") != "Bearer fresh-access" {
					rejectExpiredToken(w)
					return
				}
				conn, err := websocket.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer conn.CloseNow()
				_, _, err = conn.Read(r.Context())
				if err == nil {
					_ = conn.Write(r.Context(), websocket.MessageText, []byte(`{"type":"response.completed"}`))
				}
			}))
			defer upstream.Close()
			base, _ := url.Parse(upstream.URL)
			expired := &Account{ID: "expired", Type: AccountTypeCodex, AccessToken: "old-access", AccountID: "upstream", PlanType: "pro", File: filepath.Join(t.TempDir(), "account.json")}
			if err := os.WriteFile(expired.File, []byte(`{"tokens":{"access_token":"old-access"}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			accounts := []*Account{expired}
			if recovery == "refresh" {
				expired.RefreshToken = "refresh"
			} else {
				accounts = append(accounts, &Account{ID: "healthy", Type: AccountTypeCodex, AccessToken: "fresh-access", AccountID: "other-upstream", PlanType: "pro"})
			}
			fx := newCodexProxyFixture(t, base, accounts)
			fx.handler.cfg.disableRefresh = false
			fx.handler.cfg.maxAttempts = 2
			fx.handler.refreshTransport = http.DefaultTransport
			fx.handler.pool.pin("auth-test", expired.ID)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, resp, err := websocket.Dial(ctx, fx.server.URL+"/v1/responses?session_id=auth-test", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + generateClaudePoolToken("test-secret", "test-user")}}})
			if err != nil {
				t.Fatalf("status=%v err=%v", resp, err)
			}
			defer conn.CloseNow()
			if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-5.5","input":"health"}`)); err != nil {
				t.Fatal(err)
			}
			_, data, err := conn.Read(ctx)
			if err != nil || !bytes.Contains(data, []byte("response.completed")) {
				t.Fatalf("data=%s err=%v", data, err)
			}
			wantRefreshes := int32(0)
			if recovery == "refresh" {
				wantRefreshes = 1
			}
			if attempts.Load() != 2 || refreshes.Load() != wantRefreshes {
				t.Fatalf("attempts=%d refreshes=%d", attempts.Load(), refreshes.Load())
			}
		})
	}
}

func TestClientAuthStillRejected(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "test-secret")
	base, _ := url.Parse("http://127.0.0.1:1")
	fx := newCodexProxyFixture(t, base, nil)
	resp, err := http.Get(fx.server.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing client credential status=%d", resp.StatusCode)
	}
}

func TestPassthroughAuthUnchanged(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { rejectExpiredToken(w) }))
	defer upstream.Close()
	base, _ := url.Parse(upstream.URL)
	w := httptest.NewRecorder()
	result := relayWebSocket(w, httptest.NewRequest(http.MethodGet, "/responses", nil), base, nil, webSocketRelayOptions{ReadLimit: 1024})
	if result.statusCode != http.StatusUnauthorized || w.Code != http.StatusUnauthorized {
		t.Fatalf("caller-owned upstream credential status=%d", w.Code)
	}
}
