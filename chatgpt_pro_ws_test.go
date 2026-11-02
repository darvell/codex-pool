package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestProWSTerminalNextTurn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	frames := make(chan map[string]any, 4)
	releaseFirst := make(chan struct{})
	var calls atomic.Int64
	handle := func(w http.ResponseWriter, r *http.Request, body []byte, model string) bool {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n")
		if calls.Add(1) == 1 {
			select {
			case <-releaseFirst:
			case <-r.Context().Done():
			}
		}
		return true
	}
	bridge := newChatGPTProWS(ctx, httptest.NewRequest(http.MethodGet, "/responses", nil), handle, func(ctx context.Context, data []byte) error {
		var frame map[string]any
		if err := json.Unmarshal(data, &frame); err != nil {
			return err
		}
		select {
		case frames <- frame:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, 4096, nil)
	defer func() { cancel(); close(releaseFirst); bridge.Close() }()
	request := []byte(`{"type":"response.create","model":"gpt-6-pro","input":"test"}`)
	if handled, err := bridge.Handle(request); !handled || err != nil {
		t.Fatal("first request rejected", err)
	}
	select {
	case first := <-frames:
		if first["type"] != "response.completed" {
			t.Fatal("first turn did not complete")
		}
	case <-ctx.Done():
		t.Fatal("first turn timed out")
	}
	if handled, err := bridge.Handle(request); !handled || err != nil {
		t.Fatal("next request rejected", err)
	}
	select {
	case second := <-frames:
		if second["type"] != "response.completed" {
			t.Fatalf("completed turn still held busy gate: %v", second)
		}
	case <-ctx.Done():
		t.Fatal("next turn timed out")
	}
}

func TestProWSRetriesOverloadBeforeEmittingError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var calls atomic.Int64
	frames := make(chan map[string]any, 2)
	handle := func(w http.ResponseWriter, r *http.Request, body []byte, model string) bool {
		if calls.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":{"code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later."}}`)
			return true
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n")
		return true
	}
	bridge := newChatGPTProWS(ctx, httptest.NewRequest(http.MethodGet, "/responses", nil), handle, func(ctx context.Context, data []byte) error {
		var frame map[string]any
		if err := json.Unmarshal(data, &frame); err != nil {
			return err
		}
		select {
		case frames <- frame:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, 4096, nil)
	defer bridge.Close()

	if handled, err := bridge.Handle([]byte(`{"type":"response.create","model":"gpt-6-pro","input":"test"}`)); !handled || err != nil {
		t.Fatalf("request rejected: handled=%v err=%v", handled, err)
	}
	select {
	case frame := <-frames:
		if frame["type"] != "response.completed" {
			t.Fatalf("unexpected frame: %v", frame)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for retried Pro response")
	}
	if calls.Load() != 2 {
		t.Fatalf("Pro upstream calls=%d, want 2", calls.Load())
	}
}

func TestProWSProxyRouting(t *testing.T) {
	for _, ordinary := range []bool{false, true} {
		t.Run(fmt.Sprintf("ordinary=%v", ordinary), func(t *testing.T) {
			var nativeFrames atomic.Int64
			f := proTestHandler(t, func(w http.ResponseWriter, r *http.Request) {
				if isWebSocketUpgradeRequest(r) {
					conn, err := websocket.Accept(w, r, nil)
					if err != nil {
						return
					}
					defer conn.CloseNow()
					for {
						_, data, err := conn.Read(r.Context())
						if err != nil {
							return
						}
						nativeFrames.Add(1)
						if proModel(extractCodexWebSocketRequestedModel(data)) != "" {
							t.Error("Pro frame forwarded to native Codex")
						}
						if err := conn.Write(r.Context(), websocket.MessageText, []byte(`{"type":"response.completed","response":{"id":"resp_native","status":"completed","output":[]}}`)); err != nil {
							return
						}
					}
				}
				if r.URL.Path != "/backend-api/accounts/check/v4-2023-04-27" {
					t.Errorf("wrong Pro endpoint: %s", r.URL.Path)
				}
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"detail":"Unusual activity has been detected from your device. Try again later."}`)
			})
			if ordinary {
				f.account.PlanType = "pro"
			} else {
				f.reserve(t)
			}
			upstream := httptest.NewServer(f.upstream.Config.Handler)
			defer upstream.Close()
			base, err := url.Parse(upstream.URL + "/backend-api")
			if err != nil {
				t.Fatal(err)
			}
			f.h.registry = &ProviderRegistry{byType: map[AccountType]Provider{AccountTypeCodex: NewCodexProvider(base, base, base)}}
			f.h.recent = newRecentErrors(5)
			f.h.cfg.maxAttempts = 1
			f.h.cfg.websocketReadLimit = 1 << 20
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.h.proxyRequest(w, r, "pro-ws-routing") }))
			defer proxy.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(proxy.URL, "http")+"/backend-api/codex/responses", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + f.ownerToken}}})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseNow()
			for _, request := range []string{`{"type":"response.create","model":"gpt-6-pro","input":"test"}`, `{"type":"response.create","response":{"model":"gpt-6-pro","input":"test"}}`} {
				if err := conn.Write(ctx, websocket.MessageText, []byte(request)); err != nil {
					t.Fatal(err)
				}
				_, data, err := conn.Read(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Contains(data, []byte(`"status":403`)) || !bytes.Contains(data, []byte("ChatGPT restricted this session")) {
					t.Fatalf("restriction not propagated: %s", data)
				}
			}
			if nativeFrames.Load() != 0 {
				t.Fatal("Pro request leaked to native upstream")
			}
			if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-5.4","input":"ordinary"}`)); err != nil {
				t.Fatal(err)
			}
			_, data, err := conn.Read(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if ordinary {
				if !bytes.Contains(data, []byte("response.completed")) || nativeFrames.Load() != 1 {
					t.Fatalf("ordinary recovery failed: %s", data)
				}
			} else if !bytes.Contains(data, []byte(`"status":503`)) {
				t.Fatalf("missing ordinary account hidden: %s", data)
			}
			conn.CloseNow()
		})
	}
}

func TestProWSRequest(t *testing.T) {
	for _, frame := range []string{
		`{"type":"response.create","model":"gpt-6-pro","previous_response_id":"resp_prior","input":[{"type":"custom_tool_call_output","call_id":"call_1","output":"result"}],"tools":[{"type":"custom","name":"run"}]}`,
		`{"type":"response.create","response":{"model":"gpt-6-pro","previous_response_id":"resp_prior","input":[{"type":"custom_tool_call_output","call_id":"call_1","output":"result"}],"tools":[{"type":"custom","name":"run"}]}}`,
	} {
		body, model, err := proWSRequest([]byte(frame), 4096)
		if err != nil || model != "gpt-6-pro" {
			t.Fatalf("request: %s %v", body, err)
		}
		var request map[string]any
		_ = json.Unmarshal(body, &request)
		if request["previous_response_id"] != "resp_prior" || request["stream"] != true || request["type"] != nil {
			t.Fatalf("lost continuation: %s", body)
		}
		if !bytes.Contains(body, []byte(`"custom_tool_call_output"`)) || !bytes.Contains(body, []byte(`"tools"`)) {
			t.Fatalf("lost tools: %s", body)
		}
	}
	if _, _, err := proWSRequest([]byte(`{"type":"response.create"}`), 4); err == nil {
		t.Fatal("accepted oversized request")
	}
}

func TestProWSEvents(t *testing.T) {
	events := []string{
		`{"type":"response.created","response":{"id":"resp_test"}}`,
		`{"type":"response.output_item.added","item":{"type":"function_call","name":"read","call_id":"call_f","arguments":""}}`,
		`{"type":"response.function_call_arguments.delta","delta":"{\"path\":\"a\"}"}`,
		`{"type":"response.output_item.added","item":{"type":"custom_tool_call","name":"run","call_id":"call_c","input":""}}`,
		`{"type":"response.custom_tool_call_input.delta","delta":"ls"}`,
		`{"type":"response.completed","response":{"id":"resp_test","status":"completed","output":[]}}`,
	}
	var got []string
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &proWSResponse{header: make(http.Header), ctx: ctx, cancel: cancel, limit: 4096, write: func(_ context.Context, data []byte) error { got = append(got, string(data)); return nil }}
	w.Header().Set("Content-Type", "text/event-stream")
	stream := ": comment\r\n\r\n"
	for _, event := range events {
		stream += "event: ignored\r\ndata: " + event + "\r\n\r\n"
	}
	stream += "data: [DONE]\r\n\r\n"
	for _, c := range []byte(stream) {
		if _, err := w.Write([]byte{c}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.finish(); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(events) {
		t.Fatalf("events: %v", got)
	}
	for i := range events {
		if got[i] != events[i] {
			t.Fatalf("changed event %d: %s", i, got[i])
		}
	}
}

func TestProWSFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stream string
		limit  int64
	}{
		{"oversized", "data: " + strings.Repeat("x", 100), 32},
		{"invalid", "data: not-json\n\n", 1024},
		{"truncated", "data: {\"type\":\"response.created\"}", 1024},
		{"no terminal", "data: {\"type\":\"response.created\"}\n\n", 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w := &proWSResponse{header: http.Header{"Content-Type": []string{"text/event-stream"}}, ctx: ctx, cancel: cancel, limit: tc.limit, write: func(context.Context, []byte) error { return nil }}
			_, err := w.Write([]byte(tc.stream))
			if err == nil {
				err = w.finish()
			}
			if err == nil {
				t.Fatal("accepted broken stream")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	expected := errors.New("socket closed")
	w := &proWSResponse{header: http.Header{"Content-Type": []string{"text/event-stream"}}, ctx: ctx, cancel: cancel, limit: 1024, write: func(context.Context, []byte) error { return expected }}
	if _, err := w.Write([]byte("data: {\"type\":\"response.created\"}\n\n")); !errors.Is(err, expected) || ctx.Err() == nil {
		t.Fatalf("write did not cancel HTTP: %v", err)
	}
}

func proWSTestSocket(t *testing.T, handle proWSHandler) (*websocket.Conn, context.Context) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		limit := effectiveWebSocketReadLimit(AccountTypeCodex, 0)
		conn.SetReadLimit(limit)
		writer := &webSocketWriter{conn: conn}
		bridge := newChatGPTProWS(r.Context(), r, handle, func(ctx context.Context, data []byte) error { return writer.Write(ctx, websocket.MessageText, data) }, limit, nil)
		defer bridge.Close()
		_, stop := startWebSocketHeartbeat(r.Context(), writer, time.Second, "client")
		defer stop()
		for {
			_, data, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			if _, err := bridge.Handle(data); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/responses", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	return conn, ctx
}

func TestProWSSocketErrorRecovery(t *testing.T) {
	conn, ctx := proWSTestSocket(t, func(w http.ResponseWriter, r *http.Request, body []byte, model string) bool {
		if r.Method != http.MethodPost || model != "gpt-6-pro" || !bytes.Contains(body, []byte(`"stream":true`)) {
			t.Error("not an HTTP Responses request")
		}
		respondJSONError(w, http.StatusForbidden, errProActivityRestricted.Error())
		return true
	})
	for i := 0; i < 2; i++ {
		if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-6-pro","input":"hello"}`)); err != nil {
			t.Fatal(err)
		}
		_, frame, err := conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var event map[string]any
		if json.Unmarshal(frame, &event) != nil || event["type"] != "error" || event["status"] != float64(http.StatusForbidden) {
			t.Fatalf("error: %s", frame)
		}
		detail, _ := event["error"].(map[string]any)
		if detail["message"] != errProActivityRestricted.Error() {
			t.Fatalf("restriction hidden: %s", frame)
		}
	}
}

func TestProWSSocketCloseCancels(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	conn, ctx := proWSTestSocket(t, func(w http.ResponseWriter, r *http.Request, body []byte, model string) bool {
		close(started)
		<-r.Context().Done()
		close(stopped)
		return true
	})
	if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-6-pro","input":"hello"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("handler never started")
	}
	conn.CloseNow()
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("HTTP handler survived socket close")
	}
}

func TestProWSOrdinaryUntouched(t *testing.T) {
	b := newChatGPTProWS(context.Background(), httptest.NewRequest(http.MethodGet, "/responses", nil), func(http.ResponseWriter, *http.Request, []byte, string) bool {
		t.Error("ordinary frame reached Pro")
		return true
	}, func(context.Context, []byte) error { t.Error("ordinary frame wrote Pro event"); return nil }, 0, nil)
	defer b.Close()
	for _, frame := range []string{`{"type":"response.create","model":"gpt-6.1-sol"}`, `{"type":"other","model":"gpt-6-pro"}`} {
		if handled, err := b.Handle([]byte(frame)); handled || err != nil {
			t.Fatalf("ordinary frame consumed: %v %v", handled, err)
		}
	}
}

func TestProWSSocketAuthorization(t *testing.T) {
	f := proTestHandler(t, func(http.ResponseWriter, *http.Request) {
		t.Error("unauthorized WebSocket reached provider")
	})
	conn, ctx := proWSTestSocket(t, f.h.handleChatGPTPro)
	if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.create","model":"gpt-6-pro","input":"hello"}`)); err != nil {
		t.Fatal(err)
	}
	_, frame, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(frame, []byte(`"status":401`)) || f.calls.Load() != 0 {
		t.Fatalf("authorization failed: %s provider calls=%d", frame, f.calls.Load())
	}
}

func TestProWSSocketToolContinuation(t *testing.T) {
	conn, ctx := proWSTestSocket(t, func(w http.ResponseWriter, r *http.Request, body []byte, model string) bool {
		if !bytes.Contains(body, []byte(`"previous_response_id":"resp_prior"`)) || !bytes.Contains(body, []byte(`"call_id":"call_c"`)) {
			t.Errorf("continuation changed: %s", body)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.custom_tool_call_input.delta\",\"delta\":\"ls\",\"item_id\":\"call_c\"}\n\n")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_next\",\"status\":\"completed\",\"output\":[{\"type\":\"custom_tool_call\",\"call_id\":\"call_c\",\"name\":\"run\",\"input\":\"ls\"}]}}\n\n")
		return true
	})
	if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.create","response":{"model":"gpt-6-pro","previous_response_id":"resp_prior","input":[{"type":"custom_tool_call_output","call_id":"call_c","output":"done"}]}}`)); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"response.custom_tool_call_input.delta", "response.completed"} {
		_, frame, err := conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(frame, []byte(expected)) || bytes.Contains(frame, []byte("data:")) {
			t.Fatalf("not a Responses JSON event: %s", frame)
		}
	}
}

func TestProWSHTTPErrorObject(t *testing.T) {
	var got []byte
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &proWSResponse{header: make(http.Header), ctx: ctx, cancel: cancel, limit: 1024, write: func(_ context.Context, p []byte) error { got = append([]byte(nil), p...); return nil }}
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, `{"error":{"type":"authentication_error","code":"invalid_api_key","message":"Invalid credential"}}`)
	if err := w.finish(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`"status":401`)) || !bytes.Contains(got, []byte(`"code":"invalid_api_key"`)) {
		t.Fatalf("authorization changed: %s", got)
	}
}
