package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
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

func compressionHTTP(t *testing.T, handler http.Handler, http2 bool) (*httptest.Server, *http.Transport) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = http2
	server.StartTLS()
	t.Cleanup(server.Close)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	return server, transport
}

func compressionJSON() []byte {
	var text strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&text, "sample-%04d request compression and streaming; ", i)
	}
	return []byte(`{"model":"test","input":"` + text.String() + `"}`)
}

func TestUpstreamRequestCompression(t *testing.T) {
	for _, endpoint := range []struct {
		url      string
		encoding string
	}{
		{"https://api.anthropic.com/v1/messages?beta=true", "gzip"},
		{"https://api.anthropic.com/v1/messages/count_tokens", "gzip"},
		{"https://api.openai.com/v1/responses", "zstd"},
		{"https://chatgpt.com/backend-api/codex/responses", ""},
		{"https://opencode.ai/zen/go/v1/messages", ""},
		{"https://api.openai.com/v1/chat/completions", ""},
		{"https://example.com/v1/messages", ""},
	} {
		t.Run(endpoint.url, func(t *testing.T) {
			plain := compressionJSON()
			_, base := compressionHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Accept-Encoding") != "gzip" {
					t.Errorf("accept encoding = %q", r.Header.Get("Accept-Encoding"))
				}
				if got := r.Header.Get("Content-Encoding"); got != endpoint.encoding {
					t.Errorf("request encoding = %q, want %q", got, endpoint.encoding)
				}
				wire, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if r.ContentLength != int64(len(wire)) {
					t.Errorf("content length = %d, wire bytes = %d", r.ContentLength, len(wire))
				}
				decoded, _, err := decodeRequestBody(endpoint.encoding, wire, 1<<20)
				if err != nil || !bytes.Equal(decoded, plain) {
					t.Errorf("decoded body mismatch: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"ok":true}`)
			}), false)
			req, _ := http.NewRequest(http.MethodPost, endpoint.url, bytes.NewReader(plain))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept-Encoding", "br, zstd")
			req.Header.Set("Content-Length", fmt.Sprint(len(plain)))
			resp, err := newUpstreamTransport(base, 1<<20).RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if req.Header.Get("Content-Encoding") != "" || req.Header.Get("Accept-Encoding") != "br, zstd" {
				t.Fatal("transport mutated the original headers")
			}
		})
	}
}

func TestUpstreamCompressionGuards(t *testing.T) {
	for _, mode := range []string{"disabled", "small", "oversized", "chunked", "nonreplayable", "encoded", "nonjson", "openai-ratio"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("PROXY_UPSTREAM_COMPRESSION", "1")
			body := compressionJSON()
			endpoint := "https://api.anthropic.com/v1/messages"
			if mode == "small" {
				body = []byte(`{"input":"hi"}`)
			}
			if mode == "openai-ratio" {
				endpoint = "https://api.openai.com/v1/responses"
				body = []byte(`{"input":"` + strings.Repeat("a", 100000) + `"}`)
			}
			req, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept-Encoding", "br")
			limit := int64(1 << 20)
			switch mode {
			case "disabled":
				t.Setenv("PROXY_UPSTREAM_COMPRESSION", "0")
			case "oversized":
				limit = 1024
			case "chunked":
				req.ContentLength = -1
			case "nonreplayable":
				req.GetBody = nil
			case "encoded":
				req.Header.Set("Content-Encoding", "gzip")
			case "nonjson":
				req.Header.Set("Content-Type", "application/octet-stream")
			}
			base := roundTripFunc(func(out *http.Request) (*http.Response, error) {
				if out.Header.Get("Content-Encoding") != req.Header.Get("Content-Encoding") {
					t.Errorf("unexpected request compression")
				}
				wantAccept := ""
				if mode == "disabled" {
					wantAccept = "identity"
				}
				if got := out.Header.Get("Accept-Encoding"); got != wantAccept {
					t.Errorf("accept encoding = %q, want %q", got, wantAccept)
				}
				got, err := io.ReadAll(out.Body)
				out.Body.Close()
				if err != nil || !bytes.Equal(got, body) {
					t.Errorf("guard changed request body: %v", err)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
			})
			resp, err := newUpstreamTransport(base, limit).RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		})
	}
}

func TestUpstreamCompressionRefusal(t *testing.T) {
	for _, status := range []int{http.StatusUnsupportedMediaType, http.StatusBadRequest, http.StatusTooManyRequests, http.StatusServiceUnavailable, 0} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			body := compressionJSON()
			var calls atomic.Int32
			base := roundTripFunc(func(out *http.Request) (*http.Response, error) {
				attempt := calls.Add(1)
				wire, err := io.ReadAll(out.Body)
				out.Body.Close()
				if err != nil {
					t.Error(err)
				}
				encoding := "gzip"
				if attempt == 2 {
					encoding = ""
				}
				if out.Header.Get("Content-Encoding") != encoding {
					t.Errorf("attempt %d encoding = %q", attempt, out.Header.Get("Content-Encoding"))
				}
				decoded, _, err := decodeRequestBody(encoding, wire, 1<<20)
				if err != nil || !bytes.Equal(decoded, body) {
					t.Errorf("attempt %d changed body: %v", attempt, err)
				}
				if status == 0 {
					return nil, errors.New("network failure")
				}
				if attempt == 2 {
					return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
				}
				return &http.Response{StatusCode: status, Body: http.NoBody}, nil
			})
			req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := newUpstreamTransport(base, 1<<20).RoundTrip(req)
			if status == 0 {
				if err == nil {
					t.Fatal("network error disappeared")
				}
			} else if err != nil {
				t.Fatal(err)
			} else {
				resp.Body.Close()
			}
			wantCalls := int32(1)
			if status == http.StatusUnsupportedMediaType {
				wantCalls = 2
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("fallback status = %d", resp.StatusCode)
				}
			}
			if calls.Load() != wantCalls {
				t.Fatalf("calls = %d, want %d", calls.Load(), wantCalls)
			}
		})
	}
}

type gzipFragments struct{ w http.ResponseWriter }

func (f gzipFragments) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(3, len(p))
		count, err := f.w.Write(p[:n])
		written += count
		if err != nil {
			return written, err
		}
		f.w.(http.Flusher).Flush()
		p = p[n:]
	}
	return written, nil
}

func TestUpstreamGzipStreaming(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "compression-secret")
	for _, mode := range []struct {
		name, path, model, host, first, last string
	}{
		{"codex", "/v1/responses", "gpt-5.6", "chatgpt.com", "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_gzip\",\"status\":\"in_progress\"}}\n\nevent: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"FIRST_TOKEN\",\"output_index\":0,\"content_index\":0}\n\n", "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_gzip\",\"status\":\"completed\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n"},
		{"claude", "/v1/messages", "claude-opus-5-5", "api.anthropic.com", "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_gzip\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-opus-5-5\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"FIRST_TOKEN\"}}\n\n", "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"},
	} {
		for _, http2 := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/http2=%t", mode.name, http2), func(t *testing.T) {
				finish := make(chan struct{})
				var finishOnce sync.Once
				release := func() { finishOnce.Do(func() { close(finish) }) }
				defer release()
				var expectedProto = 1
				if http2 {
					expectedProto = 2
				}
				_, baseTransport := compressionHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.ProtoMajor != expectedProto {
						t.Errorf("HTTP major = %d, want %d", r.ProtoMajor, expectedProto)
					}
					if got := r.Header.Get("Accept-Encoding"); got != "gzip" {
						t.Errorf("upstream accept encoding = %q", got)
					}
					if _, err := io.Copy(io.Discard, r.Body); err != nil {
						t.Error(err)
					}
					w.Header().Set("Content-Type", "text/event-stream")
					w.Header().Set("Content-Encoding", "gzip")
					zw := gzip.NewWriter(gzipFragments{w})
					io.WriteString(zw, mode.first)
					zw.Flush()
					w.(http.Flusher).Flush()
					select {
					case <-finish:
					case <-r.Context().Done():
						return
					}
					io.WriteString(zw, mode.last)
					zw.Close()
				}), http2)
				baseURL, _ := url.Parse("https://" + mode.host)
				h := &proxyHandler{
					cfg:       &config{maxAttempts: 1, maxInMemoryBodyBytes: 1 << 20, disableRefresh: true},
					transport: newUpstreamTransport(baseTransport, 1<<20),
					pool:      newPoolState([]*Account{{ID: "codex", Type: AccountTypeCodex, AccessToken: "codex-token", PlanType: "pro"}, {ID: "claude", Type: AccountTypeClaude, AccessToken: "sk-ant-oat-test", PlanType: "max"}}, false),
					registry:  NewProviderRegistry(NewCodexProvider(baseURL, baseURL, baseURL), NewClaudeProvider(baseURL), NewGeminiProvider(baseURL, baseURL)),
					metrics:   newMetrics(), recent: newRecentErrors(5),
				}
				proxy := httptest.NewServer(h)
				defer proxy.Close()
				body := fmt.Sprintf(`{"model":%q,"stream":true,"max_tokens":100,"input":"hello","messages":[{"role":"user","content":"hello"}]}`, mode.model)
				req, _ := http.NewRequest(http.MethodPost, proxy.URL+mode.path, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept-Encoding", "br, gzip")
				req.Header.Set("Authorization", "Bearer "+generateClaudePoolToken("compression-secret", "compression-user"))
				client := &http.Client{Timeout: 5 * time.Second}
				resp, err := client.Do(req)
				if err != nil {
					release()
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "" {
					release()
					data, _ := io.ReadAll(resp.Body)
					t.Fatalf("status=%d encoding=%q body=%s", resp.StatusCode, resp.Header.Get("Content-Encoding"), data)
				}
				scanner := bufio.NewScanner(resp.Body)
				var output strings.Builder
				for scanner.Scan() {
					output.WriteString(scanner.Text())
					if strings.Contains(scanner.Text(), "FIRST_TOKEN") {
						break
					}
				}
				if !strings.Contains(output.String(), "FIRST_TOKEN") {
					release()
					t.Fatalf("no incremental first token before upstream finished: %v, output=%s", scanner.Err(), output.String())
				}
				release()
				for scanner.Scan() {
					output.WriteString(scanner.Text())
				}
				if err := scanner.Err(); err != nil {
					t.Fatal(err)
				}
				terminal := "response.completed"
				if mode.name == "claude" {
					terminal = "message_stop"
				}
				if !strings.Contains(output.String(), terminal) {
					t.Fatalf("missing completion: %s", output.String())
				}
			})
		}
	}
}

func TestUpstreamGzipHeaders(t *testing.T) {
	for _, setting := range []string{"0", "1"} {
		t.Run(setting, func(t *testing.T) {
			t.Setenv("PROXY_UPSTREAM_COMPRESSION", setting)
			payload := []byte(`{"message":"decoded JSON"}`)
			_, base := compressionHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if setting == "0" {
					if r.Header.Get("Accept-Encoding") != "identity" {
						t.Error("compression-off did not request identity")
					}
					w.Write(payload)
					return
				}
				var compressed bytes.Buffer
				zw := gzip.NewWriter(&compressed)
				zw.Write(payload)
				zw.Close()
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Length", fmt.Sprint(compressed.Len()))
				w.Write(compressed.Bytes())
			}), false)
			req, _ := http.NewRequest(http.MethodGet, "https://example.com/json", nil)
			resp, err := newUpstreamTransport(base, 1<<20).RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || !bytes.Equal(body, payload) {
				t.Fatalf("decoded body=%q err=%v", body, err)
			}
			if resp.Header.Get("Content-Encoding") != "" {
				t.Fatal("encoded header remained after decoding")
			}
			if setting == "1" && (!resp.Uncompressed || resp.ContentLength != -1 || resp.Header.Get("Content-Length") != "") {
				t.Fatal("compressed content length remained after decoding")
			}
		})
	}
}

func TestUpstreamGzipCancel(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprint(http2), func(t *testing.T) {
			closed := make(chan struct{})
			_, base := compressionHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(closed)
				w.Header().Set("Content-Encoding", "gzip")
				zw := gzip.NewWriter(w)
				io.WriteString(zw, "first bytes")
				zw.Flush()
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}), http2)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/stream", nil)
			resp, err := newUpstreamTransport(base, 1<<20).RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var first [5]byte
			if _, err := io.ReadFull(resp.Body, first[:]); err != nil {
				t.Fatal(err)
			}
			cancel()
			if _, err := io.ReadAll(resp.Body); !errors.Is(err, context.Canceled) {
				t.Fatalf("read after cancellation: %v", err)
			}
			select {
			case <-closed:
			case <-time.After(3 * time.Second):
				t.Fatal("cancelled gzip stream retained its upstream connection")
			}
		})
	}
}

func TestUpstreamCompressionWebSocket(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		kind, body, err := conn.Read(r.Context())
		if err == nil {
			conn.Write(r.Context(), kind, body)
		}
	}))
	defer upstream.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, upstream.URL, &websocket.DialOptions{HTTPClient: &http.Client{Transport: newUpstreamTransport(http.DefaultTransport, 1<<20)}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	if err := conn.Write(ctx, websocket.MessageText, []byte("unchanged")); err != nil {
		t.Fatal(err)
	}
	_, body, err := conn.Read(ctx)
	if err != nil || string(body) != "unchanged" {
		t.Fatalf("websocket echo=%q err=%v", body, err)
	}
}
