package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

func (h *proxyHandler) proxyProOnlyWebSocket(w http.ResponseWriter, r *http.Request, reqID string) {
	options := &websocket.AcceptOptions{InsecureSkipVerify: true}
	if h.cfg.websocketCompression {
		options.CompressionMode = websocket.CompressionNoContextTakeover
	}
	conn, err := websocket.Accept(w, r, options)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	limit := effectiveWebSocketReadLimit(AccountTypeCodex, h.cfg.websocketReadLimit)
	conn.SetReadLimit(limit)
	writer := &webSocketWriter{conn: conn}
	registry := h.webSocketRegistry()
	session := registry.register(conn)
	defer registry.unregister(session)
	atomic.AddInt64(&h.inflight, 1)
	defer atomic.AddInt64(&h.inflight, -1)
	activity := make(chan struct{}, 1)
	var bridge *chatGPTProWS
	bridge = newChatGPTProWS(ctx, r, h.handleChatGPTPro, func(ctx context.Context, data []byte) error {
		if err := writer.Write(ctx, websocket.MessageText, data); err != nil {
			return err
		}
		select {
		case activity <- struct{}{}:
		default:
		}
		return nil
	}, limit, func() { session.setActive(bridge.Active()) })
	defer bridge.Close()
	heartbeatErr, stopHeartbeat := startWebSocketHeartbeat(ctx, writer, h.cfg.websocketHeartbeatInterval, "client")
	defer stopHeartbeat()
	var idle *time.Timer
	var idleCh <-chan time.Time
	if h.cfg.websocketIdleTimeout > 0 {
		idle = time.NewTimer(h.cfg.websocketIdleTimeout)
		idleCh = idle.C
		defer idle.Stop()
	}
	resetIdle := func() {
		if idle == nil {
			return
		}
		if !idle.Stop() {
			select {
			case <-idle.C:
			default:
			}
		}
		idle.Reset(h.cfg.websocketIdleTimeout)
	}
	frames := startWebSocketReader(ctx, conn)
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeatErr:
			return
		case <-idleCh:
			return
		case <-activity:
			resetIdle()
		case frame, ok := <-frames:
			if !ok || frame.err != nil {
				return
			}
			resetIdle()
			data := applyModelAliasToJSONFrame(h, reqID, frame.data)
			userID, _, _, _, _ := h.authorizePoolCredentialRequest(r)
			data = applyEffortCapToJSONFrame(h, reqID, userID, getClientIP(r), data)
			handled, err := bridge.Handle(data)
			session.setActive(bridge.Active())
			if err != nil {
				return
			}
			if !handled {
				if err := proWSError(ctx, func(ctx context.Context, data []byte) error { return writer.Write(ctx, websocket.MessageText, data) }, http.StatusServiceUnavailable, map[string]any{"type": "server_error", "message": "This model is unavailable on this connection."}); err != nil {
					return
				}
			}
		}
	}
}

type proWSHandler func(http.ResponseWriter, *http.Request, []byte, string) bool
type proWSWrite func(context.Context, []byte) error

// chatGPTProWS bridges only Pro response.create frames. The owning relay keeps
// reading the socket and owns its read limit, heartbeat and close handshake.
// Close must run when that relay ends, so an HTTP turn cannot outlive the socket.
type chatGPTProWS struct {
	ctx     context.Context
	cancel  context.CancelFunc
	request *http.Request
	handle  proWSHandler
	write   proWSWrite
	limit   int64
	mu      sync.Mutex
	busy    bool
	closed  bool
	done    chan struct{}
	workers sync.WaitGroup
	onDone  func()
}

func newChatGPTProWS(ctx context.Context, r *http.Request, handle proWSHandler, write proWSWrite, limit int64, onDone func()) *chatGPTProWS {
	ctx, cancel := context.WithCancel(ctx)
	return &chatGPTProWS{ctx: ctx, cancel: cancel, request: r, handle: handle, write: write, limit: effectiveWebSocketReadLimit(AccountTypeCodex, limit), onDone: onDone}
}

// Handle returns false without modifying ordinary Codex frames. A handled frame
// must not also be forwarded to the ordinary upstream or context rehydrator.
func (b *chatGPTProWS) Handle(frame []byte) (bool, error) {
	if int64(len(frame)) > b.limit {
		return true, b.writeError(http.StatusBadRequest, "Request exceeds WebSocket read limit")
	}
	if !isCodexResponseCreate(frame) || proModel(extractCodexWebSocketRequestedModel(frame)) == "" {
		return false, nil
	}
	body, model, err := proWSRequest(frame, b.limit)
	if err != nil {
		return true, b.writeError(http.StatusBadRequest, err.Error())
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return true, context.Canceled
	}
	if b.busy {
		b.mu.Unlock()
		return true, b.writeError(http.StatusConflict, "A Pro response is already in progress")
	}
	b.busy = true
	done := make(chan struct{})
	b.done = done
	b.workers.Add(1)
	b.mu.Unlock()
	go func() {
		defer b.workers.Done()
		defer func() {
			b.mu.Lock()
			if b.done == done {
				b.busy = false
			}
			b.mu.Unlock()
			if b.onDone != nil {
				b.onDone()
			}
			close(done)
		}()
		ctx, cancel := context.WithCancel(b.ctx)
		defer cancel()
		r := b.request.Clone(ctx)
		r.Method = http.MethodPost
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "text/event-stream")
		write := func(ctx context.Context, data []byte) error {
			var event struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(data, &event) == nil && (isTerminalCodexWebSocketEvent(data) || event.Type == "error") {
				b.mu.Lock()
				if b.done == done {
					b.busy = false
				}
				b.mu.Unlock()
			}
			return b.write(ctx, data)
		}
		w := &proWSResponse{header: make(http.Header), ctx: ctx, cancel: cancel, write: write, limit: b.limit}
		if !b.handle(w, r, body, model) {
			_ = proWSError(ctx, write, http.StatusBadRequest, map[string]any{"message": "Pro Responses route unavailable"})
			return
		}
		if err := w.finish(); err != nil && b.ctx.Err() == nil {
			_ = proWSError(b.ctx, write, http.StatusBadGateway, map[string]any{"message": err.Error()})
		}
	}()
	return true, nil
}

func (b *chatGPTProWS) Close() {
	b.mu.Lock()
	b.closed = true
	b.cancel()
	b.mu.Unlock()
	b.workers.Wait()
}

func (b *chatGPTProWS) Active() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.busy
}

func (b *chatGPTProWS) writeError(status int, message string) error {
	return proWSError(b.ctx, b.write, status, map[string]any{"type": "invalid_request_error", "message": message})
}

func proWSRequest(frame []byte, limit int64) ([]byte, string, error) {
	if int64(len(frame)) > limit {
		return nil, "", errors.New("Pro request exceeds WebSocket read limit")
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(frame, &object) != nil || object == nil {
		return nil, "", errors.New("Invalid Responses request")
	}
	if nested, exists := object["response"]; exists {
		if json.Unmarshal(nested, &object) != nil || object == nil {
			return nil, "", errors.New("Invalid Responses request")
		}
	}
	delete(object, "type")
	object["stream"] = json.RawMessage("true")
	body, err := json.Marshal(object)
	return body, extractRequestedModelFromJSON(body), err
}

// proWSResponse implements the HTTP adapter's streaming writer without an HTTP
// round trip. Events are forwarded unchanged: tool names, arguments, custom
// inputs, response IDs and error events are owned by the native translator.
type proWSResponse struct {
	header   http.Header
	status   int
	ctx      context.Context
	cancel   context.CancelFunc
	write    proWSWrite
	limit    int64
	line     []byte
	data     []byte
	body     []byte
	terminal bool
	err      error
}

func (w *proWSResponse) Header() http.Header { return w.header }
func (w *proWSResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *proWSResponse) Flush() {}

func (w *proWSResponse) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if !strings.HasPrefix(w.header.Get("Content-Type"), "text/event-stream") {
		if int64(len(w.body))+int64(len(p)) > w.limit {
			return 0, w.fail(errors.New("Pro error exceeds WebSocket read limit"))
		}
		w.body = append(w.body, p...)
		return len(p), nil
	}
	for _, c := range p {
		if c != '\n' {
			if int64(len(w.line))+int64(len(w.data)) >= w.limit {
				return 0, w.fail(errors.New("Pro event exceeds WebSocket read limit"))
			}
			w.line = append(w.line, c)
			continue
		}
		line := bytes.TrimSuffix(w.line, []byte{'\r'})
		if len(line) == 0 {
			if err := w.event(); err != nil {
				return 0, w.fail(err)
			}
		} else if bytes.HasPrefix(line, []byte("data:")) {
			value := bytes.TrimPrefix(line, []byte("data:"))
			value = bytes.TrimPrefix(value, []byte{' '})
			w.data = append(w.data, value...)
			w.data = append(w.data, '\n')
		}
		w.line = w.line[:0]
	}
	return len(p), nil
}

func (w *proWSResponse) fail(err error) error { w.err = err; w.cancel(); return err }

func (w *proWSResponse) event() error {
	data := bytes.TrimSpace(w.data)
	defer func() { w.data = w.data[:0] }()
	if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
		return nil
	}
	var event struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &event) != nil || event.Type == "" {
		return errors.New("Invalid Pro Responses event")
	}
	if err := w.write(w.ctx, data); err != nil {
		return err
	}
	if isTerminalCodexWebSocketEvent(data) || event.Type == "error" {
		w.terminal = true
	}
	return nil
}

func (w *proWSResponse) finish() error {
	if w.err != nil {
		return w.err
	}
	if w.ctx.Err() != nil {
		return w.ctx.Err()
	}
	if strings.HasPrefix(w.header.Get("Content-Type"), "text/event-stream") {
		if len(w.line) != 0 || len(w.data) != 0 {
			return errors.New("Pro Responses stream ended mid-event")
		}
		if !w.terminal {
			return errors.New("Pro Responses stream ended without a terminal event")
		}
		return nil
	}
	status := w.status
	if status < http.StatusBadRequest {
		return errors.New("Pro Responses adapter returned no event stream")
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(w.body, &result) != nil {
		return errors.New("Invalid Pro error response")
	}
	var detail any
	if json.Unmarshal(result["error"], &detail) != nil {
		return errors.New("Invalid Pro error response")
	}
	if message, ok := detail.(string); ok {
		detail = map[string]any{"message": message}
	}
	return proWSError(w.ctx, w.write, status, detail)
}

func proWSError(ctx context.Context, write proWSWrite, status int, detail any) error {
	payload, err := json.Marshal(map[string]any{"type": "error", "status": status, "error": detail})
	if err != nil {
		return err
	}
	return write(ctx, payload)
}
