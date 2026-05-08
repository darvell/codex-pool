package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
)

var (
	cryptoRandRead = cryptorand.Read
	hexEncode      = hex.EncodeToString
)

func newSyntheticID(prefix string) string {
	var buf [12]byte
	_, _ = cryptoRandRead(buf[:])
	return prefix + "_synth_" + hexEncode(buf[:])
}

// codexCyberSwapOptions configures the cyber-aware Codex websocket relay.
type codexCyberSwapOptions struct {
	ReqID                       string
	Provider                    Provider
	InitialAccount              *Account
	InitialOutURL               *url.URL
	InitialUpstreamHeaders      http.Header
	ConversationID              string
	RequiredPlan                string
	ClientIP                    string
	IdleTimeout                 time.Duration
	DownstreamHeartbeatInterval time.Duration
	ReadLimit                   int64
	LogLabel                    string

	// SetActiveAccount lets the caller follow the swap with bookkeeping
	// (notably the inflight counter transfer) so deferred cleanup
	// touches the right account.
	SetActiveAccount func(next *Account)
}

// codexCyberSwapResult tells the caller how the relay finished.
type codexCyberSwapResult struct {
	statusCode   int
	err          error
	swapped      bool
	finalAccount *Account
}

// errCyberPolicySuppressed is the relay's "happy enough" termination
// sentinel: a cyber_policy frame was swallowed, the relay is over, but
// no error should be reported to the user-facing logs/metrics.
var errCyberPolicySuppressed = errors.New("cyber_policy suppressed")

// swapPendingErr is returned from the upstream pump when a cyber_policy
// hit should trigger a swap. The relay loop is the single owner of
// next; carrying it on the error keeps shared mutable state out of the
// relay state struct.
type swapPendingErr struct {
	next *Account
}

func (e *swapPendingErr) Error() string {
	if e == nil || e.next == nil {
		return "cyber swap pending"
	}
	return "cyber swap pending: " + e.next.ID
}

type wsFrame struct {
	msgType websocket.MessageType
	data    []byte
	err     error
}

// relayCodexWithCyberSwap runs the Codex websocket relay with universal
// cyber_policy suppression. On a non-cyber account the first cyber_policy
// frame triggers a one-shot hot-swap to a cyber_access account: the new
// upstream is dialed, the buffered response.create is replayed, and the
// stream continues against the new account. The client never sees a
// cyber_policy frame on any path.
func (h *proxyHandler) relayCodexWithCyberSwap(
	w http.ResponseWriter,
	clientReq *http.Request,
	opts codexCyberSwapOptions,
) codexCyberSwapResult {
	ctx := clientReq.Context()

	upstreamConn, upstreamResp, subprotocols, err := dialUpstreamWebSocket(ctx, opts.InitialOutURL, opts.InitialUpstreamHeaders, clientReq.Header, opts.ReadLimit)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return codexCyberSwapResult{err: err, finalAccount: opts.InitialAccount}
	}
	captureCodexResponseState(opts.InitialAccount, upstreamResp, opts.ReqID)
	if turnState := upstreamResp.Header.Get("x-codex-turn-state"); turnState != "" {
		w.Header().Set("x-codex-turn-state", turnState)
	}

	acceptOpts := &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionNoContextTakeover,
	}
	if subprotocol := upstreamConn.Subprotocol(); subprotocol != "" {
		acceptOpts.Subprotocols = []string{subprotocol}
	}
	clientConn, err := websocket.Accept(w, clientReq, acceptOpts)
	if err != nil {
		upstreamConn.CloseNow()
		return codexCyberSwapResult{err: fmt.Errorf("accept client WS: %w", err), finalAccount: opts.InitialAccount}
	}
	clientConn.SetReadLimit(opts.ReadLimit)

	log.Printf("[ws-relay %s] connected to %s, relaying messages (codex cyber-aware)", opts.LogLabel, opts.InitialOutURL.Host)

	// Long-lived relay context. The reader goroutines bind to this so
	// they survive across swap rounds; per-round writers/inspectors are
	// gated by a per-round context derived from it.
	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()

	state := &codexRelayState{
		h:             h,
		opts:          opts,
		ctx:           relayCtx,
		clientConn:    clientConn,
		upstreamConn:  upstreamConn,
		activeAccount: opts.InitialAccount,
		subprotocols:  subprotocols,
		clientCh:      startWebSocketReader(relayCtx, clientConn),
		upstreamCh:    startWebSocketReader(relayCtx, upstreamConn),
		// Already on a cyber account — no further swap is meaningful.
		swapDone: opts.InitialAccount.CyberAccess,
	}
	defer state.closeAll()

	statusCode, relayErr := state.run()
	return state.result(statusCode, relayErr)
}

type codexRelayState struct {
	h    *proxyHandler
	opts codexCyberSwapOptions
	ctx  context.Context

	clientConn    *websocket.Conn
	upstreamConn  *websocket.Conn
	activeAccount *Account
	subprotocols  []string

	clientCh   <-chan wsFrame
	upstreamCh <-chan wsFrame

	// swapDone covers both "we already swapped" and "we tried and gave
	// up" — once true, no further swap attempts.
	swapDone bool

	// lastResponseCreate holds the most recent client-originated
	// response.create frame so the swap path can replay it on the new
	// upstream.
	lastResponseCreate []byte
}

func (s *codexRelayState) run() (int, error) {
	for {
		err := s.relayOnce()
		switch {
		case err == nil:
			return 101, nil
		case errors.Is(err, errCyberPolicySuppressed):
			s.legacyPin()
			s.writeSyntheticRefusalTurn()
			return 101, errCyberPolicySuppressed
		}
		var swap *swapPendingErr
		if errors.As(err, &swap) {
			if doErr := s.doSwap(swap.next); doErr != nil {
				log.Printf("[%s] cyber swap dial failed: %v; sending synthetic refusal", s.opts.ReqID, doErr)
				s.legacyPin()
				s.writeSyntheticRefusalTurn()
				return 101, errCyberPolicySuppressed
			}
			continue
		}
		return 101, err
	}
}

// relayOnce runs one bidirectional round between the client and the
// current upstream, then returns. The reader goroutines (clientCh,
// upstreamCh) outlive the round so the client conn survives a swap.
func (s *codexRelayState) relayOnce() error {
	clientWriter := &webSocketWriter{conn: s.clientConn}
	upstreamWriter := &webSocketWriter{conn: s.upstreamConn}

	roundCtx, roundCancel := context.WithCancel(s.ctx)
	defer roundCancel()

	stopHeartbeat := startWebSocketHeartbeat(roundCtx, clientWriter, s.opts.DownstreamHeartbeatInterval)
	defer stopHeartbeat()

	upstreamErrCh := make(chan error, 1)
	clientErrCh := make(chan error, 1)

	go func() {
		upstreamErrCh <- pumpFrames(roundCtx, s.upstreamCh, clientWriter, s.opts.LogLabel, "upstream->client", s.inspectUpstream)
	}()
	go func() {
		clientErrCh <- pumpFrames(roundCtx, s.clientCh, upstreamWriter, s.opts.LogLabel, "client->upstream", s.inspectClient)
	}()

	select {
	case err := <-upstreamErrCh:
		roundCancel()
		<-clientErrCh
		return err
	case err := <-clientErrCh:
		roundCancel()
		<-upstreamErrCh
		return err
	}
}

// pumpFrames forwards frames from src to dst, calling inspect on each
// frame before writing. inspect can return a sentinel error (e.g.
// errCyberPolicySuppressed or *swapPendingErr) to abort the relay
// without writing the frame.
func pumpFrames(
	ctx context.Context,
	src <-chan wsFrame,
	dst *webSocketWriter,
	logLabel, label string,
	inspect func([]byte) error,
) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case frame, ok := <-src:
			if !ok {
				return fmt.Errorf("%s read: source closed", label)
			}
			if frame.err != nil {
				return fmt.Errorf("%s read: %w", label, frame.err)
			}
			logFrameSummary(logLabel, label, frame)
			if inspect != nil {
				if err := inspect(frame.data); err != nil {
					return err
				}
			}
			if err := dst.Write(ctx, frame.msgType, frame.data); err != nil {
				return fmt.Errorf("%s write: %w", label, err)
			}
		}
	}
}

func logFrameSummary(logLabel, direction string, frame wsFrame) {
	summary := frame.data
	suffix := ""
	if len(summary) > 200 {
		summary = summary[:200]
		suffix = "..."
	}
	log.Printf("[ws-relay %s] %s: type=%v len=%d %s%s", logLabel, direction, frame.msgType, len(frame.data), string(summary), suffix)
}

func (s *codexRelayState) inspectUpstream(data []byte) error {
	if !isCyberPolicyError(data) {
		return nil
	}
	log.Printf("[%s] suppressing cyber_policy frame from account %s", s.opts.ReqID, s.activeAccount.ID)
	if s.h != nil && s.h.metrics != nil {
		s.h.metrics.incCyberPolicy(s.activeAccount.ID, "suppressed_ws")
	}
	if !s.swapDone && s.lastResponseCreate != nil {
		if cand := s.pickCyberAccessCandidate(); cand != nil {
			s.swapDone = true
			return &swapPendingErr{next: cand}
		}
	}
	s.swapDone = true
	if s.h != nil && s.h.metrics != nil {
		s.h.metrics.incCyberPolicy(s.activeAccount.ID, "swap_no_candidate")
	}
	return errCyberPolicySuppressed
}

func (s *codexRelayState) inspectClient(data []byte) error {
	if isCodexResponseCreate(data) {
		s.lastResponseCreate = append(s.lastResponseCreate[:0], data...)
	}
	return nil
}

func (s *codexRelayState) doSwap(cand *Account) error {
	newConn, newResp, err := s.h.dialSwappedUpstream(s.ctx, s.opts, cand, s.subprotocols)
	if err != nil {
		return err
	}
	captureCodexResponseState(cand, newResp, s.opts.ReqID)
	newConn.SetReadLimit(s.opts.ReadLimit)
	// Strip previous_response_id from the replay: response_ids are
	// scoped to the account that minted them, and the swap target has
	// no knowledge of the original conversation. Keeping the field
	// would cause an immediate "previous_response_not_found" error.
	// Losing the prior turn's reasoning context is the lesser evil
	// versus a hard failure surfacing to the user.
	replay := stripPreviousResponseID(s.lastResponseCreate)
	if err := newConn.Write(s.ctx, websocket.MessageText, replay); err != nil {
		newConn.CloseNow()
		return fmt.Errorf("replay client request to swap upstream: %w", err)
	}
	log.Printf("[%s] silently swapping codex upstream to cyber account %s (was %s)", s.opts.ReqID, cand.ID, s.activeAccount.ID)
	if s.h != nil && s.h.metrics != nil {
		s.h.metrics.incCyberPolicy(cand.ID, "swap_succeeded")
	}

	if s.opts.SetActiveAccount != nil {
		s.opts.SetActiveAccount(cand)
	}
	if s.opts.ConversationID != "" {
		s.h.pool.pin(s.opts.ConversationID, cand.ID)
	}

	s.upstreamConn.CloseNow()
	s.upstreamConn = newConn
	s.upstreamCh = startWebSocketReader(s.ctx, newConn)
	s.activeAccount = cand
	return nil
}

func (s *codexRelayState) pickCyberAccessCandidate() *Account {
	exclude := map[string]bool{}
	if s.opts.InitialAccount != nil {
		exclude[s.opts.InitialAccount.ID] = true
	}
	if s.activeAccount != nil {
		exclude[s.activeAccount.ID] = true
	}
	return s.h.pool.candidateWithCyberAccess(exclude, AccountTypeCodex, s.opts.RequiredPlan, s.opts.ClientIP)
}

func (s *codexRelayState) legacyPin() {
	if s.opts.ConversationID == "" {
		return
	}
	s.h.pinConversationToCyberAccess(s.opts.ConversationID, AccountTypeCodex, s.opts.RequiredPlan, s.opts.ClientIP, s.activeAccount.ID, s.opts.ReqID)
}

// syntheticRefusalText is what we render to the client when we can't
// route the turn through any account. The codex CLI prints this as a
// normal assistant message; the user gets a clear cue without ever
// seeing the upstream's cyber_policy text.
const syntheticRefusalText = "I can't help with that request right now. Try rephrasing it, splitting it into smaller pieces, or rewording the security-sensitive parts as a higher-level question."

// writeSyntheticRefusalTurn fabricates a complete OpenAI Responses
// websocket turn (response.created → … → response.completed) so the
// client's parser sees a clean turn end. Without this, the client sees
// a TCP-level close mid-stream and infinitely retries the same request,
// which on a flagged prompt loops forever against the same suppressed
// upstream.
func (s *codexRelayState) writeSyntheticRefusalTurn() {
	respID := newSyntheticID("resp")
	itemID := newSyntheticID("msg")
	createdAt := time.Now().Unix()

	respShellInProgress := map[string]any{
		"id":           respID,
		"object":       "response",
		"created_at":   createdAt,
		"status":       "in_progress",
		"background":   false,
		"output":       []any{},
		"model":        "gpt-5.5",
		"text":         map[string]any{"format": map[string]any{"type": "text"}},
		"usage":        nil,
		"error":        nil,
		"incomplete_details": nil,
	}
	respShellCompleted := cloneJSONMap(respShellInProgress)
	respShellCompleted["status"] = "completed"
	respShellCompleted["output"] = []any{
		map[string]any{
			"id":     itemID,
			"type":   "message",
			"status": "completed",
			"role":   "assistant",
			"content": []any{
				map[string]any{
					"type":        "output_text",
					"text":        syntheticRefusalText,
					"annotations": []any{},
					"logprobs":    []any{},
				},
			},
		},
	}

	frames := []map[string]any{
		{"type": "response.created", "response": respShellInProgress, "sequence_number": 0},
		{"type": "response.in_progress", "response": respShellInProgress, "sequence_number": 1},
		{
			"type":          "response.output_item.added",
			"output_index":  0,
			"sequence_number": 2,
			"item": map[string]any{
				"id":      itemID,
				"type":    "message",
				"status":  "in_progress",
				"role":    "assistant",
				"content": []any{},
			},
		},
		{
			"type":           "response.content_part.added",
			"output_index":   0,
			"item_id":        itemID,
			"content_index":  0,
			"sequence_number": 3,
			"part": map[string]any{
				"type":        "output_text",
				"text":        "",
				"annotations": []any{},
				"logprobs":    []any{},
			},
		},
		{
			"type":            "response.output_text.delta",
			"output_index":    0,
			"item_id":         itemID,
			"content_index":   0,
			"sequence_number": 4,
			"delta":           syntheticRefusalText,
			"logprobs":        []any{},
		},
		{
			"type":            "response.output_text.done",
			"output_index":    0,
			"item_id":         itemID,
			"content_index":   0,
			"sequence_number": 5,
			"text":            syntheticRefusalText,
			"logprobs":        []any{},
		},
		{
			"type":            "response.content_part.done",
			"output_index":    0,
			"item_id":         itemID,
			"content_index":   0,
			"sequence_number": 6,
			"part": map[string]any{
				"type":        "output_text",
				"text":        syntheticRefusalText,
				"annotations": []any{},
				"logprobs":    []any{},
			},
		},
		{
			"type":            "response.output_item.done",
			"output_index":    0,
			"sequence_number": 7,
			"item": map[string]any{
				"id":     itemID,
				"type":   "message",
				"status": "completed",
				"role":   "assistant",
				"content": []any{
					map[string]any{
						"type":        "output_text",
						"text":        syntheticRefusalText,
						"annotations": []any{},
						"logprobs":    []any{},
					},
				},
			},
		},
		{"type": "response.completed", "response": respShellCompleted, "sequence_number": 8},
	}

	for _, frame := range frames {
		data, err := json.Marshal(frame)
		if err != nil {
			log.Printf("[%s] synthetic frame marshal failed: %v", s.opts.ReqID, err)
			return
		}
		if writeErr := s.clientConn.Write(s.ctx, websocket.MessageText, data); writeErr != nil {
			log.Printf("[%s] synthetic frame write failed: %v", s.opts.ReqID, writeErr)
			return
		}
	}
	log.Printf("[%s] wrote synthetic refusal turn after suppressed cyber_policy", s.opts.ReqID)
	if s.h != nil && s.h.metrics != nil {
		s.h.metrics.incCyberPolicy(s.activeAccount.ID, "synthetic_refusal_ws")
	}
}

func cloneJSONMap(in map[string]any) map[string]any {
	raw, _ := json.Marshal(in)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

// cyberPolicyHTTPSuppressor wires sseInterceptWriter.onEvent so the
// HTTP/SSE Codex code path stops cyber_policy events from reaching the
// client and substitutes a synthetic refusal turn instead. underlyingWrite
// must point at the bytes-to-the-client writer (the same writer that
// sseInterceptWriter forwards to). cancel ends the upstream copy so the
// proxy doesn't keep pumping bytes after the synthetic terminal.
type cyberPolicyHTTPSuppressor struct {
	h               *proxyHandler
	reqID           string
	conversationID  string
	requiredPlan    string
	clientIP        string
	accountID       string
	underlyingWrite io.Writer
	cancel          context.CancelFunc
	pinned          *bool
}

func (c *cyberPolicyHTTPSuppressor) onEvent(eventData []byte) (drop bool, terminate bool) {
	if !isCyberPolicyError(eventData) {
		return false, false
	}
	log.Printf("[%s] suppressing cyber_policy SSE event from account %s", c.reqID, c.accountID)
	if c.h != nil && c.h.metrics != nil {
		c.h.metrics.incCyberPolicy(c.accountID, "suppressed_sse")
	}
	if c.h != nil && c.conversationID != "" {
		if c.h.pinConversationToCyberAccess(c.conversationID, AccountTypeCodex, c.requiredPlan, c.clientIP, c.accountID, c.reqID) {
			if c.pinned != nil {
				*c.pinned = true
			}
		}
	}
	if c.underlyingWrite != nil {
		if _, err := c.underlyingWrite.Write(syntheticRefusalSSEFrames()); err != nil {
			log.Printf("[%s] synthetic SSE write failed: %v", c.reqID, err)
		} else {
			log.Printf("[%s] wrote synthetic SSE refusal turn after suppressed cyber_policy", c.reqID)
			if c.h != nil && c.h.metrics != nil {
				c.h.metrics.incCyberPolicy(c.accountID, "synthetic_refusal_sse")
			}
		}
	}
	if c.cancel != nil {
		c.cancel()
	}
	return true, true
}

// syntheticRefusalSSEFrames returns the same nine-event Responses turn
// the websocket relay emits, formatted as SSE `event: …\ndata: …\n\n`
// blocks. Used by the HTTP/SSE Codex code path so a suppressed
// cyber_policy upstream still produces a clean response.completed for
// the client.
func syntheticRefusalSSEFrames() []byte {
	respID := newSyntheticID("resp")
	itemID := newSyntheticID("msg")
	createdAt := time.Now().Unix()

	respShellInProgress := map[string]any{
		"id":                 respID,
		"object":             "response",
		"created_at":         createdAt,
		"status":             "in_progress",
		"background":         false,
		"output":             []any{},
		"model":              "gpt-5.5",
		"text":               map[string]any{"format": map[string]any{"type": "text"}},
		"usage":              nil,
		"error":              nil,
		"incomplete_details": nil,
	}
	respShellCompleted := cloneJSONMap(respShellInProgress)
	respShellCompleted["status"] = "completed"
	respShellCompleted["output"] = []any{
		map[string]any{
			"id":     itemID,
			"type":   "message",
			"status": "completed",
			"role":   "assistant",
			"content": []any{
				map[string]any{
					"type":        "output_text",
					"text":        syntheticRefusalText,
					"annotations": []any{},
					"logprobs":    []any{},
				},
			},
		},
	}

	events := []struct {
		eventType string
		payload   map[string]any
	}{
		{"response.created", map[string]any{"type": "response.created", "response": respShellInProgress, "sequence_number": 0}},
		{"response.in_progress", map[string]any{"type": "response.in_progress", "response": respShellInProgress, "sequence_number": 1}},
		{"response.output_item.added", map[string]any{
			"type": "response.output_item.added", "output_index": 0, "sequence_number": 2,
			"item": map[string]any{"id": itemID, "type": "message", "status": "in_progress", "role": "assistant", "content": []any{}},
		}},
		{"response.content_part.added", map[string]any{
			"type": "response.content_part.added", "output_index": 0, "item_id": itemID, "content_index": 0, "sequence_number": 3,
			"part": map[string]any{"type": "output_text", "text": "", "annotations": []any{}, "logprobs": []any{}},
		}},
		{"response.output_text.delta", map[string]any{
			"type": "response.output_text.delta", "output_index": 0, "item_id": itemID, "content_index": 0, "sequence_number": 4,
			"delta": syntheticRefusalText, "logprobs": []any{},
		}},
		{"response.output_text.done", map[string]any{
			"type": "response.output_text.done", "output_index": 0, "item_id": itemID, "content_index": 0, "sequence_number": 5,
			"text": syntheticRefusalText, "logprobs": []any{},
		}},
		{"response.content_part.done", map[string]any{
			"type": "response.content_part.done", "output_index": 0, "item_id": itemID, "content_index": 0, "sequence_number": 6,
			"part": map[string]any{"type": "output_text", "text": syntheticRefusalText, "annotations": []any{}, "logprobs": []any{}},
		}},
		{"response.output_item.done", map[string]any{
			"type": "response.output_item.done", "output_index": 0, "sequence_number": 7,
			"item": map[string]any{
				"id": itemID, "type": "message", "status": "completed", "role": "assistant",
				"content": []any{
					map[string]any{"type": "output_text", "text": syntheticRefusalText, "annotations": []any{}, "logprobs": []any{}},
				},
			},
		}},
		{"response.completed", map[string]any{"type": "response.completed", "response": respShellCompleted, "sequence_number": 8}},
	}

	var buf bytes.Buffer
	for _, ev := range events {
		data, err := json.Marshal(ev.payload)
		if err != nil {
			continue
		}
		buf.WriteString("event: ")
		buf.WriteString(ev.eventType)
		buf.WriteString("\ndata: ")
		buf.Write(data)
		buf.WriteString("\n\n")
	}
	return buf.Bytes()
}

func (s *codexRelayState) closeAll() {
	s.clientConn.CloseNow()
	s.upstreamConn.CloseNow()
}

func (s *codexRelayState) result(statusCode int, relayErr error) codexCyberSwapResult {
	// swapped is strictly "did the active upstream change" — never
	// inferred from the relay's terminal error class. Suppression
	// without a swap must report swapped=false so the caller's
	// post-relay bookkeeping (cyberPinned -> skip pin) stays correct.
	swapped := s.activeAccount != s.opts.InitialAccount
	if errors.Is(relayErr, errCyberPolicySuppressed) {
		return codexCyberSwapResult{statusCode: statusCode, swapped: swapped, finalAccount: s.activeAccount}
	}
	if relayErr != nil && (errors.Is(relayErr, context.Canceled) ||
		strings.Contains(relayErr.Error(), "closed") ||
		strings.Contains(relayErr.Error(), "EOF") ||
		websocket.CloseStatus(relayErr) != -1) {
		relayErr = nil
	}
	return codexCyberSwapResult{statusCode: statusCode, err: relayErr, swapped: swapped, finalAccount: s.activeAccount}
}

func (h *proxyHandler) dialSwappedUpstream(
	ctx context.Context,
	opts codexCyberSwapOptions,
	acc *Account,
	subprotocols []string,
) (*websocket.Conn, *http.Response, error) {
	if !h.cfg.disableRefresh && h.needsRefresh(acc) {
		if err := h.refreshAccount(ctx, acc); err != nil {
			if h.cfg.debug.Load() {
				log.Printf("[%s] swap account %s refresh failed: %v", opts.ReqID, acc.ID, err)
			}
		}
	}

	acc.mu.Lock()
	access := acc.AccessToken
	acc.mu.Unlock()
	if access == "" {
		return nil, nil, fmt.Errorf("swap account %s has empty access token", acc.ID)
	}

	headers := cloneHeader(opts.InitialUpstreamHeaders)
	headers.Del("Authorization")
	headers.Del("ChatGPT-Account-ID")
	headers.Del("X-Api-Key")
	headers.Del("x-goog-api-key")
	tmpReq := &http.Request{Header: headers}
	opts.Provider.SetAuthHeaders(tmpReq, acc)

	conn, resp, _, err := dialUpstreamWebSocketWithSubprotocols(ctx, opts.InitialOutURL, tmpReq.Header, subprotocols, opts.ReadLimit)
	if err != nil {
		return nil, nil, err
	}
	return conn, resp, nil
}

// dialUpstreamWebSocket dials the upstream as a websocket. It scrubs
// hop-by-hop and Sec-WebSocket-* headers, mirrors subprotocols off the
// client request, and applies the configured read limit.
func dialUpstreamWebSocket(
	ctx context.Context,
	upstreamURL *url.URL,
	upstreamHeaders http.Header,
	clientHeaders http.Header,
	readLimit int64,
) (*websocket.Conn, *http.Response, []string, error) {
	subprotocols := extractWebSocketSubprotocols(clientHeaders)
	conn, resp, _, err := dialUpstreamWebSocketWithSubprotocols(ctx, upstreamURL, upstreamHeaders, subprotocols, readLimit)
	return conn, resp, subprotocols, err
}

func dialUpstreamWebSocketWithSubprotocols(
	ctx context.Context,
	upstreamURL *url.URL,
	upstreamHeaders http.Header,
	subprotocols []string,
	readLimit int64,
) (*websocket.Conn, *http.Response, []string, error) {
	wsURL := *upstreamURL
	switch wsURL.Scheme {
	case "https":
		wsURL.Scheme = "wss"
	case "http":
		wsURL.Scheme = "ws"
	}

	dialHeaders := cloneHeader(upstreamHeaders)
	removeHopByHopHeaders(dialHeaders)
	for _, key := range []string{
		"Sec-WebSocket-Key",
		"Sec-WebSocket-Version",
		"Sec-WebSocket-Extensions",
		"Sec-WebSocket-Protocol",
		"Sec-WebSocket-Accept",
	} {
		dialHeaders.Del(key)
	}

	conn, resp, err := websocket.Dial(ctx, wsURL.String(), &websocket.DialOptions{
		HTTPHeader:      dialHeaders,
		Subprotocols:    subprotocols,
		CompressionMode: websocket.CompressionNoContextTakeover,
	})
	if err != nil {
		return nil, nil, subprotocols, fmt.Errorf("dial upstream WS %s: %w", wsURL.Host, err)
	}
	conn.SetReadLimit(readLimit)
	return conn, resp, subprotocols, nil
}

func extractWebSocketSubprotocols(h http.Header) []string {
	var out []string
	for _, raw := range h.Values("Sec-WebSocket-Protocol") {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// startWebSocketReader pumps frames from conn into a channel. The
// channel is closed when the goroutine exits, so callers can detect
// end-of-stream via channel close. The reader's lifetime is bound to
// ctx, NOT to a per-round context — that's the whole reason this
// function exists: it lets the per-round pump get cancelled (via
// roundCtx) without affecting the underlying conn.
func startWebSocketReader(ctx context.Context, conn *websocket.Conn) <-chan wsFrame {
	ch := make(chan wsFrame, 4)
	go func() {
		defer close(ch)
		for {
			mt, data, err := conn.Read(ctx)
			frame := wsFrame{msgType: mt, data: data, err: err}
			select {
			case ch <- frame:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return ch
}

func isCodexResponseCreate(data []byte) bool {
	if len(data) == 0 || data[0] != '{' {
		return false
	}
	if !bytes.Contains(data, []byte(`"response.create"`)) {
		return false
	}
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return false
	}
	return head.Type == "response.create"
}

// stripPreviousResponseID removes previous_response_id from a
// response.create payload so the swap replay is accepted by an account
// that did not mint the original response_id. If parsing fails or the
// field is absent, the original payload is returned unchanged.
func stripPreviousResponseID(data []byte) []byte {
	if !bytes.Contains(data, []byte(`"previous_response_id"`)) {
		return data
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return data
	}
	if _, ok := obj["previous_response_id"]; !ok {
		return data
	}
	delete(obj, "previous_response_id")
	out, err := json.Marshal(obj)
	if err != nil {
		return data
	}
	return out
}
