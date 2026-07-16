package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
)

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
	UserID                      string
	OriginID                    string
	IdleTimeout                 time.Duration
	DownstreamHeartbeatInterval time.Duration
	ReadLimit                   int64
	CompressionEnabled          bool
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

// swapPendingErr is returned from the upstream pump on a cyber_policy
// hit. next is the swap target, or nil when no cyber_access candidate
// was available; frame is the original upstream payload, forwarded to
// the client when the swap is skipped or fails so the user sees the
// real upstream error instead of a fabricated message.
type swapPendingErr struct {
	next  *Account
	frame []byte
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

	upstreamConn, upstreamResp, subprotocols, err := dialUpstreamWebSocket(ctx, opts.InitialOutURL, opts.InitialUpstreamHeaders, clientReq.Header, opts.ReadLimit, opts.CompressionEnabled)
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
	}
	if opts.CompressionEnabled {
		acceptOpts.CompressionMode = websocket.CompressionNoContextTakeover
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
		clientWriter:  &webSocketWriter{conn: clientConn},
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
	clientWriter  *webSocketWriter
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
	requestedModel     string
	recordedResponses  map[string]struct{}
}

func (s *codexRelayState) run() (int, error) {
	for {
		err := s.relayOnce()
		if err == nil {
			return 101, nil
		}
		var swap *swapPendingErr
		if errors.As(err, &swap) {
			if swap.next != nil {
				if doErr := s.doSwap(swap.next); doErr != nil {
					log.Printf("[%s] cyber swap dial failed: %v; forwarding upstream cyber_policy frame", s.opts.ReqID, doErr)
					s.forwardCyberPolicy(swap.frame)
					s.legacyPin()
					return 101, nil
				}
				continue
			}
			// No swap target — surface the upstream's real cyber_policy
			// frame and end the relay cleanly.
			s.forwardCyberPolicy(swap.frame)
			s.legacyPin()
			return 101, nil
		}
		return 101, err
	}
}

// forwardCyberPolicy writes the upstream cyber_policy frame through to
// the client. Routed via clientWriter so it serializes against the
// heartbeat goroutine that may also be writing.
func (s *codexRelayState) forwardCyberPolicy(frame []byte) {
	if err := s.clientWriter.Write(s.ctx, websocket.MessageText, frame); err != nil {
		log.Printf("[%s] forward cyber_policy frame to client failed: %v", s.opts.ReqID, err)
	}
}

// relayOnce runs one bidirectional round between the client and the
// current upstream, then returns. The reader goroutines (clientCh,
// upstreamCh) outlive the round so the client conn survives a swap.
func (s *codexRelayState) relayOnce() error {
	upstreamWriter := &webSocketWriter{conn: s.upstreamConn}

	roundCtx, roundCancel := context.WithCancel(s.ctx)
	defer roundCancel()

	stopHeartbeat := startWebSocketHeartbeat(roundCtx, s.clientWriter, s.opts.DownstreamHeartbeatInterval)
	defer stopHeartbeat()

	upstreamErrCh := make(chan error, 1)
	clientErrCh := make(chan error, 1)
	activityCh := make(chan struct{}, 1)

	debug := s.h != nil && s.h.cfg != nil && s.h.cfg.debug.Load()
	go func() {
		upstreamErrCh <- pumpFrames(roundCtx, s.upstreamCh, s.clientWriter, s.opts.LogLabel, "upstream->client", debug, s.inspectUpstream, activityCh)
	}()
	go func() {
		clientErrCh <- pumpFrames(roundCtx, s.clientCh, upstreamWriter, s.opts.LogLabel, "client->upstream", debug, s.inspectClient, activityCh)
	}()

	var idleTimer *time.Timer
	var idleCh <-chan time.Time
	if s.opts.IdleTimeout > 0 {
		idleTimer = time.NewTimer(s.opts.IdleTimeout)
		idleCh = idleTimer.C
		defer idleTimer.Stop()
	}
	for {
		select {
		case err := <-upstreamErrCh:
			roundCancel()
			<-clientErrCh
			return err
		case err := <-clientErrCh:
			roundCancel()
			<-upstreamErrCh
			return err
		case <-activityCh:
			if idleTimer != nil {
				if !idleTimer.Stop() {
					select {
					case <-idleTimer.C:
					default:
					}
				}
				idleTimer.Reset(s.opts.IdleTimeout)
			}
		case <-idleCh:
			roundCancel()
			<-upstreamErrCh
			<-clientErrCh
			return fmt.Errorf("websocket idle timeout after %s", s.opts.IdleTimeout)
		}
	}
}

// pumpFrames forwards frames from src to dst, calling inspect on each
// frame before writing. inspect may rewrite the frame (returned []byte)
// and/or return a sentinel error (e.g. *swapPendingErr) to abort the
// relay without writing the frame.
func pumpFrames(
	ctx context.Context,
	src <-chan wsFrame,
	dst *webSocketWriter,
	logLabel, label string,
	debug bool,
	inspect func([]byte) ([]byte, error),
	activity chan<- struct{},
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
			select {
			case activity <- struct{}{}:
			default:
			}
			data := frame.data
			if debug {
				logRelayFrame(logLabel, label, frame.msgType, data)
			}
			if inspect != nil {
				rewritten, err := inspect(data)
				if err != nil {
					return err
				}
				if rewritten != nil {
					data = rewritten
				}
			}
			if err := dst.Write(ctx, frame.msgType, data); err != nil {
				return fmt.Errorf("%s write: %w", label, err)
			}
		}
	}
}

func (s *codexRelayState) inspectUpstream(data []byte) ([]byte, error) {
	s.recordCompletedUsage(data)
	if !isCyberPolicyError(data) {
		return data, nil
	}
	log.Printf("[%s] cyber_policy frame from account %s", s.opts.ReqID, s.activeAccount.ID)
	if s.h != nil && s.h.metrics != nil {
		s.h.metrics.incCyberPolicy(s.activeAccount.ID, "suppressed_ws")
	}
	if !s.swapDone && s.lastResponseCreate != nil {
		if cand := s.pickCyberAccessCandidate(); cand != nil {
			s.swapDone = true
			return data, &swapPendingErr{next: cand, frame: data}
		}
	}
	s.swapDone = true
	if s.h != nil && s.h.metrics != nil {
		s.h.metrics.incCyberPolicy(s.activeAccount.ID, "swap_no_candidate")
	}
	return data, &swapPendingErr{frame: data}
}

func (s *codexRelayState) inspectClient(data []byte) ([]byte, error) {
	if isCodexResponseCreate(data) {
		data = applyModelAliasToJSONFrame(s.h, s.opts.ReqID, data)
		s.lastResponseCreate = append(s.lastResponseCreate[:0], data...)
		s.requestedModel = extractRequestedModelFromJSON(data)
	}
	return data, nil
}

// recordCompletedUsage sends terminal Codex websocket usage through the same
// accounting path as HTTP/SSE. A websocket can carry multiple turns, and a
// cyber swap changes which account owns the active turn, so attribution is
// resolved from state at the moment the completion arrives.
func (s *codexRelayState) recordCompletedUsage(data []byte) {
	if s.h == nil || s.opts.Provider == nil || s.activeAccount == nil || len(data) == 0 {
		return
	}

	var event map[string]any
	if err := json.Unmarshal(data, &event); err != nil || event["type"] != "response.completed" {
		return
	}

	responseID := ""
	if response, ok := event["response"].(map[string]any); ok {
		responseID, _ = response["id"].(string)
	}
	if responseID == "" {
		responseID, _ = event["id"].(string)
	}
	if responseID != "" {
		if s.recordedResponses == nil {
			s.recordedResponses = make(map[string]struct{})
		}
		if _, recorded := s.recordedResponses[responseID]; recorded {
			return
		}
	}

	ru := s.opts.Provider.ParseUsage(event)
	if ru == nil {
		return
	}
	if responseID != "" {
		s.recordedResponses[responseID] = struct{}{}
		ru.RequestID = responseID
	}

	account := s.activeAccount
	ru.AccountID = account.ID
	ru.AccountType = account.Type
	ru.UserID = s.opts.UserID
	ru.OriginID = s.opts.OriginID
	account.mu.Lock()
	ru.PlanType = account.PlanType
	account.mu.Unlock()
	if ru.Model == "" {
		ru.Model = s.requestedModel
	}
	s.h.recordUsage(account, *ru)
}

// applyModelAliasToJSONFrame rewrites a top-level JSON "model" field when a
// configured/built-in alias matches (e.g. gpt-5.6 -> gpt-5.6-sol).
func applyModelAliasToJSONFrame(h *proxyHandler, reqID string, data []byte) []byte {
	if h == nil || h.aliases == nil || len(data) == 0 {
		return data
	}
	model := extractRequestedModelFromJSON(data)
	if model == "" {
		return data
	}
	resolved, ok := h.aliases.resolve(model)
	if !ok || resolved == model {
		return data
	}
	if rewritten := rewriteModelInBody(data, resolved); rewritten != nil {
		if h.cfg != nil && h.cfg.debug.Load() {
			log.Printf("[%s] ws model alias: %s -> %s", reqID, model, resolved)
		}
		return rewritten
	}
	return data
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

// cyberPolicyHTTPSuppressor wires sseInterceptWriter.onEvent so the
// HTTP/SSE Codex code path can pin the conversation to a cyber_access
// account on cyber_policy. The event itself is forwarded to the client
// unchanged — we don't fabricate fake assistant text. The conversation
// pin steers the next turn through a cyber account so the user just
// retries and it works.
type cyberPolicyHTTPSuppressor struct {
	h              *proxyHandler
	reqID          string
	conversationID string
	requiredPlan   string
	clientIP       string
	accountID      string
	pinned         *bool
}

func (c *cyberPolicyHTTPSuppressor) onEvent(eventData []byte) (drop bool, terminate bool) {
	if !isCyberPolicyError(eventData) {
		return false, false
	}
	log.Printf("[%s] cyber_policy SSE event from account %s; pinning conversation, forwarding error", c.reqID, c.accountID)
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
	// drop=false: pass the upstream's real cyber_policy frame through.
	// terminate=false: let the upstream complete normally — it usually
	// emits response.failed/response.completed right after the error,
	// and forwarding those keeps the client's parser happy.
	return false, false
}

func (s *codexRelayState) closeAll() {
	s.clientConn.CloseNow()
	s.upstreamConn.CloseNow()
}

func (s *codexRelayState) result(statusCode int, relayErr error) codexCyberSwapResult {
	// swapped reflects whether the active upstream actually changed.
	// run() always returns nil error on the cyber_policy passthrough
	// path, so caller bookkeeping (cyberPinned -> skip pin) sees an
	// honest swapped=false there.
	swapped := s.activeAccount != s.opts.InitialAccount
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

	conn, resp, _, err := dialUpstreamWebSocketWithSubprotocols(ctx, opts.InitialOutURL, tmpReq.Header, subprotocols, opts.ReadLimit, opts.CompressionEnabled)
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
	compressionEnabled bool,
) (*websocket.Conn, *http.Response, []string, error) {
	subprotocols := extractWebSocketSubprotocols(clientHeaders)
	conn, resp, _, err := dialUpstreamWebSocketWithSubprotocols(ctx, upstreamURL, upstreamHeaders, subprotocols, readLimit, compressionEnabled)
	return conn, resp, subprotocols, err
}

func dialUpstreamWebSocketWithSubprotocols(
	ctx context.Context,
	upstreamURL *url.URL,
	upstreamHeaders http.Header,
	subprotocols []string,
	readLimit int64,
	compressionEnabled bool,
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

	dialOpts := &websocket.DialOptions{
		HTTPHeader:   dialHeaders,
		Subprotocols: subprotocols,
	}
	if compressionEnabled {
		dialOpts.CompressionMode = websocket.CompressionNoContextTakeover
	}
	conn, resp, err := websocket.Dial(ctx, wsURL.String(), dialOpts)
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
	ch := make(chan wsFrame, 64)
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
