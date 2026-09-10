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
	"sync"
	"time"

	"github.com/coder/websocket"
)

// codexCyberSwapOptions configures the cyber-aware Codex websocket relay.
type codexCyberSwapOptions struct {
	ReqID                       string
	RequestPath                 string
	Provider                    Provider
	InitialAccount              *Account
	InitialContextAccount       *Account
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
	termination  webSocketTermination
	swapped      bool
	finalAccount *Account
}

// swapPendingErr is returned from the upstream pump on a cyber_policy
// hit. next is the swap target, or nil when no cyber_access candidate
// was available; frame is the original upstream payload, forwarded to
// the client when the swap is skipped or fails so the user sees the
// real upstream error instead of a fabricated message.
type swapPendingErr struct {
	next           *Account
	frame          []byte
	conversationID string
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
		if upstreamResp != nil {
			status := writeWebSocketRejection(w, upstreamResp)
			return codexCyberSwapResult{statusCode: status, finalAccount: opts.InitialAccount}
		}
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
	registry := h.webSocketRegistry()
	session := registry.register(clientConn)
	defer registry.unregister(session)

	log.Printf("[ws-relay %s] connected to %s, relaying messages (codex cyber-aware)", opts.LogLabel, opts.InitialOutURL.Host)

	// Long-lived relay context. The reader goroutines bind to this so
	// they survive across swap rounds; per-round writers/inspectors are
	// gated by a per-round context derived from it.
	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()

	state := &codexRelayState{
		h:                    h,
		opts:                 opts,
		ctx:                  relayCtx,
		clientConn:           clientConn,
		clientWriter:         &webSocketWriter{conn: clientConn},
		upstreamConn:         upstreamConn,
		activeAccount:        opts.InitialAccount,
		contextAccount:       opts.InitialContextAccount,
		subprotocols:         subprotocols,
		clientCh:             startWebSocketReader(relayCtx, clientConn),
		upstreamCh:           startWebSocketReader(relayCtx, upstreamConn),
		session:              session,
		activeConversationID: opts.ConversationID,
		// Already on a cyber account — no further swap is meaningful.
		swapDone: opts.InitialAccount.CyberAccess,
	}
	defer state.closeAll()

	statusCode, relayErr := state.run()
	termination := normalizeCompletedWebSocketTermination(classifyWebSocketTermination(relayErr), session)
	state.closePeer(termination)
	return state.result(statusCode, relayErr, termination)
}

type codexRelayTurn struct {
	request        []byte
	model          string
	conversationID string
	account        *Account
	responseID     string
}

type codexRelayState struct {
	// Both pumps transition turns under this lock; response IDs bind to the
	// request snapshot, never to the most recently received client frame.
	turnMu sync.Mutex
	turns  []*codexRelayTurn
	h      *proxyHandler
	opts   codexCyberSwapOptions
	ctx    context.Context

	clientConn     *websocket.Conn
	clientWriter   *webSocketWriter
	upstreamConn   *websocket.Conn
	activeAccount  *Account
	contextAccount *Account
	subprotocols   []string

	clientCh   <-chan wsFrame
	upstreamCh <-chan wsFrame
	session    *trackedWebSocketSession

	// swapDone covers both "we already swapped" and "we tried and gave
	// up" — once true, no further swap attempts.
	swapDone bool

	activeConversationID string
	recordedResponses    map[string]struct{}
	clientClosing        bool
	upstreamClosing      bool
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
					if isContextError(doErr) {
						if err := s.writeContextError(doErr); err != nil {
							return http.StatusSwitchingProtocols, err
						}
						continue
					}
					if len(swap.frame) == 0 {
						return 101, doErr
					}
					log.Printf("[%s] account swap dial failed: %v; forwarding upstream cyber_policy frame", s.opts.ReqID, doErr)
					s.forwardCyberPolicy(swap.frame)
					s.legacyPin(swap.conversationID)
					return 101, nil
				}
				continue
			}
			// No swap target — surface the upstream's real cyber_policy
			// frame and end the relay cleanly.
			s.forwardCyberPolicy(swap.frame)
			s.legacyPin(swap.conversationID)
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

	clientHeartbeatErr, stopClientHeartbeat := startWebSocketHeartbeat(roundCtx, s.clientWriter, s.opts.DownstreamHeartbeatInterval, "client")
	defer stopClientHeartbeat()
	upstreamHeartbeatErr, stopUpstreamHeartbeat := startWebSocketHeartbeat(roundCtx, upstreamWriter, s.opts.DownstreamHeartbeatInterval, "upstream")
	defer stopUpstreamHeartbeat()

	upstreamErrCh := make(chan error, 1)
	clientErrCh := make(chan error, 1)
	activityCh := make(chan struct{}, 1)

	debug := s.h != nil && s.h.cfg != nil && s.h.cfg.debug.Load()
	go func() {
		upstreamErrCh <- pumpFrames(roundCtx, s.upstreamCh, s.clientWriter, s.opts.LogLabel, "upstream->client", debug, s.inspectUpstream, s.markUpstreamForwarded, activityCh)
	}()
	go func() {
		clientErrCh <- pumpFrames(roundCtx, s.clientCh, upstreamWriter, s.opts.LogLabel, "client->upstream", debug, s.inspectClient, s.markClientForwarded, activityCh)
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
		case err := <-clientHeartbeatErr:
			roundCancel()
			<-upstreamErrCh
			<-clientErrCh
			return err
		case err := <-upstreamHeartbeatErr:
			roundCancel()
			<-upstreamErrCh
			<-clientErrCh
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
	afterForward func([]byte),
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
			if inspect != nil {
				rewritten, err := inspect(data)
				if err != nil {
					return err
				}
				if rewritten != nil {
					if len(rewritten) == 0 {
						continue
					}
					data = rewritten
				}
			}
			if debug {
				logRelayFrame(logLabel, label, frame.msgType, data)
			}
			if err := dst.Write(ctx, frame.msgType, data); err != nil {
				return fmt.Errorf("%s write: %w", label, err)
			}
			if afterForward != nil {
				afterForward(data)
			}
		}
	}
}

func (s *codexRelayState) markClientForwarded(data []byte) {
	s.turnMu.Lock()
	defer s.turnMu.Unlock()
	if s.session != nil && isCodexResponseCreate(data) {
		s.session.setActive(len(s.turns) != 0)
	}
}

func (s *codexRelayState) markUpstreamForwarded(data []byte) {
	s.turnMu.Lock()
	defer s.turnMu.Unlock()
	if s.session != nil && isTerminalCodexWebSocketEvent(data) {
		s.session.setActive(len(s.turns) != 0)
	}
}

func isTerminalCodexWebSocketEvent(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	var event struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &event) != nil {
		return false
	}
	return event.Type == "response.completed" || event.Type == "response.failed" || event.Type == "response.incomplete"
}

func (s *codexRelayState) inspectUpstream(data []byte) ([]byte, error) {
	s.turnMu.Lock()
	defer s.turnMu.Unlock()
	turn := s.responseTurn(data)
	s.recordCompletedUsage(data, turn)
	filtered, drop, changed := filterHostedMCPResponseJSON(data)
	if drop {
		return []byte{}, nil
	}
	if changed {
		data = filtered
	}
	if !isCyberPolicyError(data) {
		if isTerminalCodexWebSocketEvent(data) {
			s.finishTurn(turn)
		}
		return data, nil
	}
	log.Printf("[%s] cyber_policy frame from account %s", s.opts.ReqID, s.activeAccount.ID)
	if s.h != nil && s.h.metrics != nil {
		s.h.metrics.incCyberPolicy(s.activeAccount.ID, "suppressed_ws")
	}
	if turn == nil && len(s.turns) == 1 {
		turn = s.turns[0]
	}
	conversationID := ""
	if turn != nil {
		conversationID = turn.conversationID
	}
	// A swap cannot move other outstanding response chains to a new account.
	if !s.swapDone && len(s.turns) == 1 && turn == s.turns[0] {
		if cand := s.pickCyberAccessCandidate(); cand != nil {
			s.swapDone = true
			return data, &swapPendingErr{next: cand, frame: data, conversationID: conversationID}
		}
	}
	s.swapDone = true
	if s.h != nil && s.h.metrics != nil {
		s.h.metrics.incCyberPolicy(s.activeAccount.ID, "swap_no_candidate")
	}
	return data, &swapPendingErr{frame: data, conversationID: conversationID}
}

func (s *codexRelayState) contextEnabled() bool {
	return isCodexResponsesPath(s.opts.RequestPath)
}

func (s *codexRelayState) writeContextError(err error) error {
	if s.clientWriter == nil {
		return nil
	}
	return s.clientWriter.Write(s.ctx, websocket.MessageText, contextErrorBody(err))
}

func (s *codexRelayState) inspectClient(data []byte) ([]byte, error) {
	s.turnMu.Lock()
	defer s.turnMu.Unlock()
	if !isCodexResponseCreate(data) {
		return data, nil
	}

	data = applyModelAliasToJSONFrame(s.h, s.opts.ReqID, data)
	filtered, changed, err := filterHostedMCPRequestJSON(data)
	if err != nil {
		return nil, err
	}
	if changed {
		data = filtered
	}
	conversationID := extractConversationIDFromJSON(data)
	if conversationID == "" {
		conversationID = s.activeConversationID
	}
	model := extractCodexWebSocketRequestedModel(data)
	turn := &codexRelayTurn{request: append([]byte(nil), data...), model: model, conversationID: conversationID, account: s.activeAccount}
	s.turns = append(s.turns, turn)
	if s.h != nil && s.h.pool != nil && s.h.pool.discoveredModelRequiresEntitlement(AccountTypeCodex, model) && !accountSupportsDiscoveredModel(s.activeAccount, model) {
		if len(s.turns) > 1 {
			s.finishTurn(turn)
			return nil, fmt.Errorf("cannot change websocket account while responses are pending")
		}
		exclude := map[string]bool{s.activeAccount.ID: true}
		next := s.h.pool.candidateForModel(conversationID, exclude, AccountTypeCodex, s.opts.RequiredPlan, s.opts.ClientIP, model)
		if next == nil {
			s.finishTurn(turn)
			return nil, fmt.Errorf("no Codex account is entitled to websocket model %q", model)
		}
		return nil, &swapPendingErr{next: next}
	}
	if modelRequiresHTTPProviderRoute(model) {
		s.finishTurn(turn)
		payload, _ := json.Marshal(map[string]any{
			"type":   "error",
			"status": 400,
			"error": map[string]any{
				"type": "invalid_request_error",
				"message": fmt.Sprintf(
					"model %q is not supported on the Codex Responses WebSocket; use HTTP POST /responses so the pool can route it",
					model,
				),
			},
		})
		if s.clientWriter != nil {
			_ = s.clientWriter.Write(s.ctx, websocket.MessageText, payload)
		}
		log.Printf("[%s] rejecting websocket model %q (HTTP model-route only)", s.opts.ReqID, model)
		return nil, fmt.Errorf("websocket model route rejected: %s", model)
	}
	if s.contextEnabled() {
		data, err = s.h.prepareContextFrame(s.opts.UserID, s.opts.ClientIP, data, s.contextAccount)
		if err != nil {
			s.finishTurn(turn)
			return []byte{}, s.writeContextError(err)
		}
	}
	if s.activeAccount != nil {
		s.swapDone = s.activeAccount.CyberAccess
	}

	if conversationID == "" {
		return data, nil
	}
	s.activeConversationID = conversationID
	if s.h == nil || s.h.pool == nil || s.activeAccount == nil {
		return data, nil
	}

	// Response IDs are scoped to the upstream account that minted them. A
	// downstream websocket may carry multiple logical conversations, but every
	// one of those conversations must remain on this socket's active account so
	// previous_response_id continues to resolve.
	s.h.pool.pin(conversationID, s.activeAccount.ID)
	return data, nil
}

// responseTurn binds server-assigned IDs in acceptance order. Subsequent
// events may complete out of order without changing request attribution.
// The caller holds turnMu.
func (s *codexRelayState) responseTurn(data []byte) *codexRelayTurn {
	var event struct {
		Type       string `json:"type"`
		ResponseID string `json:"response_id"`
		Response   struct {
			ID string `json:"id"`
		} `json:"response"`
	}
	if json.Unmarshal(data, &event) != nil {
		return nil
	}
	id := event.Response.ID
	if id == "" {
		id = event.ResponseID
	}
	if id != "" {
		for _, turn := range s.turns {
			if turn.responseID == id {
				return turn
			}
		}
		if _, recorded := s.recordedResponses[id]; recorded {
			return nil
		}
	}
	if event.Type != "response.created" && !isTerminalCodexWebSocketEvent(data) {
		return nil
	}
	for _, turn := range s.turns {
		if turn.responseID == "" {
			turn.responseID = id
			return turn
		}
	}
	return nil
}

func (s *codexRelayState) finishTurn(done *codexRelayTurn) {
	for i, turn := range s.turns {
		if turn == done {
			if turn.responseID != "" {
				if s.recordedResponses == nil {
					s.recordedResponses = make(map[string]struct{})
				}
				s.recordedResponses[turn.responseID] = struct{}{}
			}
			copy(s.turns[i:], s.turns[i+1:])
			s.turns[len(s.turns)-1] = nil
			s.turns = s.turns[:len(s.turns)-1]
			return
		}
	}
}

// recordCompletedUsage sends terminal Codex websocket usage through the same
// accounting path as HTTP/SSE, using the originating request snapshot.
// The caller holds turnMu.
func (s *codexRelayState) recordCompletedUsage(data []byte, turn *codexRelayTurn) {
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
	if turn != nil {
		account = turn.account
	}
	ru.AccountID = account.ID
	ru.AccountType = account.Type
	ru.UserID = s.opts.UserID
	ru.OriginID = s.opts.OriginID
	account.mu.Lock()
	ru.PlanType = account.PlanType
	account.mu.Unlock()
	if ru.Model == "" && turn != nil {
		ru.Model = turn.model
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
	s.turnMu.Lock()
	defer s.turnMu.Unlock()
	// A client frame may arrive while the other pump is stopping. Never
	// replay that later turn in place of the one that triggered the swap.
	if len(s.turns) != 1 {
		return fmt.Errorf("cannot swap websocket account with %d pending responses", len(s.turns))
	}
	turn := s.turns[0]
	s.activeConversationID = turn.conversationID
	newConn, newResp, authAccount, err := s.h.dialSwappedUpstream(s.ctx, s.opts, cand, s.subprotocols)
	if err != nil {
		if newResp != nil {
			if newResp.Body != nil {
				newResp.Body.Close()
			}
			s.h.applyWebSocketStatusEffects(s.opts.ReqID, cand, "", false, false, newResp.StatusCode)
		}
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
	replay := stripPreviousResponseID(turn.request)
	if s.contextEnabled() {
		replay, err = s.h.prepareContextFrame(s.opts.UserID, s.opts.ClientIP, replay, authAccount)
		if err != nil {
			newConn.CloseNow()
			s.finishTurn(turn)
			return err
		}
	}
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
	if s.activeConversationID != "" {
		s.h.pool.pin(s.activeConversationID, cand.ID)
	}

	s.upstreamConn.CloseNow()
	s.upstreamConn = newConn
	s.upstreamCh = startWebSocketReader(s.ctx, newConn)
	s.activeAccount = cand
	s.contextAccount = authAccount
	turn.account = cand
	turn.responseID = ""
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

func (s *codexRelayState) legacyPin(conversationID string) {
	if conversationID == "" {
		return
	}
	s.h.pinConversationToCyberAccess(conversationID, AccountTypeCodex, s.opts.RequiredPlan, s.opts.ClientIP, s.activeAccount.ID, s.opts.ReqID)
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
	if !s.clientClosing {
		s.clientConn.CloseNow()
	}
	if !s.upstreamClosing {
		s.upstreamConn.CloseNow()
	}
}

func (s *codexRelayState) closePeer(term webSocketTermination) {
	code, reason := term.wireCloseCode(), term.wireReason()
	switch term.Side {
	case "upstream":
		s.upstreamConn.CloseNow()
		s.upstreamClosing = true
		s.clientClosing = true
		beginWebSocketClose(s.clientConn, code, reason)
	case "client":
		s.clientConn.CloseNow()
		s.clientClosing = true
		s.upstreamClosing = true
		beginWebSocketClose(s.upstreamConn, code, reason)
	default:
		s.clientClosing = true
		s.upstreamClosing = true
		beginWebSocketClose(s.clientConn, code, reason)
		beginWebSocketClose(s.upstreamConn, code, reason)
	}
}

func (s *codexRelayState) result(statusCode int, relayErr error, termination webSocketTermination) codexCyberSwapResult {
	// swapped reflects whether the active upstream actually changed.
	// run() always returns nil error on the cyber_policy passthrough
	// path, so caller bookkeeping (cyberPinned -> skip pin) sees an
	// honest swapped=false there.
	swapped := s.activeAccount != s.opts.InitialAccount
	if relayErr != nil && !termination.accountFailure() {
		relayErr = nil
	}
	return codexCyberSwapResult{statusCode: statusCode, err: relayErr, termination: termination, swapped: swapped, finalAccount: s.activeAccount}
}

func (h *proxyHandler) dialSwappedUpstream(
	ctx context.Context,
	opts codexCyberSwapOptions,
	acc *Account,
	subprotocols []string,
) (*websocket.Conn, *http.Response, *Account, error) {
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
		return nil, nil, nil, fmt.Errorf("swap account %s has empty access token", acc.ID)
	}

	headers := cloneHeader(opts.InitialUpstreamHeaders)
	headers.Del("Authorization")
	headers.Del("ChatGPT-Account-ID")
	headers.Del("X-Api-Key")
	headers.Del("x-goog-api-key")
	tmpReq := &http.Request{Header: headers}
	authAccount := contextAuthSnapshot(acc)
	opts.Provider.SetAuthHeaders(tmpReq, authAccount)

	conn, resp, _, err := dialUpstreamWebSocketWithSubprotocols(ctx, opts.InitialOutURL, tmpReq.Header, subprotocols, opts.ReadLimit, opts.CompressionEnabled)
	if err != nil {
		return nil, resp, nil, err
	}
	return conn, resp, authAccount, nil
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
		return nil, resp, subprotocols, fmt.Errorf("dial upstream WS %s: %w", wsURL.Host, err)
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
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return false
	}
	if !bytes.Contains(data, []byte(`"response.create"`)) && !bytes.Contains(data, []byte(`\`)) {
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

// extractCodexWebSocketRequestedModel reads model from either the flat HTTP
// Responses shape or the nested Codex websocket response.create envelope.
func extractCodexWebSocketRequestedModel(data []byte) string {
	if model := extractRequestedModelFromJSON(data); model != "" {
		return model
	}
	var nested struct {
		Response struct {
			Model string `json:"model"`
		} `json:"response"`
	}
	if err := json.Unmarshal(data, &nested); err != nil {
		return ""
	}
	return strings.TrimSpace(nested.Response.Model)
}

// modelRequiresHTTPProviderRoute reports models that the HTTP proxy would
// divert away from ChatGPT/Codex via modelRouteOverride. The Codex websocket
// tunnel is dialed before the body arrives, so these must not be forwarded.
func modelRequiresHTTPProviderRoute(model string) bool {
	model = strings.TrimSpace(model)
	if model == "" {
		return false
	}
	return isGrokModel(model) ||
		isKimiModel(model) ||
		isMinimaxModel(model) ||
		isZAIModel(model) ||
		isXiaomiModel(model) ||
		isAdverserialModel(model)
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
	_, changed := obj["previous_response_id"]
	delete(obj, "previous_response_id")
	if response, ok := obj["response"].(map[string]any); ok {
		if _, exists := response["previous_response_id"]; exists {
			delete(response, "previous_response_id")
			changed = true
		}
	}
	if !changed {
		return data
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return data
	}
	return out
}

// writeWebSocketRejection owns only failed handshake bodies. Successful
// upgrades belong to websocket.Conn and must not be closed here.
func writeWebSocketRejection(w http.ResponseWriter, resp *http.Response) int {
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	status := resp.StatusCode
	if status < http.StatusBadRequest || status > 599 {
		status = http.StatusBadGateway
	}
	if retry := resp.Header.Get("Retry-After"); retry != "" {
		w.Header().Set("Retry-After", retry)
	}
	http.Error(w, http.StatusText(status), status)
	return status
}
