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
	"sync/atomic"
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
	Model                       string
	ServiceTier                 string
	RequiredPlan                string
	ClientIP                    string
	UserID                      string
	OriginID                    string
	IdleTimeout                 time.Duration
	FirstByteTimeout            time.Duration
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

type overloadPendingErr struct {
	turn  *codexRelayTurn
	count int
}

type transportPendingErr struct {
	turn *codexRelayTurn
	err  error
}

func (e *swapPendingErr) Error() string {
	if e == nil || e.next == nil {
		return "cyber swap pending"
	}
	return "cyber swap pending: " + e.next.ID
}

func (e *overloadPendingErr) Error() string {
	if e == nil || e.turn == nil {
		return "overload retry pending"
	}
	return fmt.Sprintf("overload retry pending for %s (%d)", e.turn.model, e.count)
}

func (e *transportPendingErr) Error() string {
	if e == nil || e.turn == nil {
		return "transport retry pending"
	}
	return fmt.Sprintf("transport retry pending for %s: %v", e.turn.model, e.err)
}

func (e *transportPendingErr) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
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

	dialCtx, disarmDial := beginFirstByteDeadline(ctx, opts.FirstByteTimeout)
	upstreamConn, upstreamResp, subprotocols, err := dialUpstreamWebSocket(dialCtx, opts.InitialOutURL, opts.InitialUpstreamHeaders, clientReq.Header, opts.ReadLimit, opts.CompressionEnabled)
	if disarmDial() || errors.Is(err, errUpstreamFirstByteTimeout) || errors.Is(context.Cause(dialCtx), errUpstreamFirstByteTimeout) {
		if upstreamConn != nil {
			upstreamConn.CloseNow()
		}
		if upstreamResp != nil && upstreamResp.Body != nil {
			upstreamResp.Body.Close()
		}
		writeUpstreamFirstByteTimeout(w)
		return codexCyberSwapResult{statusCode: http.StatusGatewayTimeout, err: errUpstreamFirstByteTimeout, finalAccount: opts.InitialAccount}
	}
	excluded := map[string]bool{opts.InitialAccount.ID: true}
	for attempt := 0; err != nil && upstreamResp != nil && upstreamResp.StatusCode == http.StatusUnauthorized; attempt++ {
		if upstreamTokenRevoked(upstreamResp) {
			persistDeadAccount(opts.InitialAccount, "upstream token revoked")
		}
		if h.retryPoolAuth(ctx, opts.InitialAccount) {
			_ = upstreamResp.Body.Close()
			upstreamConn, upstreamResp, opts.InitialContextAccount, err = h.dialSwappedUpstream(ctx, opts, opts.InitialAccount, subprotocols)
			if err == nil || upstreamResp == nil || upstreamResp.StatusCode != http.StatusUnauthorized {
				break
			}
		}
		h.applyWebSocketStatusEffects(opts.ReqID, opts.InitialAccount, "", false, false, http.StatusUnauthorized)
		if attempt+1 >= h.cfg.maxAttempts {
			break
		}
		next := h.pool.candidateForTier(opts.ConversationID, excluded, AccountTypeCodex, opts.RequiredPlan, opts.ClientIP, opts.Model, opts.ServiceTier)
		if next == nil {
			break
		}
		_ = upstreamResp.Body.Close()
		excluded[next.ID] = true
		opts.InitialAccount = next
		if opts.SetActiveAccount != nil {
			opts.SetActiveAccount(next)
		}
		upstreamConn, upstreamResp, opts.InitialContextAccount, err = h.dialSwappedUpstream(ctx, opts, next, subprotocols)
	}
	if errors.Is(err, errUpstreamFirstByteTimeout) {
		if upstreamConn != nil {
			upstreamConn.CloseNow()
		}
		if upstreamResp != nil && upstreamResp.Body != nil {
			upstreamResp.Body.Close()
		}
		writeUpstreamFirstByteTimeout(w)
		return codexCyberSwapResult{statusCode: http.StatusGatewayTimeout, err: errUpstreamFirstByteTimeout, finalAccount: opts.InitialAccount}
	}
	if err != nil {
		if upstreamResp != nil && upstreamResp.StatusCode == http.StatusUnauthorized {
			_ = upstreamResp.Body.Close()
			log.Printf("[%s] upstream authentication unavailable: account=%s path=websocket", opts.ReqID, opts.InitialAccount.ID)
			writeUpstreamAuthError(w)
			return codexCyberSwapResult{statusCode: http.StatusServiceUnavailable, finalAccount: opts.InitialAccount}
		}
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
		// The downstream handshake carries this account's blob; remember the
		// minter so a later redial to another account drops the echo.
		h.noteCodexTurnState(opts.UserID, opts.ConversationID, opts.InitialAccount, turnState)
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
		activityCh:           make(chan struct{}, 1),
		activeConversationID: opts.ConversationID,
		// Already on a cyber account — no further swap is meaningful.
		swapDone:         opts.InitialAccount.CyberAccess,
		overloadTimes:    make(map[string][]time.Time),
		bootstrapEnabled: true,
	}
	defer state.closeAll()
	if state.contextEnabled() {
		state.proWS = newChatGPTProWS(relayCtx, clientReq, h.handleChatGPTPro, func(ctx context.Context, data []byte) error {
			if err := state.clientWriter.Write(ctx, websocket.MessageText, data); err != nil {
				return err
			}
			select {
			case state.activityCh <- struct{}{}:
			default:
			}
			return nil
		}, opts.ReadLimit, func() {
			state.turnMu.Lock()
			defer state.turnMu.Unlock()
			state.session.setActive(state.turnsActive())
		})
		defer state.proWS.Close()
	}

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
	outputStarted  bool

	// inputItems is the turn's normalized input sequence; hasPrevID records
	// whether the client anchored this turn to a prior response. The replay
	// collector mines the assistant's tool calls and messages from the
	// upstream frames so a redial can rebuild the full transcript.
	inputItems  []json.RawMessage
	hasPrevID   bool
	collector   codexToolReplayCollector
	completedOK bool
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

	clientCh            <-chan wsFrame
	upstreamCh          <-chan wsFrame
	upstreamResponseCh  chan struct{}
	sawUpstreamResponse atomic.Bool
	session             *trackedWebSocketSession
	proWS               *chatGPTProWS
	activityCh          chan struct{}

	// swapDone covers both "we already swapped" and "we tried and gave
	// up" — once true, no further swap attempts.
	swapDone         bool
	overloadTimes    map[string][]time.Time
	overloadRecovery int
	bootstrap        [][]byte
	bootstrapBytes   int
	bootstrapReady   bool
	bootstrapEnabled bool

	activeConversationID string
	recordedResponses    map[string]struct{}
	clientClosing        bool
	upstreamClosing      bool

	// history keys each conversation's full input transcript by conversation
	// id. A redial rebuilds the conversation from it instead of the dead
	// response id; a fresh turn (no previous_response_id) resets its key.
	// historyIncomplete marks a key whose transcript was truncated and must
	// not be replayed as if it were complete.
	history           map[string][]json.RawMessage
	historyIncomplete map[string]bool
}

func (s *codexRelayState) run() (int, error) {
	for {
		err := s.relayOnce()
		if err == nil {
			return 101, nil
		}
		var transport *transportPendingErr
		if errors.As(err, &transport) {
			if retryErr := s.retryTransportTurn(transport); retryErr != nil {
				if status, done := s.surfaceRelayErr(retryErr); done {
					return status, retryErr
				}
				return 101, retryErr
			}
			continue
		}
		var overload *overloadPendingErr
		if errors.As(err, &overload) {
			if retryErr := s.retryOverloadedTurn(overload); retryErr != nil {
				if status, done := s.surfaceRelayErr(retryErr); done {
					return status, retryErr
				}
				return 101, retryErr
			}
			continue
		}
		if status, done := s.surfaceRelayErr(err); done {
			return status, err
		}
		var swap *swapPendingErr
		if errors.As(err, &swap) {
			if swap.next != nil {
				if doErr := s.doSwap(swap.next); doErr != nil {
					if status, done := s.surfaceRelayErr(doErr); done {
						return status, doErr
					}
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
	activityCh := s.activityCh
	if activityCh == nil {
		activityCh = make(chan struct{}, 1)
	}

	if s.upstreamResponseCh == nil {
		s.upstreamResponseCh = make(chan struct{}, 1)
	}
	s.sawUpstreamResponse.Store(false)
	select {
	case <-s.upstreamResponseCh:
	default:
	}
	debug := s.h != nil && s.h.cfg != nil && s.h.cfg.debug.Load()
	go func() {
		upstreamErrCh <- pumpFrames(roundCtx, s.ctx, s.upstreamCh, s.clientWriter, s.opts.LogLabel, "upstream->client", debug, s.inspectUpstream, s.flushBootstrap, s.markUpstreamForwarded, activityCh)
	}()
	go func() {
		clientErrCh <- pumpFrames(roundCtx, s.ctx, s.clientCh, upstreamWriter, s.opts.LogLabel, "client->upstream", debug, s.inspectClient, nil, s.markClientForwarded, activityCh)
	}()

	var idleTimer *time.Timer
	var idleCh <-chan time.Time
	if s.opts.IdleTimeout > 0 {
		idleTimer = time.NewTimer(s.opts.IdleTimeout)
		idleCh = idleTimer.C
		defer idleTimer.Stop()
	}
	var firstTimer *time.Timer
	var firstCh <-chan time.Time
	if s.opts.FirstByteTimeout > 0 {
		firstTimer = time.NewTimer(s.opts.FirstByteTimeout)
		firstCh = firstTimer.C
		defer firstTimer.Stop()
	}
	for {
		select {
		case err := <-upstreamErrCh:
			roundCancel()
			<-clientErrCh
			if pending := s.transportRetry(err); pending != nil {
				return pending
			}
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
		case <-s.upstreamResponseCh:
			if firstTimer != nil {
				firstTimer.Stop()
				firstTimer = nil
				firstCh = nil
			}
		case <-firstCh:
			if s.sawUpstreamResponse.Load() {
				firstTimer = nil
				firstCh = nil
				continue
			}
			roundCancel()
			<-upstreamErrCh
			<-clientErrCh
			return errUpstreamFirstByteTimeout
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
	ctx, writeCtx context.Context,
	src <-chan wsFrame,
	dst *webSocketWriter,
	logLabel, label string,
	debug bool,
	inspect func([]byte) ([]byte, error),
	flush func() [][]byte,
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
					data = rewritten
				}
			}
			batch := [][]byte{data}
			if flush != nil {
				if buffered := flush(); len(buffered) > 0 {
					batch = buffered
				}
			}
			if len(data) == 0 && len(batch) == 1 && len(batch[0]) == 0 {
				continue
			}
			for _, output := range batch {
				if len(output) == 0 {
					continue
				}
				if debug {
					logRelayFrame(logLabel, label, frame.msgType, output)
				}
				// Cancelling a coder/websocket write closes its socket. Round
				// cancellation must not destroy connections retained after a swap.
				if err := dst.Write(writeCtx, frame.msgType, output); err != nil {
					return fmt.Errorf("%s write: %w", label, err)
				}
				if afterForward != nil {
					afterForward(output)
				}
			}
		}
	}
}

func (s *codexRelayState) turnsActive() bool {
	return len(s.turns) != 0 || s.proWS != nil && s.proWS.Active()
}

func (s *codexRelayState) markClientForwarded(data []byte) {
	s.turnMu.Lock()
	defer s.turnMu.Unlock()
	if s.session != nil && isCodexResponseCreate(data) {
		s.session.setActive(s.turnsActive())
	}
}

func (s *codexRelayState) markUpstreamForwarded(data []byte) {
	s.turnMu.Lock()
	defer s.turnMu.Unlock()
	if s.session != nil && isTerminalCodexWebSocketEvent(data) {
		s.session.setActive(s.turnsActive())
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
	return event.Type == "response.completed" || event.Type == "response.done" || event.Type == "response.failed" || event.Type == "response.incomplete"
}

func (s *codexRelayState) noteUpstreamResponse() {
	if s == nil {
		return
	}
	s.sawUpstreamResponse.Store(true)
	if s.upstreamResponseCh == nil {
		return
	}
	select {
	case s.upstreamResponseCh <- struct{}{}:
	default:
	}
}

func (s *codexRelayState) inspectUpstream(data []byte) ([]byte, error) {
	s.noteUpstreamResponse()
	s.turnMu.Lock()
	defer s.turnMu.Unlock()
	turn := s.responseTurn(data)
	if turn != nil {
		turn.collector.AddEvent(codexEventType(data), data)
	}
	s.recordCompletedUsage(data, turn)
	filtered, drop, changed := filterHostedMCPResponseJSON(data)
	if drop {
		return []byte{}, nil
	}
	if changed {
		data = filtered
	}
	if turn != nil && isCodexMeaningfulOutput(data) {
		turn.outputStarted = true
	}
	if isServerOverloadedError(data) {
		turn := s.responseTurn(data)
		if turn == nil && len(s.turns) == 1 {
			turn = s.turns[0]
		}
		if turn != nil {
			return []byte{}, &overloadPendingErr{turn: turn, count: s.recordOverload(s.activeAccount)}
		}
	}
	if !isCyberPolicyError(data) {
		if s.bootstrapEnabled && turn != nil && len(s.turns) == 1 && !s.bootstrapReady {
			s.bufferBootstrap(data, turn)
			if isTerminalCodexWebSocketEvent(data) {
				s.markTurnCompleted(turn, data)
				s.finishTurn(turn)
			}
			return []byte{}, nil
		}
		if isTerminalCodexWebSocketEvent(data) {
			s.markTurnCompleted(turn, data)
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

	model := ""
	if s.h != nil {
		model = s.h.modelRedirects.modelFor(s.opts.ClientIP)
	}
	if model != "" {
		var err error
		data, err = redirectWSModel(data, model)
		if err != nil {
			return nil, err
		}
	} else {
		data = applyModelAliasToJSONFrame(s.h, s.opts.ReqID, data)
	}
	if s.h != nil {
		if tier := s.h.serviceTierOverride.modelFor(s.opts.ClientIP); tier != "" {
			var err error
			data, err = forceServiceTier(data, tier)
			if err != nil {
				return nil, err
			}
		}
	}
	data = applyEffortCapToJSONFrame(s.h, s.opts.ReqID, s.opts.UserID, s.opts.ClientIP, data)
	filtered, changed, err := filterHostedMCPRequestJSON(data)
	if err != nil {
		return nil, err
	}
	if changed {
		data = filtered
	}
	if s.contextEnabled() && s.proWS != nil {
		handled, err := s.proWS.Handle(data)
		if handled {
			if s.session != nil {
				s.session.setActive(s.turnsActive())
			}
			return []byte{}, err
		}
	}
	conversationID := extractConversationIDFromJSON(data)
	if conversationID == "" {
		conversationID = s.activeConversationID
	}
	model = extractCodexWebSocketRequestedModel(data)
	turn := &codexRelayTurn{
		request:        append([]byte(nil), data...),
		model:          model,
		conversationID: conversationID,
		account:        s.activeAccount,
		inputItems:     extractInputItems(data),
		hasPrevID:      hasPreviousResponseID(data),
	}
	s.turns = append(s.turns, turn)
	tier := serviceTierFromJSON(data)
	if s.h != nil && s.h.pool != nil && ((s.h.pool.discoveredModelRequiresEntitlement(AccountTypeCodex, model) && !accountSupportsDiscoveredModel(s.activeAccount, model)) || !accountSupportsTier(s.activeAccount, model, tier)) {
		if len(s.turns) > 1 {
			s.finishTurn(turn)
			return nil, fmt.Errorf("cannot change websocket account while responses are pending")
		}
		exclude := map[string]bool{s.activeAccount.ID: true}
		next := s.h.pool.candidateForTier(conversationID, exclude, AccountTypeCodex, s.opts.RequiredPlan, s.opts.ClientIP, model, tier)
		if next == nil {
			s.finishTurn(turn)
			if tierNeedsDiscovery(tier) && s.clientWriter != nil {
				payload, _ := json.Marshal(map[string]any{
					"type": "error", "status": http.StatusServiceUnavailable,
					"error": map[string]any{
						"type": "server_error", "code": "service_tier_unavailable",
						"message": fmt.Sprintf("Service tier %q unavailable for %q. Choose another tier or retry.", tier, model),
					},
				})
				_ = s.clientWriter.Write(s.ctx, websocket.MessageText, payload)
			}
			return nil, fmt.Errorf("no Codex account is entitled to websocket model %q with service tier %q", model, tier)
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
			if turn.completedOK {
				s.recordHistory(turn)
			}
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

// markTurnCompleted records whether a terminal upstream event closed the turn
// successfully. Only completed turns fold into the conversation history; a
// failed or incomplete turn contributes nothing the next delta can build on.
func (s *codexRelayState) markTurnCompleted(turn *codexRelayTurn, data []byte) {
	if turn == nil {
		return
	}
	switch codexEventType(data) {
	case "response.completed", "response.done":
		turn.completedOK = true
	}
}

// recordHistory folds a completed turn into the conversation transcript. The
// turn's own input is appended to the accumulated history (or replaces it when
// the client started a fresh chain), then the assistant's mined output items
// follow. The caller holds turnMu.
func (s *codexRelayState) recordHistory(done *codexRelayTurn) {
	if done == nil {
		return
	}
	key := replayHistoryKey(done.conversationID)
	if done.hasPrevID && s.historyIncomplete[key] {
		return
	}
	var combined []json.RawMessage
	if done.hasPrevID {
		fullInput := buildReplaySequence(s.historyFor(done.conversationID), done.inputItems, true)
		combined = combineInputItems(fullInput, done.collector.AllItems())
	} else {
		// A fresh chain replaces whatever that conversation held before.
		combined = combineInputItems(done.inputItems, done.collector.AllItems())
	}
	capped, truncated := capHistory(combined)
	if truncated {
		// A partial tail is not a full transcript. Forget it so the next
		// redial asks the client to resend instead of succeeding without
		// the dropped context.
		s.setHistory(key, nil)
		if key != "" {
			if s.historyIncomplete == nil {
				s.historyIncomplete = map[string]bool{}
			}
			s.historyIncomplete[key] = true
		}
		return
	}
	if s.historyIncomplete != nil {
		delete(s.historyIncomplete, key)
	}
	s.setHistory(key, capped)
}

func replayHistoryKey(conversationID string) string {
	if strings.TrimSpace(conversationID) == "" {
		return ""
	}
	return conversationID
}

func (s *codexRelayState) setHistory(key string, items []json.RawMessage) {
	if s.history == nil {
		s.history = map[string][]json.RawMessage{}
	}
	if len(items) == 0 {
		delete(s.history, key)
		return
	}
	s.history[key] = items
}

func (s *codexRelayState) historyFor(conversationID string) []json.RawMessage {
	key := replayHistoryKey(conversationID)
	if s.historyIncomplete[key] {
		return nil
	}
	if s.history == nil {
		return nil
	}
	return s.history[key]
}

// surfaceRelayErr writes the client-visible frame for a terminal relay
// failure. It reports done when the caller should stop instead of treating
// the error as a generic swap or close. The write is bounded so a stalled
// client cannot pin the relay.
func (s *codexRelayState) surfaceRelayErr(err error) (int, bool) {
	switch {
	case errors.Is(err, errUpstreamFirstByteTimeout):
		s.writeClientFrame(upstreamFirstByteTimeoutFrame())
		return 101, true
	case errors.Is(err, errPreviousResponseUnreplayable):
		return 101, true
	default:
		return 0, false
	}
}

func (s *codexRelayState) writeClientFrame(frame []byte) {
	if s == nil || s.clientWriter == nil || len(frame) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.clientWriter.Write(ctx, websocket.MessageText, frame)
}

// recordCompletedUsage sends terminal Codex websocket usage through the same
// accounting path as HTTP/SSE, using the originating request snapshot.
// The caller holds turnMu.
func (s *codexRelayState) recordCompletedUsage(data []byte, turn *codexRelayTurn) {
	if s.h == nil || s.opts.Provider == nil || s.activeAccount == nil || len(data) == 0 {
		return
	}

	var event map[string]any
	if err := json.Unmarshal(data, &event); err != nil || (event["type"] != "response.completed" && event["type"] != "response.done") {
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

// applyEffortCapToJSONFrame clamps reasoning effort on a websocket
// response.create frame for capped principals/origins. Codex Desktop sends
// effort inside the nested "response" envelope, which capCodexEffortInBody
// handles alongside the flat shape.
func applyEffortCapToJSONFrame(h *proxyHandler, reqID, userID, clientIP string, data []byte) []byte {
	if h == nil || len(data) == 0 {
		return data
	}
	limit := h.effortCap.limitFor(userID, clientIP)
	if limit == "" {
		return data
	}
	capped, previous, changed := capCodexEffortInBody(data, limit)
	if !changed {
		return data
	}
	log.Printf("[%s] ws effort cap: %s -> %s (user=%s ip=%s)", reqID, previous, limit, userID, clientIP)
	return capped
}

const (
	websocketBootstrapMaxFrames = 48
	websocketBootstrapMaxBytes  = 1 << 20
)

func isCodexMeaningfulOutput(data []byte) bool {
	var event struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &event) != nil {
		return false
	}
	switch event.Type {
	case "response.output_text.delta",
		"response.output_text.done",
		"response.reasoning_summary_text.delta",
		"response.reasoning_summary_text.done",
		"response.reasoning_text.delta",
		"response.reasoning_text.done",
		"response.function_call_arguments.delta",
		"response.function_call_arguments.done",
		"response.audio.delta":
		return true
	default:
		return false
	}
}

const (
	websocketOverloadWindow = 30 * time.Second
	// One same-account retry absorbs a transient blip; a second overload in
	// the window means the account is being shed, so move the turn.
	websocketOverloadSwapAfter = 2

	// websocketOverloadRecoveryMax bounds how many times a turn re-enters
	// the relay after every candidate account is cooling down from overload.
	// Each round waits for a candidate to leave cooldown, then retries the
	// previously failed accounts. Overload arrives in waves: a small pool that
	// fails together should wait out the cooldown rather than end the session.
	websocketOverloadRecoveryMax = 3

	// websocketOverloadRecoveryWait caps how long one recovery round blocks.
	// It mirrors the HTTP path's maxCooldownWait so a wave that outlasts the
	// cap falls back to the existing same-socket replay instead of pinning the
	// client behind a long spinner.
	websocketOverloadRecoveryWait = 10 * time.Second
)

func websocketOverloadDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := time.Second * time.Duration(attempt)
	if delay > 3*time.Second {
		return 3 * time.Second
	}
	return delay
}

func (s *codexRelayState) recordOverload(account *Account) int {
	if account == nil {
		return 0
	}
	if s.overloadTimes == nil {
		s.overloadTimes = make(map[string][]time.Time)
	}
	now := time.Now()
	cutoff := now.Add(-websocketOverloadWindow)
	entries := s.overloadTimes[account.ID]
	kept := entries[:0]
	for _, entry := range entries {
		if entry.After(cutoff) {
			kept = append(kept, entry)
		}
	}
	kept = append(kept, now)
	s.overloadTimes[account.ID] = kept
	if s.h != nil {
		s.h.applyServerOverloadCooldown(account)
	}
	return len(kept)
}

func (s *codexRelayState) overloadCandidate(turn *codexRelayTurn) *Account {
	if s.h == nil || s.h.pool == nil || turn == nil {
		return nil
	}
	exclude := map[string]bool{}
	if s.activeAccount != nil {
		exclude[s.activeAccount.ID] = true
	}
	tier := serviceTierFromJSON(turn.request)
	exclude = s.h.pool.tierExclusions(exclude, AccountTypeCodex, turn.model, tier)
	return s.h.pool.candidateForTier(turn.conversationID, exclude, AccountTypeCodex, s.opts.RequiredPlan, s.opts.ClientIP, turn.model, tier)
}

func (s *codexRelayState) bufferBootstrap(data []byte, turn *codexRelayTurn) {
	if turn == nil || s.bootstrapReady {
		return
	}
	if len(s.bootstrap) >= websocketBootstrapMaxFrames || s.bootstrapBytes+len(data) > websocketBootstrapMaxBytes {
		s.bootstrapReady = true
		s.bootstrap = append(s.bootstrap, append([]byte(nil), data...))
		s.bootstrapBytes += len(data)
		return
	}
	s.bootstrap = append(s.bootstrap, append([]byte(nil), data...))
	s.bootstrapBytes += len(data)
	if turn.outputStarted || isTerminalCodexWebSocketEvent(data) {
		s.bootstrapReady = true
	}
}

func (s *codexRelayState) flushBootstrap() [][]byte {
	s.turnMu.Lock()
	defer s.turnMu.Unlock()
	if !s.bootstrapReady {
		return nil
	}
	batch := s.bootstrap
	s.bootstrap = nil
	s.bootstrapBytes = 0
	s.bootstrapReady = false
	return batch
}

func (s *codexRelayState) clearBootstrap() {
	s.bootstrap = nil
	s.bootstrapBytes = 0
	s.bootstrapReady = false
}

func (s *codexRelayState) transportRetry(err error) *transportPendingErr {
	if err == nil || !strings.Contains(err.Error(), "upstream->client read:") || strings.Contains(err.Error(), "received close frame") {
		return nil
	}
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) && closeErr.Code != websocket.StatusAbnormalClosure {
		return nil
	}
	s.turnMu.Lock()
	defer s.turnMu.Unlock()
	if len(s.turns) != 1 || s.turns[0].outputStarted {
		return nil
	}
	return &transportPendingErr{turn: s.turns[0], err: err}
}

func (s *codexRelayState) retryTransportTurn(pending *transportPendingErr) error {
	if pending == nil || pending.turn == nil {
		return errors.New("transport retry has no pending turn")
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	s.turnMu.Lock()
	active := s.activeAccount
	s.turnMu.Unlock()
	if active == nil {
		return errors.New("transport retry has no active account")
	}
	return s.replaceTurnUpstream(active, pending.turn, "transport")
}

func (s *codexRelayState) retryOverloadedTurn(pending *overloadPendingErr) error {
	if pending == nil || pending.turn == nil {
		return errors.New("overload retry has no pending turn")
	}
	delay := websocketOverloadDelay(pending.count)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
	s.discardOverloadTail()
	s.clearBootstrap()

	s.turnMu.Lock()
	if len(s.turns) != 1 || s.turns[0] != pending.turn {
		pendingCount := len(s.turns)
		s.turnMu.Unlock()
		return fmt.Errorf("cannot retry websocket overload with %d pending responses", pendingCount)
	}
	turn := s.turns[0]
	if pending.count >= websocketOverloadSwapAfter {
		if cand := s.overloadCandidate(turn); cand != nil {
			s.turnMu.Unlock()
			return s.replaceTurnUpstream(cand, turn, "overload")
		}
		// No candidate is available: every eligible account is inside its
		// overload cooldown. Overload arrives in waves, so wait out the
		// nearest cooldown and retry candidate selection rather than ending
		// the session. Bound the rounds so a permanently failing pool still
		// fails instead of hanging forever.
		if cooldown, ok := s.overloadRecoveryCooldown(turn); ok {
			s.turnMu.Unlock()
			log.Printf("[%s] overload recovery %d/%d: waiting %s for account cooldown", s.opts.ReqID, s.overloadRecovery, websocketOverloadRecoveryMax, cooldown)
			select {
			case <-time.After(cooldown):
			case <-s.ctx.Done():
				return s.ctx.Err()
			}
			if cand := s.overloadCandidate(turn); cand != nil {
				return s.replaceTurnUpstream(cand, turn, "overload")
			}
		}
	}
	turn.responseID = ""
	replay := append([]byte(nil), turn.request...)
	writeErr := s.upstreamConn.Write(s.ctx, websocket.MessageText, replay)
	active := s.activeAccount
	s.turnMu.Unlock()
	if writeErr == nil {
		return nil
	}
	if active == nil {
		return writeErr
	}
	return s.replaceTurnUpstream(active, turn, "overload")
}

// overloadRecoveryCooldown reports whether and how long to wait before
// retrying candidate selection after every eligible account is cooling down
// from overload. It returns false once the bounded recovery rounds are
// exhausted, which falls through to the same-socket replay. The caller holds
// turnMu.
func (s *codexRelayState) overloadRecoveryCooldown(turn *codexRelayTurn) (time.Duration, bool) {
	if s == nil || s.h == nil || s.h.pool == nil || turn == nil {
		return 0, false
	}
	if s.overloadRecovery >= websocketOverloadRecoveryMax {
		return 0, false
	}
	cooldown := s.h.pool.nearestCooldown(AccountTypeCodex, s.h.pool.tierExclusions(map[string]bool{s.activeAccount.ID: true}, AccountTypeCodex, turn.model, serviceTierFromJSON(turn.request)))
	// Waiting only helps when another account is cooling down and will come
	// back; with no alternate account, retry the current one immediately.
	if cooldown <= 0 {
		return 0, false
	}
	s.overloadRecovery++
	if cooldown > websocketOverloadRecoveryWait {
		cooldown = websocketOverloadRecoveryWait
	}
	return cooldown, true
}

func (s *codexRelayState) discardOverloadTail() {
	for {
		select {
		case _, ok := <-s.upstreamCh:
			if !ok {
				return
			}
		default:
			return
		}
	}
}

// replayForNewSocket chooses the body for a socket that did not mint
// previous_response_id. Codex Responses uses contextRedialPayload. Other
// relays may rebuild a covering transcript from history.
func (s *codexRelayState) replayForNewSocket(turn *codexRelayTurn) ([]byte, error) {
	if turn == nil {
		return nil, errPreviousResponseUnreplayable
	}
	if s.contextEnabled() {
		return contextRedialPayload(turn.request)
	}
	return buildRedialPayload(turn.request, s.historyFor(turn.conversationID))
}

func (s *codexRelayState) replaceTurnUpstream(cand *Account, turn *codexRelayTurn, reason string) error {
	s.turnMu.Lock()
	defer s.turnMu.Unlock()
	if len(s.turns) != 1 || s.turns[0] != turn {
		return fmt.Errorf("cannot replace websocket overload turn")
	}
	if cand == nil {
		return errors.New("cannot replace websocket upstream without an account")
	}
	replay, replayErr := s.replayForNewSocket(turn)
	if replayErr != nil {
		err := s.rejectUnreplayableTurn(turn)
		s.turnMu.Unlock()
		s.writeUnreplayableFrame()
		s.turnMu.Lock()
		return err
	}
	s.clearBootstrap()
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
		return fmt.Errorf("replay overloaded turn: %w", err)
	}
	old := s.activeAccount
	s.activeConversationID = turn.conversationID
	if s.opts.SetActiveAccount != nil {
		s.opts.SetActiveAccount(cand)
	}
	if turn.conversationID != "" {
		s.h.pool.pin(turn.conversationID, cand.ID)
	}
	log.Printf("[%s] replacing codex upstream: %s -> %s (reason=%s)", s.opts.ReqID, accountIDForLog(old), cand.ID, reason)
	s.upstreamConn.CloseNow()
	s.upstreamConn = newConn
	s.upstreamCh = startWebSocketReader(s.ctx, newConn)
	s.activeAccount = cand
	s.contextAccount = authAccount
	turn.account = cand
	turn.responseID = ""
	return nil
}

// rejectUnreplayableTurn drops the turn under turnMu. The caller writes the
// previous_response_not_found frame after releasing the lock.
func (s *codexRelayState) rejectUnreplayableTurn(turn *codexRelayTurn) error {
	s.finishTurn(turn)
	log.Printf("[%s] refusing redial of previous_response_id on a new upstream socket", s.opts.ReqID)
	return errPreviousResponseUnreplayable
}

func (s *codexRelayState) writeUnreplayableFrame() {
	s.writeClientFrame(previousResponseNotFoundFrame())
}

func accountIDForLog(account *Account) string {
	if account == nil {
		return "unknown"
	}
	return account.ID
}

func (s *codexRelayState) doSwap(cand *Account) error {
	s.turnMu.Lock()
	defer s.turnMu.Unlock()
	// A client frame may arrive while the other pump is stopping. Never
	// replay that later turn in place of the one that triggered the swap.
	if len(s.turns) != 1 {
		return fmt.Errorf("cannot swap websocket account with %d pending responses", len(s.turns))
	}
	s.clearBootstrap()
	turn := s.turns[0]
	s.activeConversationID = turn.conversationID
	replay, replayErr := s.replayForNewSocket(turn)
	if replayErr != nil {
		err := s.rejectUnreplayableTurn(turn)
		s.turnMu.Unlock()
		s.writeUnreplayableFrame()
		s.turnMu.Lock()
		return err
	}
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
	if len(s.turns) == 1 {
		turn := s.turns[0]
		exclude = s.h.pool.tierExclusions(exclude, AccountTypeCodex, turn.model, serviceTierFromJSON(turn.request))
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
	// The swap target must not see the previous account's turn-state echo:
	// the replayed response.create would otherwise carry a blob this account
	// did not mint, a contradiction real Codex never produces.
	h.guardCodexTurnStateEcho(opts.UserID, opts.ConversationID, acc, tmpReq.Header)

	dialCtx, disarm := beginFirstByteDeadline(ctx, opts.FirstByteTimeout)
	conn, resp, _, err := dialUpstreamWebSocketWithSubprotocols(dialCtx, opts.InitialOutURL, tmpReq.Header, subprotocols, opts.ReadLimit, opts.CompressionEnabled)
	if disarm() || errors.Is(err, errUpstreamFirstByteTimeout) || errors.Is(context.Cause(dialCtx), errUpstreamFirstByteTimeout) {
		if conn != nil {
			conn.CloseNow()
		}
		return nil, resp, nil, errUpstreamFirstByteTimeout
	}
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
// response.create payload so a newly dialed upstream accepts the replay.
// If parsing fails or the field is absent, the original payload is returned
// unchanged.
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
