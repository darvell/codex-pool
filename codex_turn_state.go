package main

import (
	"net/http"
	"strings"
	"time"
)

// Codex mints the opaque x-codex-turn-state blob per account (bound to the
// outbound identity the account used). A client echo minted by account A and
// replayed to account B is a contradiction real Codex never produces — only a
// proxy chain creates it, on failover retries and hot-swaps. Track which
// account minted the blob the downstream client currently holds, and strip a
// known cross-account echo before it reaches upstream.
//
// This is the anti-contamination half of sub2api's ticket system, without the
// harvester: we never synthesize traffic or store blobs, we only stop
// forwarding a blob to an account that did not mint it. Unknown origin (no
// record, expired record, first turn) passes through untouched.

const codexTurnStateHeader = "x-codex-turn-state"

// codexTurnStateProvenanceTTL bounds a stale mapping. Upstream tickets live
// about an hour, so an entry older than that no longer describes what the
// client holds.
const codexTurnStateProvenanceTTL = time.Hour

type codexTurnStateOrigin struct {
	accountID string
	expiresAt time.Time
}

// codexTurnStateSeed keys a downstream session. The pool credential must be
// part of the key because unrelated pool users can reuse the same
// conversation/session string. Empty means untrackable: keep passthrough.
func codexTurnStateSeed(userID, conversationID string) string {
	userID = strings.TrimSpace(userID)
	conversationID = strings.TrimSpace(conversationID)
	if userID == "" || conversationID == "" {
		return ""
	}
	return userID + "\x00" + conversationID
}

// noteCodexTurnState records which account minted the turn-state blob just
// committed downstream. Call only when the client confirmedly received the
// blob (response headers written, attempt not discarded by failover),
// otherwise a dropped attempt poisons the next request's guard.
func (h *proxyHandler) noteCodexTurnState(userID, conversationID string, acc *Account, state string) {
	if h == nil || acc == nil || acc.Type != AccountTypeCodex {
		return
	}
	if strings.TrimSpace(state) == "" {
		return
	}
	seed := codexTurnStateSeed(userID, conversationID)
	if seed == "" {
		return
	}
	h.turnStateMu.Lock()
	if h.turnStateOrigins == nil {
		h.turnStateOrigins = map[string]codexTurnStateOrigin{}
	}
	h.turnStateOrigins[seed] = codexTurnStateOrigin{accountID: acc.ID, expiresAt: time.Now().Add(codexTurnStateProvenanceTTL)}
	h.turnStateWrites++
	sweep := h.turnStateWrites%256 == 0
	if sweep {
		now := time.Now()
		for key, origin := range h.turnStateOrigins {
			if origin.expiresAt.IsZero() || !now.Before(origin.expiresAt) {
				delete(h.turnStateOrigins, key)
			}
		}
	}
	h.turnStateMu.Unlock()
}

// guardCodexTurnStateEcho strips a client-echoed turn-state blob known to be
// minted by a different account than the one about to serve the request.
// Same-account and unknown-origin echoes pass through unchanged.
func (h *proxyHandler) guardCodexTurnStateEcho(userID, conversationID string, acc *Account, header http.Header) {
	if h == nil || acc == nil || acc.Type != AccountTypeCodex || header == nil {
		return
	}
	if strings.TrimSpace(header.Get(codexTurnStateHeader)) == "" {
		return
	}
	seed := codexTurnStateSeed(userID, conversationID)
	if seed == "" {
		return
	}
	h.turnStateMu.Lock()
	origin, ok := h.turnStateOrigins[seed]
	if ok && (origin.expiresAt.IsZero() || !time.Now().Before(origin.expiresAt)) {
		delete(h.turnStateOrigins, seed)
		ok = false
	}
	h.turnStateMu.Unlock()
	if !ok {
		return
	}
	if origin.accountID != acc.ID {
		header.Del(codexTurnStateHeader)
	}
}
