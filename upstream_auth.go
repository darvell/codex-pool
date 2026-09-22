package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
)

const upstreamAuthErrorCode = "upstream_auth_unavailable"

// Pool credentials and provider credentials are separate authorities. Only a
// rejected pool credential may tell the client to refresh its own login.
func writeUpstreamAuthError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = fmt.Fprintf(w, `{"error":{"type":"server_error","code":%q,"message":"Upstream account authentication failed. Retry the request; your pool credentials are unchanged."}}`, upstreamAuthErrorCode)
}

func (h *proxyHandler) retryPoolAuth(ctx context.Context, acc *Account) bool {
	if h.cfg.disableRefresh {
		return false
	}
	acc.mu.Lock()
	hasRefresh := acc.RefreshToken != ""
	acc.mu.Unlock()
	if !hasRefresh {
		return false
	}
	if err := h.refreshAccountAfterAuthFailure(ctx, acc); err != nil {
		log.Printf("upstream authentication recovery failed: account=%s", acc.ID)
		return false
	}
	return true
}
