package main

import (
	"net/http"
	"strings"
)

type modelAuthenticator interface {
	SetAuthHeadersForModel(*http.Request, *Account, string)
}

func setPoolAuth(req *http.Request, provider Provider, account *Account, model string) {
	req.Header.Del("Authorization")
	req.Header.Del("X-Api-Key")
	req.Header.Del("x-goog-api-key")
	if auth, ok := provider.(modelAuthenticator); ok {
		auth.SetAuthHeadersForModel(req, account, model)
		return
	}
	provider.SetAuthHeaders(req, account)
}

func removeConflictingProxyHeaders(h http.Header) {
	// Remove ALL Cloudflare headers (Cf-*) — our own Cloudflare adds these,
	// and they confuse upstream Cloudflare (e.g. chatgpt.com) into blocking us.
	for key := range h {
		if strings.HasPrefix(strings.ToLower(key), "cf-") {
			h.Del(key)
		}
	}
	h.Del("Cdn-Loop")

	h.Del("X-Forwarded-For")
	h.Del("X-Forwarded-Proto")
	h.Del("X-Forwarded-Host")
	h.Del("X-Real-Ip")
	h.Del("Via")
	h.Del("True-Client-Ip")
}
