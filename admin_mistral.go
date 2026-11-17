package main

import (
	"net/http"
	"strings"
)

func (h *proxyHandler) serveMistralAdmin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/mistral")
	if path == "" {
		path = "/"
	}

	switch {
	case path == "/" && r.Method == http.MethodGet:
		h.handleAPIKeyList(w, AccountTypeMistral)
	case path == "/add" && r.Method == http.MethodPost:
		h.handleMistralAdd(w, r)
	case strings.HasSuffix(path, "/remove") && r.Method == http.MethodPost:
		id := strings.TrimPrefix(path, "/")
		id = strings.TrimSuffix(id, "/remove")
		h.handleAPIKeyRemove(w, AccountTypeMistral, id)
	default:
		http.NotFound(w, r)
	}
}

func (h *proxyHandler) handleMistralAdd(w http.ResponseWriter, r *http.Request) {
	apiKey, ok := readAdmissionKey(w, r)
	if !ok {
		return
	}
	h.handleCatalogKeyAdd(w, r, "Mistral", NewMistralProvider(h.cfg.mistralBase), apiKey)
}
