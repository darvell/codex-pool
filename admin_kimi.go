package main

import (
	"net/http"
	"strings"
)

func (h *proxyHandler) serveKimiAdmin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/kimi")
	if path == "" {
		path = "/"
	}

	switch {
	case path == "/" && r.Method == http.MethodGet:
		h.handleAPIKeyList(w, AccountTypeKimi)

	case path == "/add" && r.Method == http.MethodPost:
		h.handleKimiAdd(w, r)

	case strings.HasSuffix(path, "/remove") && r.Method == http.MethodPost:
		id := strings.TrimPrefix(path, "/")
		id = strings.TrimSuffix(id, "/remove")
		h.handleAPIKeyRemove(w, AccountTypeKimi, id)

	default:
		http.NotFound(w, r)
	}
}

func (h *proxyHandler) handleKimiAdd(w http.ResponseWriter, r *http.Request) {
	apiKey, ok := readAdmissionKey(w, r)
	if !ok {
		return
	}
	h.handleCatalogKeyAdd(w, r, "Kimi", NewKimiProvider(h.cfg.kimiBase), apiKey)
}
