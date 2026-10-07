package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
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
	var req struct {
		APIKey string `json:"api_key"`
	}

	if r.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondJSONError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
	} else {
		req.APIKey = r.FormValue("api_key")
	}

	apiKey := strings.TrimSpace(req.APIKey)
	if apiKey == "" {
		respondJSONError(w, http.StatusBadRequest, "api_key is required")
		return
	}

	// Persist the validated catalog with the key so admission makes the
	// models routable immediately, rather than waiting for the next poll.
	validationURL := strings.TrimRight(h.cfg.mistralBase.String(), "/") + "/v1/models"
	validReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, validationURL, nil)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "invalid Mistral validation URL")
		return
	}
	validReq.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := h.transport.RoundTrip(validReq)
	if err != nil {
		respondJSONError(w, http.StatusBadGateway, "failed to validate key: "+err.Error())
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	resp.Body.Close()
	if err != nil {
		respondJSONError(w, http.StatusBadGateway, "failed to read Mistral catalog")
		return
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		respondJSONError(w, http.StatusBadRequest, "invalid API key (authentication failed)")
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respondJSONError(w, http.StatusBadGateway, fmt.Sprintf("key validation returned status %d", resp.StatusCode))
		return
	}
	models, err := parseMistralModels(body)
	if err != nil {
		respondJSONError(w, http.StatusBadGateway, "key validation returned an unexpected catalog: "+err.Error())
		return
	}

	snapshot := &providerModelSnapshot{FetchedAt: time.Now().UTC(), Models: models}
	h.saveAPIKeySnapshot(w, r, AccountTypeMistral, "mistral", apiKey, snapshot)
}
