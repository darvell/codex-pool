package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (h *proxyHandler) serveXiaomiAdmin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/xiaomi")
	if path == "" {
		path = "/"
	}

	switch {
	case path == "/" && r.Method == http.MethodGet:
		h.handleAPIKeyList(w, AccountTypeXiaomi)
	case path == "/add" && r.Method == http.MethodPost:
		h.handleXiaomiAdd(w, r)
	case strings.HasSuffix(path, "/remove") && r.Method == http.MethodPost:
		id := strings.TrimPrefix(path, "/")
		id = strings.TrimSuffix(id, "/remove")
		h.handleAPIKeyRemove(w, AccountTypeXiaomi, id)
	default:
		http.NotFound(w, r)
	}
}

func (h *proxyHandler) handleXiaomiAdd(w http.ResponseWriter, r *http.Request) {
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

	validationURL := h.cfg.xiaomiBase.String() + "/v1/messages"
	body := map[string]any{
		"model":      xiaomiCanonicalModel("mimo-v2.5-pro"),
		"max_tokens": 8,
		"messages": []map[string]string{
			{"role": "user", "content": "hi"},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	validReq, _ := http.NewRequest(http.MethodPost, validationURL, bytes.NewReader(bodyBytes))
	validReq.Header.Set("Authorization", "Bearer "+apiKey)
	validReq.Header.Set("Content-Type", "application/json")
	validReq.Header.Set("anthropic-version", ccAnthropicVersion)

	resp, err := h.transport.RoundTrip(validReq)
	if err != nil {
		respondJSONError(w, http.StatusBadGateway, "failed to validate key: "+err.Error())
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		respondJSONError(w, http.StatusBadRequest, "invalid API key (authentication failed)")
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respondJSONError(w, http.StatusBadGateway, fmt.Sprintf("key validation returned status %d", resp.StatusCode))
		return
	}

	h.saveAPIKeyAccountFile(w, AccountTypeXiaomi, "xiaomi", apiKey)
}
