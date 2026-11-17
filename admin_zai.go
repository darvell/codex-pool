package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (h *proxyHandler) serveZAIAdmin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/zai")
	if path == "" {
		path = "/"
	}

	switch {
	case path == "/" && r.Method == http.MethodGet:
		h.handleAPIKeyList(w, AccountTypeZAI)
	case path == "/add" && r.Method == http.MethodPost:
		h.handleZAIAdd(w, r)
	case strings.HasSuffix(path, "/remove") && r.Method == http.MethodPost:
		id := strings.TrimPrefix(path, "/")
		id = strings.TrimSuffix(id, "/remove")
		h.handleAPIKeyRemove(w, AccountTypeZAI, id)
	default:
		http.NotFound(w, r)
	}
}

func (h *proxyHandler) handleZAIAdd(w http.ResponseWriter, r *http.Request) {
	apiKey, ok := readAdmissionKey(w, r)
	if !ok {
		return
	}
	validationURL := h.cfg.zaiBase.String() + "/v1/messages"
	body := map[string]any{
		"model":      "glm-5.3",
		"max_tokens": 1,
		"messages": []map[string]string{
			{"role": "user", "content": "hi"},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	validReq, _ := http.NewRequest(http.MethodPost, validationURL, strings.NewReader(string(bodyBytes)))
	validReq.Header.Set("X-Api-Key", apiKey)
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

	h.saveAPIKeyAccountFile(w, r, AccountTypeZAI, apiKey)
}
