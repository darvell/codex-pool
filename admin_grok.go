package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (h *proxyHandler) serveGrokAdmin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/grok")
	if path == "" {
		path = "/"
	}

	switch {
	case path == "/" && r.Method == http.MethodGet:
		h.handleAPIKeyList(w, AccountTypeGrok)
	case (path == "/import" || path == "/add") && r.Method == http.MethodPost:
		h.handleGrokImport(w, r)
	case strings.HasSuffix(path, "/remove") && r.Method == http.MethodPost:
		id := strings.TrimPrefix(path, "/")
		id = strings.TrimSuffix(id, "/remove")
		h.handleAPIKeyRemove(w, AccountTypeGrok, id)
	default:
		http.NotFound(w, r)
	}
}

func (h *proxyHandler) handleGrokImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AuthJSON      string `json:"auth_json"`
		AccessToken   string `json:"access_token"`
		RefreshToken  string `json:"refresh_token"`
		ExpiresAt     string `json:"expires_at"`
		TokenEndpoint string `json:"token_endpoint"`
	}

	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondJSONError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
	} else {
		req.AuthJSON = r.FormValue("auth_json")
		req.AccessToken = r.FormValue("access_token")
		req.RefreshToken = r.FormValue("refresh_token")
		req.ExpiresAt = r.FormValue("expires_at")
		req.TokenEndpoint = r.FormValue("token_endpoint")
	}

	data := []byte(strings.TrimSpace(req.AuthJSON))
	if len(data) == 0 {
		access := strings.TrimSpace(req.AccessToken)
		refresh := strings.TrimSpace(req.RefreshToken)
		if access == "" && refresh == "" {
			respondJSONError(w, http.StatusBadRequest, "auth_json or access_token/refresh_token is required")
			return
		}
		body := map[string]any{
			"access_token":  access,
			"refresh_token": refresh,
			"plan_type":     "grok",
		}
		if endpoint := strings.TrimSpace(req.TokenEndpoint); endpoint != "" {
			body["token_endpoint"] = endpoint
		} else {
			body["token_endpoint"] = grokDefaultTokenURL
		}
		if expires := strings.TrimSpace(req.ExpiresAt); expires != "" {
			body["expires_at"] = expires
		}
		var err error
		data, err = json.MarshalIndent(body, "", "  ")
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, "failed to marshal account json: "+err.Error())
			return
		}
	}

	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		respondJSONError(w, http.StatusBadRequest, "invalid Grok auth JSON: "+err.Error())
		return
	}
	root["added_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "failed to marshal account json: "+err.Error())
		return
	}

	accountID := "grok_" + randomHex(4)
	poolDir := filepath.Join(h.cfg.poolDir, "grok")
	filePath := filepath.Join(poolDir, accountID+".json")
	provider := NewGrokProvider(h.cfg.grokBase)
	acc, err := provider.LoadAccount(filepath.Base(filePath), filePath, data)
	if err != nil {
		respondJSONError(w, http.StatusBadRequest, "invalid Grok account: "+err.Error())
		return
	}
	if acc == nil || strings.TrimSpace(acc.AccessToken) == "" && strings.TrimSpace(acc.RefreshToken) == "" {
		respondJSONError(w, http.StatusBadRequest, "Grok auth JSON did not contain tokens")
		return
	}

	if err := os.MkdirAll(poolDir, 0o755); err != nil {
		respondJSONError(w, http.StatusInternalServerError, "failed to create pool dir: "+err.Error())
		return
	}
	if _, err := os.Stat(filePath); err == nil {
		for i := 2; i <= 99; i++ {
			candidateID := fmt.Sprintf("%s_%d", accountID, i)
			candidatePath := filepath.Join(poolDir, candidateID+".json")
			if _, err := os.Stat(candidatePath); os.IsNotExist(err) {
				accountID = candidateID
				filePath = candidatePath
				break
			}
		}
	}
	if err := os.WriteFile(filePath, data, 0o600); err != nil {
		respondJSONError(w, http.StatusInternalServerError, "failed to write account: "+err.Error())
		return
	}

	h.reloadAccounts()
	respondJSON(w, map[string]any{
		"success":    true,
		"account_id": acc.ID,
	})
}
