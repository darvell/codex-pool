package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Pool user admin handlers - JSON API only

// servePoolUsersAdmin routes pool user admin requests (auth already checked by router)
func (h *proxyHandler) servePoolUsersAdmin(w http.ResponseWriter, r *http.Request) {
	if h.poolUsers == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "pool users not configured")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/admin/pool-users")
	if path == "" {
		path = "/"
	}

	switch {
	case path == "/" && r.Method == http.MethodGet:
		h.handlePoolUsersList(w, r)

	case path == "/" && r.Method == http.MethodPost:
		h.handlePoolUsersCreate(w, r)

	case strings.HasPrefix(path, "/") && r.Method == http.MethodDelete:
		id := strings.TrimPrefix(path, "/")
		id = strings.TrimSuffix(id, "/")
		h.handlePoolUserDelete(w, r, id)

	// Support POST with /disable suffix for backwards compatibility
	case strings.HasSuffix(path, "/disable") && r.Method == http.MethodPost:
		id := strings.TrimPrefix(path, "/")
		id = strings.TrimSuffix(id, "/disable")
		h.handlePoolUserDelete(w, r, id)

	default:
		http.NotFound(w, r)
	}
}

// GET /admin/pool-users - list all pool users
func (h *proxyHandler) handlePoolUsersList(w http.ResponseWriter, r *http.Request) {
	users := h.poolUsers.List()

	type userInfo struct {
		ID        string    `json:"id"`
		Email     string    `json:"email"`
		PlanType  string    `json:"plan_type"`
		CreatedAt time.Time `json:"created_at"`
		Disabled  bool      `json:"disabled"`
	}

	var result []userInfo
	for _, u := range users {
		result = append(result, userInfo{
			ID:        u.ID,
			Email:     u.Email,
			PlanType:  u.PlanType,
			CreatedAt: u.CreatedAt,
			Disabled:  u.Disabled,
		})
	}

	respondJSON(w, map[string]any{
		"users": result,
		"count": len(result),
	})
}

// POST /admin/pool-users - create a new pool user
func (h *proxyHandler) handlePoolUsersCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		PlanType string `json:"plan_type"`
	}

	if r.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondJSONError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
	} else {
		req.Email = r.FormValue("email")
		req.PlanType = r.FormValue("plan_type")
	}

	email := strings.TrimSpace(req.Email)
	planType := req.PlanType
	if planType == "" {
		planType = "pro"
	}

	if email == "" {
		respondJSONError(w, http.StatusBadRequest, "email is required")
		return
	}

	user := &PoolUser{
		ID:        randomHex(16),
		Token:     randomHex(32),
		Email:     email,
		PlanType:  planType,
		CreatedAt: time.Now(),
	}

	if err := h.poolUsers.Create(user); err != nil {
		respondJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	baseURL := h.getEffectivePublicURL(r)

	respondJSON(w, map[string]any{
		"user": map[string]any{
			"id":         user.ID,
			"email":      user.Email,
			"plan_type":  user.PlanType,
			"created_at": user.CreatedAt,
		},
		"token": user.Token,
		"setup": map[string]string{
			"codex_config":  baseURL + "/config/codex/" + user.Token,
			"gemini_config": baseURL + "/config/gemini/" + user.Token,
			"claude_config": baseURL + "/config/claude/" + user.Token,
		},
	})
}

// DELETE /admin/pool-users/:id - disable/delete a pool user
func (h *proxyHandler) handlePoolUserDelete(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.poolUsers.Disable(id); err != nil {
		respondJSONError(w, http.StatusNotFound, err.Error())
		return
	}

	respondJSON(w, map[string]any{
		"success": true,
		"id":      id,
	})
}

// Config download endpoints (no auth - token IS the auth)

func (h *proxyHandler) serveConfigDownload(w http.ResponseWriter, r *http.Request) {
	if h.poolUsers == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "pool users not configured")
		return
	}

	path := r.URL.Path
	var configType string
	var token string

	switch {
	case strings.HasPrefix(path, "/config/codex/"):
		configType = "codex"
		token = strings.TrimPrefix(path, "/config/codex/")
	case strings.HasPrefix(path, "/config/gemini/"):
		configType = "gemini"
		token = strings.TrimPrefix(path, "/config/gemini/")
	case strings.HasPrefix(path, "/config/claude/"):
		configType = "claude"
		token = strings.TrimPrefix(path, "/config/claude/")
	case strings.HasPrefix(path, "/config/pi/"):
		configType = "pi"
		token = strings.TrimPrefix(path, "/config/pi/")
	default:
		http.NotFound(w, r)
		return
	}

	token = strings.TrimSuffix(token, "/")
	if token == "" {
		respondJSONError(w, http.StatusBadRequest, "token required")
		return
	}

	user := h.poolUsers.GetByToken(token)
	if user == nil {
		respondJSONError(w, http.StatusNotFound, "invalid token")
		return
	}
	if user.Disabled {
		respondJSONError(w, http.StatusForbidden, "user disabled")
		return
	}

	secret := getPoolJWTSecret()
	if secret == "" {
		respondJSONError(w, http.StatusServiceUnavailable, "JWT secret not configured")
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch configType {
	case "codex":
		auth, err := generateCodexAuth(secret, user)
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		json.NewEncoder(w).Encode(auth)
	case "gemini":
		auth, err := generateGeminiAuth(secret, user)
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		json.NewEncoder(w).Encode(auth)
	case "claude":
		auth, err := generateClaudeAuth(secret, user)
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		json.NewEncoder(w).Encode(auth)
	case "pi":
		codexAuth, err := generateCodexAuth(secret, user)
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		auth, err := generateClaudeAuth(secret, user)
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		publicURL := h.getEffectivePublicURL(r)
		codexAccessToken := ""
		if codexAuth.Tokens != nil {
			codexAccessToken = codexAuth.Tokens.AccessToken
		}
		modelsJSON, err := generatePiModelsJSON(publicURL, codexAccessToken, auth.AccessToken)
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Write(modelsJSON)
	}
}
