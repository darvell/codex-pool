package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

type clientCredentialView struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	Status     string     `json:"status"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
}

func parsePoolCredentialRequest(r *http.Request, secret string) (identity string, issuedAt time.Time, kind string, ok bool) {
	if secret == "" {
		return "", time.Time{}, "", false
	}
	authHeader := r.Header.Get("Authorization")
	claudeToken := strings.TrimPrefix(authHeader, "Bearer ")
	if claudeToken == "" {
		claudeToken = strings.TrimSpace(r.Header.Get("X-Api-Key"))
	}
	if identity, issuedAt, ok = parseClaudePoolCredential(secret, claudeToken); ok {
		return identity, issuedAt, "claude", true
	}
	geminiKey := r.Header.Get("x-goog-api-key")
	if geminiKey == "" {
		geminiKey = r.URL.Query().Get("key")
	}
	if identity, issuedAt, ok = parsePoolGeminiAPIKey(secret, geminiKey); ok {
		return identity, issuedAt, "gemini_api_key", true
	}
	if identity, issuedAt, ok = parsePoolUserToken(secret, authHeader); ok {
		return identity, issuedAt, "jwt", true
	}
	if strings.HasPrefix(authHeader, "Bearer ") {
		if identity, issuedAt, ok = parseGeminiOAuthPoolToken(secret, strings.TrimPrefix(authHeader, "Bearer ")); ok {
			return identity, issuedAt, "gemini_oauth", true
		}
	}
	return "", time.Time{}, "", false
}

func (h *proxyHandler) authorizePoolCredentialRequest(r *http.Request) (identity, principalID, clientID, kind string, allowed bool) {
	identity, issuedAt, kind, parsed := parsePoolCredentialRequest(r, getPoolJWTSecret())
	if !parsed {
		h.metrics.incPassport("authorization_outcomes", "unrecognized")
		return "", "", "", "", false
	}
	if h.passport != nil {
		principalID, clientID, allowed = h.passport.authorizeIssuedCredential(identity, issuedAt)
		if allowed {
			h.metrics.incPassport("authorization_outcomes", "allowed")
			h.passport.markCredentialSeen(principalID, clientID, time.Now())
		} else {
			h.metrics.incPassport("authorization_outcomes", "denied")
		}
		return identity, principalID, clientID, kind, allowed
	}
	if h.poolUsers != nil {
		user := h.poolUsers.Get(identity)
		if user != nil && !user.Disabled {
			return identity, identity, "legacy-" + identity, kind, true
		}
		return identity, "", "", kind, false
	}
	// Production startup requires Passport. Preserve the former signed-token
	// behavior only for directly constructed handlers used by embedders and tests.
	return identity, identity, "legacy-" + identity, kind, true
}

func (h *proxyHandler) requirePoolCredential(w http.ResponseWriter, r *http.Request) bool {
	if _, _, _, _, ok := h.authorizePoolCredentialRequest(r); ok {
		return true
	}
	http.Error(w, "unauthorized: valid pool credential required", http.StatusUnauthorized)
	return false
}

func (h *proxyHandler) handlePassportLegacyExchange(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		DownloadToken string `json:"download_token"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil || strings.TrimSpace(input.DownloadToken) == "" {
		respondJSONError(w, http.StatusBadRequest, "download token required")
		return
	}
	client := h.passport.clientByDownloadToken(strings.TrimSpace(input.DownloadToken))
	if client == nil {
		respondJSONError(w, http.StatusUnauthorized, "legacy session unavailable")
		return
	}
	principalID, _, ok := h.passport.authorizeCredential(client.PrincipalID + "-c-" + client.ID)
	if !ok {
		respondJSONError(w, http.StatusUnauthorized, "legacy session unavailable")
		return
	}
	token, csrf, err := h.passport.createSession(principalID)
	if err != nil {
		respondJSONError(w, 500, "session unavailable")
		return
	}
	setSessionCookies(w, token, csrf)
	respondJSON(w, map[string]any{"principal": publicPrincipal(h.passport.principal(principalID)), "csrf": csrf})
}

func (h *proxyHandler) handlePassportLogin(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if h.passport == nil {
		respondJSONError(w, 503, "accounts unavailable")
		return
	}
	var q struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		respondJSONError(w, 400, "invalid json")
		return
	}
	pr, token, csrf, err := h.passport.login(q.Email, q.Password)
	if err != nil {
		h.metrics.incPassport("sign_in_outcomes", "failed")
		respondJSONError(w, 401, "email or password is incorrect")
		return
	}
	h.metrics.incPassport("sign_in_outcomes", "succeeded")
	setSessionCookies(w, token, csrf)
	respondJSON(w, map[string]any{"principal": publicPrincipal(pr), "csrf": csrf})
}
func publicPrincipal(p *Principal) map[string]any {
	avatarURL := ""
	if p.AvatarUpdatedAt != nil {
		avatarURL = "/api/avatars/" + p.ID + "?v=" + p.AvatarUpdatedAt.UTC().Format("20060102T150405.000000000")
	}
	return map[string]any{"id": p.ID, "kind": p.Kind, "status": p.Status, "display_name": p.DisplayName, "username": p.Username, "email": p.Email, "expires_at": p.ExpiresAt, "avatar_url": avatarURL}
}
func (h *proxyHandler) handlePassportLogout(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	_, session := h.passport.authenticate(r)
	if session == nil {
		respondJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.passportCSRF(r, session) {
		respondJSONError(w, http.StatusForbidden, "csrf validation failed")
		return
	}
	if cookie, err := r.Cookie("pool_session"); err == nil {
		digest := hashToken(cookie.Value)
		_ = h.passport.db.Update(func(tx *bbolt.Tx) error {
			return tx.Bucket([]byte(bucketPassportSessions)).Delete(digest[:])
		})
	}
	http.SetCookie(w, &http.Cookie{Name: "pool_session", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "pool_csrf", Path: "/", Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	respondJSON(w, map[string]any{"success": true})
}

func (h *proxyHandler) handlePassportMe(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	pr, session := h.passport.authenticate(r)
	if pr == nil {
		respondJSONError(w, 401, "unauthorized")
		return
	}
	h.passport.renewSession(w, r, session)
	respondJSON(w, publicPrincipal(pr))
}
func (h *proxyHandler) passportCSRF(r *http.Request, s *passportSession) bool {
	c, e := r.Cookie("pool_csrf")
	if e != nil {
		return false
	}
	got := r.Header.Get("X-CSRF-Token")
	if got == "" || got != c.Value {
		return false
	}
	x := hashToken(got)
	return x == s.CSRFHash
}
func (h *proxyHandler) handlePassportClients(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	pr, s := h.passport.authenticate(r)
	if pr == nil {
		respondJSONError(w, 401, "unauthorized")
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.passport.mu.RLock()
		out := make([]clientCredentialView, 0)
		for _, c := range h.passport.clients {
			if c.PrincipalID == pr.ID {
				view := clientCredentialView{ID: c.ID, Label: c.Label, Status: c.Status, ExpiresAt: c.ExpiresAt, CreatedAt: c.CreatedAt}
				if !c.LastSeenAt.IsZero() {
					lastSeen := c.LastSeenAt
					view.LastSeenAt = &lastSeen
				}
				out = append(out, view)
			}
		}
		h.passport.mu.RUnlock()
		respondJSON(w, out)
	case http.MethodPost:
		if !h.passportCSRF(r, s) {
			respondJSONError(w, 403, "csrf validation failed")
			return
		}
		var q struct {
			Label     string     `json:"label"`
			ExpiresAt *time.Time `json:"expires_at"`
		}
		if json.NewDecoder(r.Body).Decode(&q) != nil {
			respondJSONError(w, 400, "invalid json")
			return
		}
		c, err := h.passport.createClient(pr.ID, q.Label, q.ExpiresAt)
		if err != nil {
			respondJSONError(w, 400, err.Error())
			return
		}
		respondJSON(w, map[string]any{"id": c.ID, "label": c.Label, "expires_at": c.ExpiresAt, "setup_token": c.DownloadToken})
	default:
		http.Error(w, "method not allowed", 405)
	}
}
func (h *proxyHandler) handlePassportUsage(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	pr, _ := h.passport.authenticate(r)
	if pr == nil {
		respondJSONError(w, 401, "unauthorized")
		return
	}
	if h.duckAnalytics == nil {
		respondJSONError(w, 503, "analytics unavailable")
		return
	}
	hours := 168
	if v, _ := strconv.Atoi(r.URL.Query().Get("hours")); v > 0 && v <= 24*366 {
		hours = v
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	rows, err := h.duckAnalytics.UserHourly(ctx, pr.ID, time.Now().Add(-time.Duration(hours)*time.Hour))
	if err != nil {
		respondJSONError(w, 500, "analytics query failed")
		return
	}
	respondJSON(w, map[string]any{"hourly": rows, "excludes_passthrough": true})
}
func (h *proxyHandler) handleOperatorBootstrap(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if strings.TrimSpace(r.Header.Get("X-Admin-Token")) == "" || !h.checkAdminAuth(w, r) {
		return
	}
	if h.passport == nil {
		respondJSONError(w, 503, "accounts unavailable")
		return
	}
	var q struct {
		Username         string `json:"username"`
		Email            string `json:"email"`
		Password         string `json:"password"`
		DisplayName      string `json:"display_name"`
		LegacyCredential string `json:"legacy_credential"`
	}
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		respondJSONError(w, http.StatusBadRequest, "invalid operator bootstrap request")
		return
	}
	principal, err := h.passport.bootstrapOperator(q.Username, q.Email, q.DisplayName, q.Password, q.LegacyCredential)
	if err != nil {
		status := http.StatusBadRequest
		if err.Error() == "operator already exists" {
			status = http.StatusNotFound
		}
		respondJSONError(w, status, err.Error())
		return
	}
	respondJSON(w, publicPrincipal(principal))
}
