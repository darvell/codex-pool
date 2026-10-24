package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

const chatGPTBucket = "chatgpt_gateway"
const chatGPTSessionTTL = 15 * time.Minute
const chatGPTPrefix = "/pool/chatgpt"

type chatGPTReservation struct {
	Alias       string `json:"alias"`
	PrincipalID string `json:"principal_id"`
	Identity    string `json:"identity"`
	Version     string `json:"version"`
	Enabled     bool   `json:"enabled"`
}

type chatGPTSession struct {
	ID          string             `json:"session_id"`
	Identity    string             `json:"credential_identity"`
	IssuedAt    time.Time          `json:"issued_at"`
	PrincipalID string             `json:"principal_id"`
	Reservation chatGPTReservation `json:"reservation"`
	ExpiresAt   time.Time          `json:"expires_at"`
}

type chatGPTGateway struct {
	db        *bbolt.DB
	pool      *poolState
	origin    *url.URL
	issuer    string
	key       []byte
	transport http.RoundTripper
	refresh   func(context.Context, *Account) error
}

// Call before serving traffic: reservations and their physical identity bindings
// are loaded into the same lock boundary used by every generic selector.
func newChatGPTGateway(db *bbolt.DB, pool *poolState, origin, issuer string, transport http.RoundTripper) (*chatGPTGateway, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid ChatGPT backend origin")
	}
	public, err := url.Parse(issuer)
	if err != nil || public.Scheme != "https" || public.Host == "" || public.User != nil || public.Path != "" || public.RawQuery != "" || public.Fragment != "" {
		return nil, errors.New("invalid ChatGPT pool issuer")
	}
	g := &chatGPTGateway{db: db, pool: pool, origin: u, issuer: issuer, transport: transport}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	reservations := map[string]chatGPTReservation{}
	err = db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(chatGPTBucket))
		if err != nil {
			return err
		}
		g.key = append([]byte(nil), b.Get([]byte("key"))...)
		if len(g.key) == 0 {
			g.key = make([]byte, 32)
			if _, err = rand.Read(g.key); err != nil {
				return err
			}
			if err = b.Put([]byte("key"), g.key); err != nil {
				return err
			}
		}
		if len(g.key) != 32 {
			return errors.New("invalid ChatGPT signing key")
		}
		return b.ForEach(func(k, v []byte) error {
			if !strings.HasPrefix(string(k), "reservation:") {
				return nil
			}
			var r chatGPTReservation
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			if r.Alias == "" || r.Identity == "" || r.PrincipalID == "" || r.Version == "" {
				return errors.New("invalid ChatGPT reservation")
			}
			reservations[r.Alias] = r
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	pool.chatGPTReservations = reservations
	return g, nil
}

func chatGPTPhysicalLocked(a *Account) string {
	accountID := a.AccountID
	if accountID == "" {
		accountID = a.IDTokenChatGPTAccountID
	}
	user := a.ChatGPTUserID
	for _, token := range []string{a.IDToken, a.AccessToken} {
		claims := parseCodexClaims(token)
		if claims.ChatGPTAccountID != "" && claims.ChatGPTAccountID != accountID {
			return ""
		}
		if claims.ChatGPTUserID == "" {
			continue
		}
		// Refresh may retain cached fields or the old ID token. A changed token
		// subject must not inherit the previous user's reservation.
		if user != "" && user != claims.ChatGPTUserID {
			return ""
		}
		user = claims.ChatGPTUserID
	}
	if a.Type != AccountTypeCodex || accountID == "" || user == "" {
		return ""
	}
	raw, _ := json.Marshal([]string{accountID, user})
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

// Both locks are held by selectors. Alias exclusions survive credential replacement;
// physical exclusions also cover duplicate files and renamed aliases.
func (p *poolState) chatGPTReservedLocked(a *Account) bool {
	if len(p.chatGPTReservations) == 0 {
		return false
	}
	if _, ok := p.chatGPTReservations[a.ID]; ok {
		return true
	}
	identity := chatGPTPhysicalLocked(a)
	for _, r := range p.chatGPTReservations {
		if identity != "" && r.Identity == identity {
			return true
		}
	}
	return false
}

func (g *chatGPTGateway) reserve(alias, principal string, enabled bool) (chatGPTReservation, error) {
	g.pool.mu.Lock()
	defer g.pool.mu.Unlock()
	a := g.pool.getLocked(alias)
	if a == nil {
		return chatGPTReservation{}, errors.New("account unavailable")
	}
	a.mu.Lock()
	identity := chatGPTPhysicalLocked(a)
	a.mu.Unlock()
	if identity == "" {
		return chatGPTReservation{}, errors.New("account identity unavailable")
	}
	for _, r := range g.pool.chatGPTReservations {
		if r.Alias == alias && (r.PrincipalID != principal || r.Identity != identity) {
			return chatGPTReservation{}, errors.New("reservation owner or physical account cannot change")
		}
		if r.Alias != alias && (r.PrincipalID == principal || r.Identity == identity) {
			return chatGPTReservation{}, errors.New("reservation collision")
		}
	}
	version, err := chatGPTRandomID()
	if err != nil {
		return chatGPTReservation{}, err
	}
	r := chatGPTReservation{Alias: alias, PrincipalID: principal, Identity: identity, Version: version, Enabled: enabled}
	raw, _ := json.Marshal(r)
	if err := g.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(chatGPTBucket)).Put([]byte("reservation:"+alias), raw)
	}); err != nil {
		return r, err
	}
	if g.pool.chatGPTReservations == nil {
		g.pool.chatGPTReservations = map[string]chatGPTReservation{}
	}
	g.pool.chatGPTReservations[alias] = r
	return r, nil
}

func (g *chatGPTGateway) reservation(principal string) (chatGPTReservation, bool) {
	g.pool.mu.RLock()
	defer g.pool.mu.RUnlock()
	for _, r := range g.pool.chatGPTReservations {
		if r.PrincipalID == principal {
			return r, r.Enabled
		}
	}
	return chatGPTReservation{}, false
}

func (g *chatGPTGateway) account(r chatGPTReservation, ip string) (*Account, string, string, string, error) {
	g.pool.mu.RLock()
	defer g.pool.mu.RUnlock()
	current, ok := g.pool.chatGPTReservations[r.Alias]
	if !ok || current != r || !current.Enabled {
		return nil, "", "", "", errors.New("reservation revoked")
	}
	a := g.pool.getLocked(r.Alias)
	if a == nil {
		return nil, "", "", "", errors.New("account unavailable")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if chatGPTPhysicalLocked(a) != r.Identity {
		return nil, "", "", "", errors.New("account identity changed")
	}
	if a.Disabled {
		return nil, "", "", "", errors.New("account disabled")
	}
	if a.Dead {
		return nil, "", "", "", errors.New("account authentication failed")
	}
	if a.RateLimitUntil.After(time.Now()) {
		return nil, "", "", "", errors.New("account cooling down")
	}
	if !accountAllowsClientIPLocked(a, ip) {
		return nil, "", "", "", errors.New("account access denied")
	}
	if a.AccessToken == "" {
		return nil, "", "", "", errors.New("account authentication unavailable")
	}
	id := a.AccountID
	if id == "" {
		id = a.IDTokenChatGPTAccountID
	}
	user := a.ChatGPTUserID
	if user == "" {
		user = parseCodexClaims(a.IDToken).ChatGPTUserID
	}
	if user == "" {
		user = parseCodexClaims(a.AccessToken).ChatGPTUserID
	}
	return a, a.AccessToken, id, user, nil
}

func (g *chatGPTGateway) send(ctx context.Context, r chatGPTReservation, ip, method, path, query string, headers http.Header, body io.Reader) (*http.Response, error) {
	a, token, id, _, err := g.account(r, ip)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	expired := !a.ExpiresAt.IsZero() && !a.ExpiresAt.After(time.Now())
	a.mu.Unlock()
	if expired {
		if g.refresh == nil {
			return nil, errors.New("account authentication unavailable")
		}
		if err = g.refresh(ctx, a); err != nil {
			return nil, errors.New("account refresh failed")
		}
		_, token, id, _, err = g.account(r, ip)
		if err != nil {
			return nil, err
		}
	}
	u := *g.origin
	u.Path = path
	u.RawQuery = query
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	// Never merge client cookies, fingerprint headers, identity or routing overrides.
	for _, key := range []string{
		"Content-Type", "Accept", "Accept-Language", "Last-Event-ID", "User-Agent", "Originator",
		"OpenAI-Sentinel-Chat-Requirements-Prepare-Token", "OpenAI-Sentinel-Chat-Requirements-Token",
		"OpenAI-Sentinel-Proof-Token", "OpenAI-Sentinel-Token", "OpenAI-Sentinel-Turnstile-Token",
		"X-Conduit-Token", "X-Oai-Turn-Trace-Id",
	} {
		if value := headers.Get(key); value != "" {
			req.Header.Set(key, value)
		}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("ChatGPT-Account-ID", id)
	resp, err := g.transport.RoundTrip(req)
	if err != nil {
		return nil, errors.New("ChatGPT upstream unavailable")
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		resp.Body.Close()
		return nil, errors.New("ChatGPT redirect refused")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		if g.refresh == nil || g.refresh(ctx, a) != nil {
			return nil, errors.New("account authentication failed")
		}
		if _, _, _, _, err = g.account(r, ip); err != nil {
			return nil, err
		}
		// Do not replay arbitrary mutations: the owner can retry with refreshed credentials.
		return nil, errors.New("account refreshed; retry request")
	}
	return resp, nil
}

// The account check is the entitlement authority, not the credential's plan claim.
func (g *chatGPTGateway) membership(ctx context.Context, r chatGPTReservation, ip string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, _, accountID, userID, err := g.account(r, ip)
	if err != nil {
		return nil, err
	}
	resp, err := g.send(ctx, r, ip, http.MethodGet, "/backend-api/accounts/check/v4-2023-04-27", "", nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("ChatGPT membership verification failed")
	}
	var result struct {
		Accounts map[string]struct {
			Account struct {
				AccountID string `json:"account_id"`
				PlanType  string `json:"plan_type"`
				TBOConfig struct {
					Available bool `json:"tbo_available"`
				} `json:"tbo_config"`
			} `json:"account"`
		} `json:"accounts"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&result); err != nil {
		return nil, errors.New("invalid ChatGPT membership response")
	}
	member, ok := result.Accounts[accountID]
	if !ok || member.Account.AccountID != accountID || member.Account.PlanType == "" {
		return nil, errors.New("ChatGPT membership unavailable")
	}
	if member.Account.PlanType != "pro" && member.Account.PlanType != "promax" {
		return nil, errors.New("ChatGPT Pro membership required")
	}
	if _, _, _, _, err = g.account(r, ip); err != nil {
		return nil, err
	}
	return map[string]any{"account_id": accountID, "user_id": userID, "plan_type": member.Account.PlanType, "capabilities": map[string]bool{"dots": member.Account.TBOConfig.Available}}, nil
}

func (g *chatGPTGateway) mint(s chatGPTSession, metadata map[string]any) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	raw, _ := json.Marshal(map[string]any{"iss": g.issuer, "aud": chatGPTPrefix, "sub": s.PrincipalID, "sid": s.ID, "iat": time.Now().Unix(), "exp": s.ExpiresAt.Unix(), "scope": "chatgpt:reserved", "chatgpt": metadata, "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": metadata["account_id"], "chatgpt_user_id": metadata["user_id"], "chatgpt_plan_type": metadata["plan_type"]}})
	payload := header + "." + base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, g.key)
	mac.Write([]byte(payload))
	token := payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	digest := sha256.Sum256([]byte(token))
	data, _ := json.Marshal(s)
	err := g.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(chatGPTBucket)).Put([]byte("session:"+hex.EncodeToString(digest[:])), data)
	})
	return token, err
}

func (g *chatGPTGateway) session(token string) (*chatGPTSession, error) {
	digest := sha256.Sum256([]byte(token))
	var s chatGPTSession
	err := g.db.View(func(tx *bbolt.Tx) error {
		raw := tx.Bucket([]byte(chatGPTBucket)).Get([]byte("session:" + hex.EncodeToString(digest[:])))
		if raw == nil {
			return errors.New("session unavailable")
		}
		return json.Unmarshal(raw, &s)
	})
	if err != nil {
		return nil, err
	}
	if !s.ExpiresAt.After(time.Now()) {
		return nil, errors.New("session expired")
	}
	return &s, nil
}

func chatGPTPath(r *http.Request) bool {
	if r.URL.RawPath != "" || strings.ContainsAny(r.URL.Path, "\\%\x00") || strings.Contains(r.URL.Path, "//") || r.URL.IsAbs() || r.URL.Host != "" {
		return false
	}
	for _, segment := range strings.Split(r.URL.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func (h *proxyHandler) handleChatGPT(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	g := h.chatGPT
	if g == nil || h.passport == nil {
		http.Error(w, "ChatGPT gateway unavailable", http.StatusServiceUnavailable)
		return
	}
	if !chatGPTPath(r) {
		http.Error(w, "invalid ChatGPT path", http.StatusBadRequest)
		return
	}
	if r.URL.Path == chatGPTPrefix+"/admin/reservation" {
		if !h.checkAdminAuth(w, r) {
			return
		}
		if h.cfg.adminToken == "" || r.Header.Get("X-Admin-Token") != h.cfg.adminToken {
			_, session := h.passport.authenticate(r)
			if session == nil || !h.passportCSRF(r, session) {
				http.Error(w, "csrf validation failed", http.StatusForbidden)
				return
			}
		}
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var input struct {
			Alias       string `json:"alias"`
			PrincipalID string `json:"principal_id"`
			Enabled     bool   `json:"enabled"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
		dec.DisallowUnknownFields()
		if dec.Decode(&input) != nil || input.Alias == "" || input.PrincipalID == "" {
			http.Error(w, "invalid reservation", http.StatusBadRequest)
			return
		}
		principal := h.passport.principal(input.PrincipalID)
		if principal == nil || principal.Status != PrincipalActive || principal.Kind == PrincipalGuest || (principal.ExpiresAt != nil && !principal.ExpiresAt.After(time.Now())) {
			http.Error(w, "active member required", http.StatusBadRequest)
			return
		}
		reservation, err := g.reserve(input.Alias, input.PrincipalID, input.Enabled)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		respondJSON(w, reservation)
		return
	}
	if r.URL.Path == chatGPTPrefix+"/identity" && r.Method == http.MethodGet {
		_, principal, _, _, allowed := h.authorizePoolCredentialRequest(r)
		if !allowed {
			http.Error(w, "live pool credential required", http.StatusUnauthorized)
			return
		}
		respondJSON(w, map[string]any{"principal_id": principal})
		return
	}
	if r.URL.Path == chatGPTPrefix+"/sessions" && r.Method == http.MethodPost {
		identity, principal, _, _, allowed := h.authorizePoolCredentialRequest(r)
		if !allowed {
			http.Error(w, "live pool credential required", http.StatusUnauthorized)
			return
		}
		reservation, ok := g.reservation(principal)
		if !ok {
			http.Error(w, "desktop reservation unavailable", http.StatusForbidden)
			return
		}
		metadata, err := g.membership(r.Context(), reservation, getClientIP(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		_, issued, _, ok := parsePoolCredentialRequest(r, getPoolJWTSecret())
		if !ok {
			http.Error(w, "live pool credential required", http.StatusUnauthorized)
			return
		}
		sessionID, err := chatGPTRandomID()
		if err != nil {
			http.Error(w, "session creation failed", http.StatusServiceUnavailable)
			return
		}
		s := chatGPTSession{ID: sessionID, Identity: identity, IssuedAt: issued, PrincipalID: principal, Reservation: reservation, ExpiresAt: time.Now().Add(chatGPTSessionTTL)}
		capabilities := metadata["capabilities"]
		delete(metadata, "capabilities")
		token, err := g.mint(s, metadata)
		if err != nil {
			http.Error(w, "session creation failed", http.StatusServiceUnavailable)
			return
		}
		respondJSON(w, map[string]any{"session_id": s.ID, "backend_api_base": g.issuer + chatGPTPrefix + "/backend-api", "metadata": metadata, "capabilities": capabilities, "delegation_token": token, "token_type": "Bearer", "expires_at": s.ExpiresAt, "issuer": g.issuer})
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s, err := g.session(token)
	if err != nil {
		http.Error(w, "valid desktop session required", http.StatusUnauthorized)
		return
	}
	principal, _, allowed := h.passport.authorizeIssuedCredential(s.Identity, s.IssuedAt)
	if !allowed || principal != s.PrincipalID {
		http.Error(w, "desktop authorization revoked", http.StatusUnauthorized)
		return
	}
	if _, _, _, _, err = g.account(s.Reservation, getClientIP(r)); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if r.URL.Path == chatGPTPrefix+"/sessions/"+s.ID && r.Method == http.MethodDelete {
		digest := sha256.Sum256([]byte(token))
		err = g.db.Update(func(tx *bbolt.Tx) error {
			return tx.Bucket([]byte(chatGPTBucket)).Delete([]byte("session:" + hex.EncodeToString(digest[:])))
		})
		if err != nil {
			http.Error(w, "session revocation failed", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !strings.HasPrefix(r.URL.Path, chatGPTPrefix+"/backend-api/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, _, expectedAccount, _, err := g.account(s.Reservation, getClientIP(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	for key := range r.Header {
		lower := strings.ToLower(key)
		if lower == "chatgpt-account-id" && len(r.Header.Values(key)) == 1 && r.Header.Get(key) == expectedAccount {
			continue
		}
		if strings.Contains(lower, "account") || strings.Contains(lower, "user-id") || lower == "x-api-key" || lower == "x-goog-api-key" || lower == "cookie" || strings.HasPrefix(lower, "x-openai-") {
			http.Error(w, "provider identity overrides refused", http.StatusBadRequest)
			return
		}
	}
	if r.Header.Get("Upgrade") != "" {
		http.Error(w, "ChatGPT websocket unsupported", http.StatusNotImplemented)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, chatGPTPrefix)
	for _, segment := range strings.Split(strings.ToLower(path), "/") {
		if segment == "auth" || segment == "token" || segment == "tokens" || segment == "oauth" {
			http.Error(w, "authentication routes refused", http.StatusForbidden)
			return
		}
	}
	for key := range r.URL.Query() {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "token") || strings.Contains(lower, "account") || lower == "key" || strings.Contains(lower, "user_id") {
			http.Error(w, "provider identity overrides refused", http.StatusBadRequest)
			return
		}
	}
	account, _, _, _, err := g.account(s.Reservation, getClientIP(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	account.mu.Lock()
	secrets := []string{account.AccessToken, account.RefreshToken, account.IDToken}
	account.mu.Unlock()
	resp, err := g.send(r.Context(), s.Reservation, getClientIP(r), r.Method, path, r.URL.RawQuery, r.Header, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	account.mu.Lock()
	secrets = append(secrets, account.AccessToken, account.RefreshToken, account.IDToken)
	account.mu.Unlock()
	if path == "/backend-api/wham/accounts/check" && resp.StatusCode == http.StatusOK {
		result, err := chatGPTRouting(resp.Body, expectedAccount)
		if err != nil {
			http.Error(w, "ChatGPT workspace membership unavailable", http.StatusServiceUnavailable)
			return
		}
		body, err := json.Marshal(result)
		if err != nil {
			http.Error(w, "ChatGPT workspace membership unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		copyChatGPT(w, strings.NewReader(string(body)), secrets)
		return
	}
	for _, key := range []string{"Content-Type", "Retry-After"} {
		if value := resp.Header.Get(key); value != "" {
			w.Header().Set(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	copyChatGPT(w, resp.Body, secrets)
}

// Redact literal provider credentials even across reads, retaining only a suffix
// that could complete a credential. Ordinary SSE events flush immediately.
func copyChatGPT(w http.ResponseWriter, body io.Reader, secrets []string) {
	buf := make([]byte, 32<<10)
	pending := ""
	for {
		n, readErr := body.Read(buf)
		pending += string(buf[:n])
		for _, secret := range secrets {
			if secret != "" {
				pending = strings.ReplaceAll(pending, secret, "[credential removed]")
			}
		}
		keep := 0
		if readErr == nil {
			for _, secret := range secrets {
				limit := len(secret) - 1
				if limit > len(pending) {
					limit = len(pending)
				}
				for length := limit; length > keep; length-- {
					if strings.HasSuffix(pending, secret[:length]) {
						keep = length
						break
					}
				}
			}
		}
		end := len(pending) - keep
		if end > 0 {
			if _, err := io.WriteString(w, pending[:end]); err != nil {
				return
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
		pending = pending[end:]
		if readErr != nil {
			return
		}
	}
}

// Native discovery must not return another workspace or an origin that routes
// around this reservation. Membership fields are copied from the live response;
// NO_CONSTRAINT keeps native requests on the configured pool backend base.
func chatGPTRouting(body io.Reader, accountID string) (map[string]any, error) {
	var result struct {
		Accounts []map[string]any `json:"accounts"`
	}
	if err := json.NewDecoder(io.LimitReader(body, 2<<20)).Decode(&result); err != nil {
		return nil, err
	}
	for _, account := range result.Accounts {
		if account["id"] != accountID {
			continue
		}
		seat, _ := account["account_user_id"].(string)
		plan, _ := account["plan_type"].(string)
		if seat == "" || plan == "" {
			return nil, errors.New("incomplete workspace membership")
		}
		account["workspace_backend_origin"] = "NO_CONSTRAINT"
		account["account_routing_override"] = "NO_CONSTRAINT"
		return map[string]any{"accounts": []map[string]any{account}, "default_account_id": accountID, "account_ordering": []string{accountID}}, nil
	}
	return nil, errors.New("reserved workspace membership unavailable")
}

func chatGPTRandomID() (string, error) {
	var value [24]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func chatGPTOrigins() (string, string) {
	origin := os.Getenv("CHATGPT_BACKEND_ORIGIN")
	if origin == "" {
		origin = "https://chatgpt.com"
	}
	issuer := os.Getenv("CHATGPT_POOL_ORIGIN")
	if issuer == "" {
		issuer = "https://codex.ppflix.net"
	}
	return origin, issuer
}
