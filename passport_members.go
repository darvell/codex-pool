package main

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

const bucketMemberRecoveryLinks = "member_recovery_links"

type memberRecoveryLink struct {
	ID          string    `json:"id"`
	PrincipalID string    `json:"principal_id"`
	Purpose     string    `json:"purpose"`
	TokenDigest string    `json:"token_digest"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type memberLinkResult struct {
	Principal *Principal
	Token     string
	ExpiresAt time.Time
}

func copyPrincipal(principal *Principal) *Principal {
	if principal == nil {
		return nil
	}
	copy := *principal
	copy.WebAuthnUserID = append([]byte(nil), principal.WebAuthnUserID...)
	return &copy
}

func normalizeUsername(value string) (string, error) {
	username := strings.ToLower(strings.TrimSpace(value))
	if len(username) < 3 || len(username) > 32 {
		return "", errors.New("username must be 3 to 32 characters")
	}
	for _, char := range username {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '_' || char == '-' || char == '.' {
			continue
		}
		return "", errors.New("username may use letters, numbers, dots, dashes, and underscores")
	}
	return username, nil
}

func normalizeMemberEmail(value string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(value))
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || !strings.Contains(email, "@") {
		return "", errors.New("valid member email required")
	}
	return email, nil
}

func (p *PassportStore) createMemberLink(actorID, email, displayName, purpose string) (*memberLinkResult, error) {
	email, err := normalizeMemberEmail(email)
	if err != nil {
		return nil, err
	}
	if purpose != "onboard" && purpose != "recover" {
		return nil, errors.New("invalid member link purpose")
	}

	principal := p.byEmail(email)
	if purpose == "onboard" {
		if principal != nil {
			return nil, errors.New("an account already uses that email")
		}
		id, err := secureID(12)
		if err != nil {
			return nil, err
		}
		principal = &Principal{
			ID: id, Kind: PrincipalMember, Status: PrincipalActive,
			DisplayName: strings.TrimSpace(displayName), Email: email,
			Note: "member", CreatedAt: time.Now().UTC(),
		}
	} else if principal == nil || (principal.Kind != PrincipalMember && principal.Kind != PrincipalOperator) {
		return nil, errors.New("member not found")
	}

	id, err := secureID(9)
	if err != nil {
		return nil, err
	}
	token, err := secureToken(32)
	if err != nil {
		return nil, err
	}
	digest := hashToken(token)
	now := time.Now().UTC()
	link := memberRecoveryLink{
		ID: id, PrincipalID: principal.ID, Purpose: purpose,
		TokenDigest: hex.EncodeToString(digest[:]), CreatedBy: actorID,
		CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute),
	}

	err = p.db.Update(func(tx *bbolt.Tx) error {
		if purpose == "onboard" {
			if err := putJSON(tx.Bucket([]byte(bucketPrincipals)), principal.ID, principal); err != nil {
				return err
			}
		}
		if err := putJSON(tx.Bucket([]byte(bucketMemberRecoveryLinks)), link.ID, &link); err != nil {
			return err
		}
		action := "member.onboarding_link_created"
		if purpose == "recover" {
			action = "member.recovery_link_created"
		}
		return p.audit(tx, actorID, action, principal.ID, email)
	})
	if err != nil {
		return nil, err
	}
	if purpose == "onboard" {
		p.mu.Lock()
		p.principals[principal.ID] = principal
		p.mu.Unlock()
	}
	return &memberLinkResult{Principal: copyPrincipal(principal), Token: token, ExpiresAt: link.ExpiresAt}, nil
}

func (p *PassportStore) redeemMemberLink(token, password string) (*Principal, string, string, error) {
	if len(password) < 12 {
		return nil, "", "", errors.New("password must be at least 12 characters")
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		return nil, "", "", err
	}
	digest := hashToken(strings.TrimSpace(token))
	var principal Principal
	var link memberRecoveryLink
	now := time.Now().UTC()
	err = p.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketMemberRecoveryLinks))
		var matchedKey []byte
		if err := bucket.ForEach(func(key, value []byte) error {
			var candidate memberRecoveryLink
			if json.Unmarshal(value, &candidate) != nil {
				return nil
			}
			stored, decodeErr := hex.DecodeString(candidate.TokenDigest)
			if decodeErr == nil && len(stored) == len(digest) && subtle.ConstantTimeCompare(stored, digest[:]) == 1 {
				link = candidate
				matchedKey = append([]byte(nil), key...)
			}
			return nil
		}); err != nil {
			return err
		}
		if matchedKey == nil || now.After(link.ExpiresAt) {
			return errors.New("member link unavailable")
		}
		value := tx.Bucket([]byte(bucketPrincipals)).Get([]byte(link.PrincipalID))
		if value == nil || json.Unmarshal(value, &principal) != nil || principal.Status != PrincipalActive {
			return errors.New("member link unavailable")
		}
		principal.PasswordHash = passwordHash
		if err := putJSON(tx.Bucket([]byte(bucketPrincipals)), principal.ID, &principal); err != nil {
			return err
		}
		if err := deletePrincipalSessions(tx, principal.ID); err != nil {
			return err
		}
		if err := bucket.Delete(matchedKey); err != nil {
			return err
		}
		return p.audit(tx, principal.ID, "member.password_set", principal.ID, link.Purpose)
	})
	if err != nil {
		return nil, "", "", err
	}
	p.mu.Lock()
	p.principals[principal.ID] = &principal
	p.mu.Unlock()
	sessionToken, csrf, err := p.createSession(principal.ID)
	if err != nil {
		return nil, "", "", err
	}
	return copyPrincipal(&principal), sessionToken, csrf, nil
}

func (p *PassportStore) hasOperator() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, principal := range p.principals {
		if principal.Kind == PrincipalOperator {
			return true
		}
	}
	return false
}

func (p *PassportStore) bootstrapOperator(username, email, displayName, password, legacyCredential string) (*Principal, error) {
	if p.hasOperator() {
		return nil, errors.New("operator already exists")
	}
	if username == "" {
		username = "operator"
	}
	username, err := normalizeUsername(username)
	if err != nil {
		return nil, err
	}
	if p.byLogin(username) != nil {
		return nil, errors.New("username is already taken")
	}
	if len(password) < 12 {
		return nil, errors.New("password must be at least 12 characters")
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}

	var principal *Principal
	if token := strings.TrimSpace(legacyCredential); token != "" {
		identity, issuedAt, ok := parseClaudePoolCredential(getPoolJWTSecret(), token)
		if !ok {
			return nil, errors.New("legacy credential is invalid")
		}
		principalID, _, allowed := p.authorizeIssuedCredential(identity, issuedAt)
		if !allowed {
			return nil, errors.New("legacy credential is no longer active")
		}
		principal = p.principal(principalID)
	}
	if principal == nil {
		id, err := secureID(12)
		if err != nil {
			return nil, err
		}
		principal = &Principal{ID: id, Status: PrincipalActive, CreatedAt: time.Now().UTC()}
	}
	updated := *principal
	updated.Kind = PrincipalOperator
	updated.Status = PrincipalActive
	updated.Note = "operator"
	updated.Username = username
	updated.Email = strings.ToLower(strings.TrimSpace(email))
	updated.DisplayName = strings.TrimSpace(displayName)
	updated.PasswordHash = passwordHash
	if updated.DisplayName == "" {
		updated.DisplayName = username
	}
	if err := p.db.Update(func(tx *bbolt.Tx) error {
		if err := putJSON(tx.Bucket([]byte(bucketPrincipals)), updated.ID, &updated); err != nil {
			return err
		}
		return p.audit(tx, updated.ID, "operator.bootstrapped", updated.ID, username)
	}); err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.principals[updated.ID] = &updated
	p.mu.Unlock()
	return copyPrincipal(&updated), nil
}

func (p *PassportStore) claimLegacyAccount(username, password, downloadToken string) (*Principal, string, string, error) {
	username, err := normalizeUsername(username)
	if err != nil {
		return nil, "", "", err
	}
	if len(password) < 12 {
		return nil, "", "", errors.New("password must be at least 12 characters")
	}
	if p.byLogin(username) != nil {
		return nil, "", "", errors.New("username is already taken")
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		return nil, "", "", err
	}

	var principal *Principal
	if client := p.clientByDownloadToken(strings.TrimSpace(downloadToken)); client != nil {
		principal = p.principal(client.PrincipalID)
	}
	if principal == nil {
		id, err := secureID(12)
		if err != nil {
			return nil, "", "", err
		}
		principal = &Principal{ID: id, Kind: PrincipalMember, Status: PrincipalActive, Note: "legacy-code signup", CreatedAt: time.Now().UTC()}
	}
	updated := *principal
	// First legacy signup becomes operator if none exists yet.
	if !p.hasOperator() {
		updated.Kind = PrincipalOperator
	} else {
		updated.Kind = PrincipalMember
	}
	updated.Username = username
	if updated.DisplayName == "" {
		updated.DisplayName = username
	}
	updated.PasswordHash = passwordHash
	updated.Status = PrincipalActive
	if err := p.db.Update(func(tx *bbolt.Tx) error {
		if err := putJSON(tx.Bucket([]byte(bucketPrincipals)), updated.ID, &updated); err != nil {
			return err
		}
		return p.audit(tx, updated.ID, "member.legacy_signup", updated.ID, username)
	}); err != nil {
		return nil, "", "", err
	}
	p.mu.Lock()
	p.principals[updated.ID] = &updated
	p.mu.Unlock()
	sessionToken, csrf, err := p.createSession(updated.ID)
	if err != nil {
		return nil, "", "", err
	}
	return copyPrincipal(&updated), sessionToken, csrf, nil
}

func memberLinkURL(h *proxyHandler, r *http.Request, token string) string {
	return strings.TrimRight(h.getEffectivePublicURL(r), "/") + "/recover#" + token
}

func (h *proxyHandler) handleLegacySignup(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		Code          string `json:"code"`
		Username      string `json:"username"`
		Password      string `json:"password"`
		DownloadToken string `json:"download_token"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&input) != nil {
		respondJSONError(w, http.StatusBadRequest, "invalid signup request")
		return
	}
	if h.cfg == nil || strings.TrimSpace(h.cfg.legacyFriendCode) == "" || hashToken(strings.TrimSpace(input.Code)) != hashToken(strings.TrimSpace(h.cfg.legacyFriendCode)) {
		h.metrics.incPassport("legacy_signups", "denied")
		respondJSONError(w, http.StatusUnauthorized, "pool code is incorrect")
		return
	}
	principal, sessionToken, csrf, err := h.passport.claimLegacyAccount(input.Username, input.Password, input.DownloadToken)
	if err != nil {
		h.metrics.incPassport("legacy_signups", "failed")
		respondJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.metrics.incPassport("legacy_signups", "succeeded")
	setSessionCookies(w, sessionToken, csrf)
	respondJSON(w, map[string]any{"principal": publicPrincipal(principal)})
}

func (h *proxyHandler) handleConsoleMembers(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	operator, session, ok := h.requireOperator(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost || !h.passportCSRF(r, session) {
		respondJSONError(w, http.StatusForbidden, "csrf validation failed")
		return
	}
	var input struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Purpose     string `json:"purpose"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		respondJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if input.Purpose == "" {
		input.Purpose = "onboard"
	}
	result, err := h.passport.createMemberLink(operator.ID, input.Email, input.DisplayName, input.Purpose)
	if err != nil {
		respondJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondJSON(w, map[string]any{
		"principal":  publicPrincipal(result.Principal),
		"link":       memberLinkURL(h, r, result.Token),
		"expires_at": result.ExpiresAt,
	})
}

func (h *proxyHandler) handleMemberRecovery(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&input) != nil {
		respondJSONError(w, http.StatusBadRequest, "This recovery link is unavailable.")
		return
	}
	principal, sessionToken, csrf, err := h.passport.redeemMemberLink(input.Token, input.Password)
	if err != nil {
		if strings.Contains(err.Error(), "at least 12") {
			respondJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		respondJSONError(w, http.StatusBadRequest, "This recovery link is unavailable.")
		return
	}
	setSessionCookies(w, sessionToken, csrf)
	respondJSON(w, map[string]any{"principal": publicPrincipal(principal)})
}
