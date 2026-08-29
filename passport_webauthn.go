package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"go.etcd.io/bbolt"
)

type storedWebAuthnCredential struct {
	ID          string    `json:"id"`
	PrincipalID string    `json:"principal_id"`
	Label       string    `json:"label"`
	Ciphertext  []byte    `json:"ciphertext"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsedAt  time.Time `json:"last_used_at,omitempty"`
}

type passkeyView struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type storedWebAuthnChallenge struct {
	ID          string         `json:"id"`
	PrincipalID string         `json:"principal_id,omitempty"`
	Purpose     string         `json:"purpose"`
	Session     wa.SessionData `json:"session"`
	ExpiresAt   time.Time      `json:"expires_at"`
}

type passportWebAuthnUser struct {
	principal   *Principal
	credentials []wa.Credential
}

func (u *passportWebAuthnUser) WebAuthnID() []byte   { return u.principal.WebAuthnUserID }
func (u *passportWebAuthnUser) WebAuthnName() string { return u.principal.Email }
func (u *passportWebAuthnUser) WebAuthnDisplayName() string {
	if u.principal.DisplayName != "" {
		return u.principal.DisplayName
	}
	return u.principal.Email
}
func (u *passportWebAuthnUser) WebAuthnCredentials() []wa.Credential { return u.credentials }

func (h *proxyHandler) webAuthnForRequest(r *http.Request) (*wa.WebAuthn, error) {
	origin := h.getEffectivePublicURL(r)
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Hostname() == "" {
		return nil, errors.New("invalid public URL for passkeys")
	}
	return wa.New(&wa.Config{
		RPID:          parsed.Hostname(),
		RPDisplayName: "Codex Pool",
		RPOrigins:     []string{parsed.Scheme + "://" + parsed.Host},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
	})
}

func (p *PassportStore) ensureWebAuthnUserID(principalID string) (*Principal, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	principal := p.principals[principalID]
	if principal == nil {
		return nil, errors.New("principal not found")
	}
	if len(principal.WebAuthnUserID) == 0 {
		handle := make([]byte, 32)
		if _, err := rand.Read(handle); err != nil {
			return nil, err
		}
		updated := *principal
		updated.WebAuthnUserID = handle
		if err := p.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx.Bucket([]byte(bucketPrincipals)), principalID, &updated) }); err != nil {
			return nil, err
		}
		p.principals[principalID] = &updated
		principal = &updated
	}
	copy := *principal
	copy.WebAuthnUserID = append([]byte(nil), principal.WebAuthnUserID...)
	return &copy, nil
}

func (p *PassportStore) webAuthnCredentials(principalID string) ([]wa.Credential, error) {
	credentials := []wa.Credential{}
	err := p.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketWebAuthnCredentials)).ForEach(func(_, value []byte) error {
			var record storedWebAuthnCredential
			if json.Unmarshal(value, &record) != nil || record.PrincipalID != principalID {
				return nil
			}
			plaintext, err := p.open("webauthn", record.ID, principalID, record.Ciphertext)
			if err != nil {
				return err
			}
			var credential wa.Credential
			if err := json.Unmarshal([]byte(plaintext), &credential); err != nil {
				return err
			}
			credentials = append(credentials, credential)
			return nil
		})
	})
	return credentials, err
}

func (p *PassportStore) webAuthnUser(principalID string) (*passportWebAuthnUser, error) {
	principal, err := p.ensureWebAuthnUserID(principalID)
	if err != nil {
		return nil, err
	}
	credentials, err := p.webAuthnCredentials(principalID)
	if err != nil {
		return nil, err
	}
	return &passportWebAuthnUser{principal: principal, credentials: credentials}, nil
}

func (p *PassportStore) saveWebAuthnCredential(principalID, label string, credential *wa.Credential) error {
	id := base64.RawURLEncoding.EncodeToString(credential.ID)
	encoded, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	ciphertext, err := p.seal("webauthn", id, principalID, string(encoded))
	if err != nil {
		return err
	}
	record := storedWebAuthnCredential{ID: id, PrincipalID: principalID, Label: strings.TrimSpace(label), Ciphertext: ciphertext, CreatedAt: time.Now().UTC()}
	return p.db.Update(func(tx *bbolt.Tx) error {
		if err := putJSON(tx.Bucket([]byte(bucketWebAuthnCredentials)), principalID+"|"+id, &record); err != nil {
			return err
		}
		return p.audit(tx, principalID, "passkey.added", principalID, record.Label)
	})
}

func (p *PassportStore) updateWebAuthnCredential(principalID string, credential *wa.Credential) error {
	id := base64.RawURLEncoding.EncodeToString(credential.ID)
	key := principalID + "|" + id
	var record storedWebAuthnCredential
	if err := p.db.View(func(tx *bbolt.Tx) error {
		value := tx.Bucket([]byte(bucketWebAuthnCredentials)).Get([]byte(key))
		if value == nil {
			return errors.New("passkey not found")
		}
		return json.Unmarshal(value, &record)
	}); err != nil {
		return err
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	record.Ciphertext, err = p.seal("webauthn", id, principalID, string(encoded))
	if err != nil {
		return err
	}
	record.LastUsedAt = time.Now().UTC()
	return p.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx.Bucket([]byte(bucketWebAuthnCredentials)), key, &record) })
}

func (p *PassportStore) saveWebAuthnChallenge(principalID, purpose string, session *wa.SessionData) (string, error) {
	id, err := secureToken(18)
	if err != nil {
		return "", err
	}
	record := storedWebAuthnChallenge{ID: id, PrincipalID: principalID, Purpose: purpose, Session: *session, ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}
	err = p.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx.Bucket([]byte(bucketWebAuthnChallenges)), id, &record) })
	return id, err
}

func (p *PassportStore) takeWebAuthnChallenge(id, purpose string) (*storedWebAuthnChallenge, error) {
	var record storedWebAuthnChallenge
	err := p.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketWebAuthnChallenges))
		value := bucket.Get([]byte(id))
		if value == nil {
			return errors.New("passkey challenge unavailable")
		}
		if err := json.Unmarshal(value, &record); err != nil {
			return err
		}
		return bucket.Delete([]byte(id))
	})
	if err != nil || (purpose != "" && record.Purpose != purpose) || time.Now().After(record.ExpiresAt) {
		return nil, errors.New("passkey challenge unavailable")
	}
	return &record, nil
}

func (p *PassportStore) discoverableWebAuthnUser(rawID, userHandle []byte) (wa.User, error) {
	p.mu.RLock()
	principalIDs := make([]string, 0, len(p.principals))
	for id, principal := range p.principals {
		if len(principal.WebAuthnUserID) == len(userHandle) && subtle.ConstantTimeCompare(principal.WebAuthnUserID, userHandle) == 1 {
			principalIDs = append(principalIDs, id)
		}
	}
	p.mu.RUnlock()
	for _, principalID := range principalIDs {
		user, err := p.webAuthnUser(principalID)
		if err != nil {
			continue
		}
		for _, credential := range user.credentials {
			if bytes.Equal(credential.ID, rawID) {
				return user, nil
			}
		}
	}
	return nil, errors.New("passkey not found")
}

func (p *PassportStore) passkeys(principalID string) ([]passkeyView, error) {
	views := []passkeyView{}
	err := p.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketWebAuthnCredentials)).ForEach(func(_, value []byte) error {
			var record storedWebAuthnCredential
			if json.Unmarshal(value, &record) == nil && record.PrincipalID == principalID {
				view := passkeyView{ID: record.ID, Label: record.Label, CreatedAt: record.CreatedAt}
				if !record.LastUsedAt.IsZero() {
					lastUsed := record.LastUsedAt
					view.LastUsedAt = &lastUsed
				}
				views = append(views, view)
			}
			return nil
		})
	})
	return views, err
}

func (p *PassportStore) deletePasskey(principalID, id string) error {
	key := principalID + "|" + id
	return p.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketWebAuthnCredentials))
		value := bucket.Get([]byte(key))
		if value == nil {
			return errors.New("passkey not found")
		}
		var record storedWebAuthnCredential
		if json.Unmarshal(value, &record) != nil || record.PrincipalID != principalID {
			return errors.New("passkey not found")
		}
		if err := bucket.Delete([]byte(key)); err != nil {
			return err
		}
		return p.audit(tx, principalID, "passkey.removed", principalID, record.Label)
	})
}

func (h *proxyHandler) handlePasskeys(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	principal, session := h.passport.authenticate(r)
	if principal == nil || principal.Kind == PrincipalGuest {
		respondJSONError(w, http.StatusForbidden, "member access required")
		return
	}
	if r.URL.Path == "/api/me/passkeys" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		views, err := h.passport.passkeys(principal.ID)
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, "passkeys unavailable")
			return
		}
		respondJSON(w, views)
		return
	}
	if r.Method != http.MethodDelete || !h.passportCSRF(r, session) {
		respondJSONError(w, http.StatusForbidden, "csrf validation failed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/me/passkeys/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	if err := h.passport.deletePasskey(principal.ID, id); err != nil {
		respondJSONError(w, http.StatusNotFound, "passkey not found")
		return
	}
	respondJSON(w, map[string]bool{"success": true})
}

func (h *proxyHandler) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	principal, session := h.passport.authenticate(r)
	if principal == nil || principal.Kind == PrincipalGuest {
		respondJSONError(w, http.StatusForbidden, "member access required")
		return
	}
	if r.Method != http.MethodPost || !h.passportCSRF(r, session) {
		respondJSONError(w, http.StatusForbidden, "csrf validation failed")
		return
	}
	var input struct {
		Password string `json:"password"`
		Label    string `json:"label"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil || !verifyPassword(principal.PasswordHash, input.Password) {
		respondJSONError(w, http.StatusUnauthorized, "fresh password verification required")
		return
	}
	web, err := h.webAuthnForRequest(r)
	if err != nil {
		respondJSONError(w, 500, err.Error())
		return
	}
	user, err := h.passport.webAuthnUser(principal.ID)
	if err != nil {
		respondJSONError(w, 500, "passkey unavailable")
		return
	}
	creation, data, err := web.BeginRegistration(user, wa.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired))
	if err != nil {
		respondJSONError(w, 500, "passkey unavailable")
		return
	}
	challengeID, err := h.passport.saveWebAuthnChallenge(principal.ID, "register|"+strings.TrimSpace(input.Label), data)
	if err != nil {
		respondJSONError(w, 500, "passkey unavailable")
		return
	}
	respondJSON(w, map[string]any{"challenge_id": challengeID, "options": creation.Response})
}

func (h *proxyHandler) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	principal, session := h.passport.authenticate(r)
	if principal == nil || principal.Kind == PrincipalGuest || !h.passportCSRF(r, session) {
		respondJSONError(w, http.StatusForbidden, "member access required")
		return
	}
	challenge, err := h.passport.takeWebAuthnChallenge(r.Header.Get("X-WebAuthn-Challenge"), "")
	if err != nil || challenge.PrincipalID != principal.ID || !strings.HasPrefix(challenge.Purpose, "register|") {
		respondJSONError(w, http.StatusBadRequest, "passkey challenge unavailable")
		return
	}
	web, err := h.webAuthnForRequest(r)
	if err != nil {
		respondJSONError(w, 500, "passkey unavailable")
		return
	}
	user, err := h.passport.webAuthnUser(principal.ID)
	if err != nil {
		respondJSONError(w, 500, "passkey unavailable")
		return
	}
	credential, err := web.FinishRegistration(user, challenge.Session, r)
	if err != nil {
		respondJSONError(w, http.StatusBadRequest, "passkey registration failed")
		return
	}
	label := strings.TrimPrefix(challenge.Purpose, "register|")
	if err := h.passport.saveWebAuthnCredential(principal.ID, label, credential); err != nil {
		respondJSONError(w, 500, "passkey store failed")
		return
	}
	respondJSON(w, map[string]any{"success": true})
}

func (h *proxyHandler) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	web, err := h.webAuthnForRequest(r)
	if err != nil {
		respondJSONError(w, 500, "passkey unavailable")
		return
	}
	assertion, data, err := web.BeginDiscoverableLogin(wa.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		respondJSONError(w, 500, "passkey unavailable")
		return
	}
	challengeID, err := h.passport.saveWebAuthnChallenge("", "login", data)
	if err != nil {
		respondJSONError(w, 500, "passkey unavailable")
		return
	}
	respondJSON(w, map[string]any{"challenge_id": challengeID, "options": assertion.Response})
}

func (h *proxyHandler) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	challenge, err := h.passport.takeWebAuthnChallenge(r.Header.Get("X-WebAuthn-Challenge"), "login")
	if err != nil {
		respondJSONError(w, http.StatusBadRequest, "passkey challenge unavailable")
		return
	}
	web, err := h.webAuthnForRequest(r)
	if err != nil {
		respondJSONError(w, 500, "passkey unavailable")
		return
	}
	user, credential, err := web.FinishPasskeyLogin(h.passport.discoverableWebAuthnUser, challenge.Session, r)
	if err != nil {
		respondJSONError(w, http.StatusUnauthorized, "passkey sign-in failed")
		return
	}
	passportUser, ok := user.(*passportWebAuthnUser)
	if !ok || passportUser.principal.Status != PrincipalActive {
		respondJSONError(w, http.StatusUnauthorized, "passkey sign-in failed")
		return
	}
	if err := h.passport.updateWebAuthnCredential(passportUser.principal.ID, credential); err != nil {
		respondJSONError(w, 500, "passkey store failed")
		return
	}
	token, csrf, err := h.passport.createSession(passportUser.principal.ID)
	if err != nil {
		respondJSONError(w, 500, "session unavailable")
		return
	}
	setSessionCookies(w, token, csrf)
	respondJSON(w, map[string]any{"principal": publicPrincipal(passportUser.principal), "csrf": csrf})
}
