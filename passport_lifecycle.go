package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

func nextCredentialCutoff(now time.Time) time.Time {
	return time.Unix(now.UTC().Unix()+1, 0).UTC()
}

func (p *PassportStore) rotateClientSecret(c *ClientCredential) error {
	token, err := secureToken(24)
	if err != nil {
		return err
	}
	digest := hashToken(token)
	ciphertext, err := p.seal("client", c.ID, c.PrincipalID, token)
	if err != nil {
		return err
	}
	c.DownloadDigest = hex.EncodeToString(digest[:])
	c.DownloadCiphertext = ciphertext
	c.DownloadToken = token
	return nil
}

func deletePrincipalSessions(tx *bbolt.Tx, principalID string) error {
	bucket := tx.Bucket([]byte(bucketPassportSessions))
	var keys [][]byte
	if err := bucket.ForEach(func(k, v []byte) error {
		var session passportSession
		if json.Unmarshal(v, &session) == nil && session.PrincipalID == principalID {
			keys = append(keys, append([]byte(nil), k...))
		}
		return nil
	}); err != nil {
		return err
	}
	for _, key := range keys {
		if err := bucket.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

func (p *PassportStore) setPrincipalStatus(actorID, principalID string, status PrincipalStatus) (*Principal, error) {
	if status != PrincipalActive && status != PrincipalSuspended {
		return nil, errors.New("status must be active or suspended")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	current := p.principals[principalID]
	if current == nil {
		return nil, errors.New("principal not found")
	}
	if current.Kind == PrincipalOperator && status != PrincipalActive {
		return nil, errors.New("operator cannot be suspended")
	}
	if current.Status == status {
		cp := *current
		return &cp, nil
	}

	updated := *current
	updated.Status = status
	clientUpdates := make(map[string]*ClientCredential)
	if status == PrincipalSuspended {
		cutoff := nextCredentialCutoff(time.Now())
		updated.CredentialsValidAfter = cutoff
		for id, existing := range p.clients {
			if existing.PrincipalID != principalID || existing.Status != "active" {
				continue
			}
			client := *existing
			client.ValidAfter = cutoff
			if err := p.rotateClientSecret(&client); err != nil {
				return nil, err
			}
			clientUpdates[id] = &client
		}
	}

	err := p.db.Update(func(tx *bbolt.Tx) error {
		if err := putJSON(tx.Bucket([]byte(bucketPrincipals)), principalID, &updated); err != nil {
			return err
		}
		for id, client := range clientUpdates {
			if err := putJSON(tx.Bucket([]byte(bucketClientCredentials)), id, client); err != nil {
				return err
			}
		}
		if status == PrincipalSuspended {
			if err := deletePrincipalSessions(tx, principalID); err != nil {
				return err
			}
		}
		return p.audit(tx, actorID, "principal.status_changed", principalID, string(current.Status)+" -> "+string(status))
	})
	if err != nil {
		return nil, err
	}
	p.principals[principalID] = &updated
	for id, client := range clientUpdates {
		p.clients[id] = client
	}
	cp := updated
	return &cp, nil
}

// setPrincipalKind changes a principal's role. Promoting keeps sessions;
// removing the operator role drops them so the demotion takes effect
// immediately. The last operator cannot be demoted.
func (p *PassportStore) setPrincipalKind(actorID, principalID string, kind PrincipalKind) (*Principal, error) {
	if kind != PrincipalOperator && kind != PrincipalMember && kind != PrincipalGuest {
		return nil, errors.New("kind must be operator, member, or guest")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	current := p.principals[principalID]
	if current == nil {
		return nil, errors.New("principal not found")
	}
	if current.Kind == kind {
		cp := *current
		return &cp, nil
	}
	if current.Kind == PrincipalOperator {
		operators := 0
		for _, other := range p.principals {
			if other.Kind == PrincipalOperator {
				operators++
			}
		}
		if operators < 2 {
			return nil, errors.New("cannot demote the last operator")
		}
	}

	updated := *current
	updated.Kind = kind
	demoteOperator := current.Kind == PrincipalOperator
	err := p.db.Update(func(tx *bbolt.Tx) error {
		if err := putJSON(tx.Bucket([]byte(bucketPrincipals)), principalID, &updated); err != nil {
			return err
		}
		if demoteOperator {
			if err := deletePrincipalSessions(tx, principalID); err != nil {
				return err
			}
		}
		return p.audit(tx, actorID, "principal.kind_changed", principalID, string(current.Kind)+" -> "+string(kind))
	})
	if err != nil {
		return nil, err
	}
	p.principals[principalID] = &updated
	cp := updated
	return &cp, nil
}

func (p *PassportStore) rotateClient(actorID, principalID, clientID string) (*ClientCredential, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	current := p.clients[clientID]
	if current == nil || current.PrincipalID != principalID {
		return nil, errors.New("client credential not found")
	}
	updated := *current
	updated.Status = "active"
	updated.ValidAfter = nextCredentialCutoff(time.Now())
	if err := p.rotateClientSecret(&updated); err != nil {
		return nil, err
	}
	err := p.db.Update(func(tx *bbolt.Tx) error {
		if err := putJSON(tx.Bucket([]byte(bucketClientCredentials)), clientID, &updated); err != nil {
			return err
		}
		return p.audit(tx, actorID, "client.rotated", clientID, updated.Label)
	})
	if err != nil {
		return nil, err
	}
	p.clients[clientID] = &updated
	cp := updated
	return &cp, nil
}

func (p *PassportStore) revokeClient(actorID, principalID, clientID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	current := p.clients[clientID]
	if current == nil || current.PrincipalID != principalID {
		return errors.New("client credential not found")
	}
	if current.Status == "revoked" {
		return nil
	}
	updated := *current
	updated.Status = "revoked"
	updated.ValidAfter = nextCredentialCutoff(time.Now())
	if err := p.rotateClientSecret(&updated); err != nil {
		return err
	}
	updated.DownloadToken = ""
	err := p.db.Update(func(tx *bbolt.Tx) error {
		if err := putJSON(tx.Bucket([]byte(bucketClientCredentials)), clientID, &updated); err != nil {
			return err
		}
		return p.audit(tx, actorID, "client.revoked", clientID, updated.Label)
	})
	if err != nil {
		return err
	}
	p.clients[clientID] = &updated
	return nil
}

func (p *PassportStore) joinLinkForPrincipal(principalID string) (*JoinLink, error) {
	var found *JoinLink
	err := p.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketJoinLinks)).ForEach(func(_, value []byte) error {
			var link JoinLink
			if json.Unmarshal(value, &link) == nil && link.PrincipalID == principalID {
				copy := link
				found = &copy
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, errors.New("guest pass not found")
	}
	return found, nil
}

func (p *PassportStore) updateGuestPass(actorID, principalID, note, displayName string, expiresAt *time.Time) (*Principal, error) {
	note = strings.TrimSpace(note)
	if note == "" || len([]rune(note)) > 300 {
		return nil, errors.New("note required (max 300 characters)")
	}
	if len([]rune(strings.TrimSpace(displayName))) > 48 {
		return nil, errors.New("display name must be 48 characters or fewer")
	}
	link, err := p.joinLinkForPrincipal(principalID)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	current := p.principals[principalID]
	if current == nil || current.Kind != PrincipalGuest {
		return nil, errors.New("guest pass not found")
	}
	updated := *current
	updated.Note = note
	updated.DisplayName = strings.TrimSpace(displayName)
	updated.ExpiresAt = expiresAt
	link.ExpiresAt = expiresAt
	clientUpdates := make(map[string]*ClientCredential)
	for id, existing := range p.clients {
		if existing.PrincipalID == principalID {
			client := *existing
			client.ExpiresAt = expiresAt
			clientUpdates[id] = &client
		}
	}
	err = p.db.Update(func(tx *bbolt.Tx) error {
		if err := putJSON(tx.Bucket([]byte(bucketPrincipals)), principalID, &updated); err != nil {
			return err
		}
		if err := putJSON(tx.Bucket([]byte(bucketJoinLinks)), link.ID, link); err != nil {
			return err
		}
		for id, client := range clientUpdates {
			if err := putJSON(tx.Bucket([]byte(bucketClientCredentials)), id, client); err != nil {
				return err
			}
		}
		return p.audit(tx, actorID, "guest.updated", principalID, note)
	})
	if err != nil {
		return nil, err
	}
	p.principals[principalID] = &updated
	for id, client := range clientUpdates {
		p.clients[id] = client
	}
	cp := updated
	return &cp, nil
}

func (p *PassportStore) setGuestPassStatus(actorID, principalID string, active bool) (*Principal, error) {
	link, err := p.joinLinkForPrincipal(principalID)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	current := p.principals[principalID]
	if current == nil || current.Kind != PrincipalGuest {
		return nil, errors.New("guest pass not found")
	}
	updated := *current
	clientUpdates := make(map[string]*ClientCredential)
	action := "guest.restored"
	if active {
		if updated.ExpiresAt != nil && time.Now().After(*updated.ExpiresAt) {
			return nil, errors.New("set a future expiry or remove expiry before restoring")
		}
		updated.Status = PrincipalActive
		link.Revoked = false
	} else {
		action = "guest.revoked"
		updated.Status = PrincipalSuspended
		link.Revoked = true
		cutoff := nextCredentialCutoff(time.Now())
		updated.CredentialsValidAfter = cutoff
		for id, existing := range p.clients {
			if existing.PrincipalID != principalID || existing.Status != "active" {
				continue
			}
			client := *existing
			client.ValidAfter = cutoff
			if err := p.rotateClientSecret(&client); err != nil {
				return nil, err
			}
			clientUpdates[id] = &client
		}
	}
	err = p.db.Update(func(tx *bbolt.Tx) error {
		if err := putJSON(tx.Bucket([]byte(bucketPrincipals)), principalID, &updated); err != nil {
			return err
		}
		if err := putJSON(tx.Bucket([]byte(bucketJoinLinks)), link.ID, link); err != nil {
			return err
		}
		for id, client := range clientUpdates {
			if err := putJSON(tx.Bucket([]byte(bucketClientCredentials)), id, client); err != nil {
				return err
			}
		}
		if !active {
			if err := deletePrincipalSessions(tx, principalID); err != nil {
				return err
			}
		}
		return p.audit(tx, actorID, action, principalID, updated.Note)
	})
	if err != nil {
		return nil, err
	}
	p.principals[principalID] = &updated
	for id, client := range clientUpdates {
		p.clients[id] = client
	}
	cp := updated
	return &cp, nil
}

func (p *PassportStore) rotateGuestLink(actorID, principalID string) (string, error) {
	link, err := p.joinLinkForPrincipal(principalID)
	if err != nil {
		return "", err
	}
	token, err := secureToken(32)
	if err != nil {
		return "", err
	}
	digest := hashToken(token)
	link.TokenDigest = hex.EncodeToString(digest[:])
	link.TokenCiphertext, err = p.seal("join", link.ID, principalID, token)
	if err != nil {
		return "", err
	}
	if err = p.db.Update(func(tx *bbolt.Tx) error {
		if err := putJSON(tx.Bucket([]byte(bucketJoinLinks)), link.ID, link); err != nil {
			return err
		}
		return p.audit(tx, actorID, "guest.link_rotated", principalID, "")
	}); err != nil {
		return "", err
	}
	return token, nil
}

func (h *proxyHandler) requireOperator(w http.ResponseWriter, r *http.Request) (*Principal, *passportSession, bool) {
	pr, session := h.passport.authenticate(r)
	if pr == nil || pr.Kind != PrincipalOperator {
		respondJSONError(w, http.StatusForbidden, "operator access required")
		return nil, nil, false
	}
	return pr, session, true
}

func (h *proxyHandler) handlePassportClientItem(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	principal, session := h.passport.authenticate(r)
	if principal == nil {
		respondJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !h.passportCSRF(r, session) {
		respondJSONError(w, http.StatusForbidden, "csrf validation failed")
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/me/clients/"), "/")
	clientID, action, _ := strings.Cut(path, "/")
	if clientID == "" {
		http.NotFound(w, r)
		return
	}
	switch {
	case r.Method == http.MethodPost && action == "rotate":
		client, err := h.passport.rotateClient(principal.ID, principal.ID, clientID)
		if err != nil {
			respondJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		respondJSON(w, map[string]any{"id": client.ID, "label": client.Label, "expires_at": client.ExpiresAt, "setup_token": client.DownloadToken})
	case r.Method == http.MethodPost && action == "reveal":
		h.passport.mu.RLock()
		stored := h.passport.clients[clientID]
		var client *ClientCredential
		if stored != nil {
			copy := *stored
			client = &copy
		}
		h.passport.mu.RUnlock()
		if client == nil || client.PrincipalID != principal.ID || client.Status != "active" {
			respondJSONError(w, http.StatusNotFound, "client credential not found")
			return
		}
		token, err := h.passport.clientDownloadToken(client)
		if err != nil {
			respondJSONError(w, 500, "setup token unavailable")
			return
		}
		respondJSON(w, map[string]any{"setup_token": token})
	case r.Method == http.MethodDelete && action == "":
		if err := h.passport.revokeClient(principal.ID, principal.ID, clientID); err != nil {
			respondJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		respondJSON(w, map[string]any{"success": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *proxyHandler) handlePassItem(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	actor, session, ok := h.requireMember(w, r)
	if !ok {
		return
	}
	if !h.passportCSRF(r, session) {
		respondJSONError(w, http.StatusForbidden, "csrf validation failed")
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/passes/"), "/")
	principalID, action, _ := strings.Cut(path, "/")
	if principalID == "" {
		http.NotFound(w, r)
		return
	}
	switch {
	case r.Method == http.MethodPatch && action == "":
		var input struct {
			Note        string     `json:"note"`
			DisplayName string     `json:"display_name"`
			ExpiresAt   *time.Time `json:"expires_at"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			respondJSONError(w, http.StatusBadRequest, "invalid json")
			return
		}
		principal, err := h.passport.updateGuestPass(actor.ID, principalID, input.Note, input.DisplayName, input.ExpiresAt)
		if err != nil {
			respondJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		respondJSON(w, publicPrincipal(principal))
	case r.Method == http.MethodDelete && action == "":
		if _, err := h.passport.setGuestPassStatus(actor.ID, principalID, false); err != nil {
			respondJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		respondJSON(w, map[string]any{"success": true})
	case r.Method == http.MethodPost && action == "restore":
		principal, err := h.passport.setGuestPassStatus(actor.ID, principalID, true)
		if err != nil {
			respondJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		respondJSON(w, publicPrincipal(principal))
	case r.Method == http.MethodPost && action == "rotate":
		token, err := h.passport.rotateGuestLink(actor.ID, principalID)
		if err != nil {
			respondJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		respondJSON(w, map[string]any{"link": "/join#" + token})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *proxyHandler) handlePrincipalItem(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	actor, session, ok := h.requireOperator(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.passportCSRF(r, session) {
		respondJSONError(w, http.StatusForbidden, "csrf validation failed")
		return
	}
	principalID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/principals/"), "/")
	if principalID == "" || strings.Contains(principalID, "/") {
		http.NotFound(w, r)
		return
	}
	var input struct {
		Status *PrincipalStatus `json:"status"`
		Kind   *PrincipalKind   `json:"kind"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		respondJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	// Accept a username or email in place of the principal ID.
	if h.passport.principal(principalID) == nil {
		if found := h.passport.byLogin(principalID); found != nil {
			principalID = found.ID
		}
	}
	principal := h.passport.principal(principalID)
	if principal == nil {
		respondJSONError(w, http.StatusNotFound, "principal not found")
		return
	}
	if input.Status != nil {
		var err error
		principal, err = h.passport.setPrincipalStatus(actor.ID, principalID, *input.Status)
		if err != nil {
			respondJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if input.Kind != nil {
		var err error
		principal, err = h.passport.setPrincipalKind(actor.ID, principalID, *input.Kind)
		if err != nil {
			respondJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	respondJSON(w, publicPrincipal(principal))
}
