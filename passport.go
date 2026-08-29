package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"go.etcd.io/bbolt"
	"golang.org/x/crypto/argon2"
)

const (
	bucketPrincipals        = "principals"
	bucketPassportSessions  = "passport_sessions"
	bucketClientCredentials = "client_credentials"
)

type PrincipalKind string
type PrincipalStatus string

const (
	PrincipalOperator  PrincipalKind   = "operator"
	PrincipalMember    PrincipalKind   = "member"
	PrincipalGuest     PrincipalKind   = "guest"
	PrincipalActive    PrincipalStatus = "active"
	PrincipalSuspended PrincipalStatus = "suspended"
)

type Principal struct {
	ID                    string          `json:"id"`
	Kind                  PrincipalKind   `json:"kind"`
	Status                PrincipalStatus `json:"status"`
	Note                  string          `json:"note"`
	DisplayName           string          `json:"display_name,omitempty"`
	Username              string          `json:"username,omitempty"`
	Email                 string          `json:"email,omitempty"`
	PasswordHash          string          `json:"password_hash,omitempty"`
	CredentialsValidAfter time.Time       `json:"credentials_valid_after,omitempty"`
	PlanType              string          `json:"plan_type,omitempty"`
	ExpiresAt             *time.Time      `json:"expires_at,omitempty"`
	CreatedBy             string          `json:"created_by,omitempty"`
	CreatedAt             time.Time       `json:"created_at"`
	LastSeenAt            time.Time       `json:"last_seen_at,omitempty"`
	AvatarUpdatedAt       *time.Time      `json:"avatar_updated_at,omitempty"`
	WebAuthnUserID        []byte          `json:"webauthn_user_id,omitempty"`
}

type ClientCredential struct {
	ID                 string     `json:"id"`
	PrincipalID        string     `json:"principal_id"`
	Label              string     `json:"label"`
	Status             string     `json:"status"`
	ValidAfter         time.Time  `json:"valid_after,omitempty"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
	DownloadDigest     string     `json:"download_digest"`
	DownloadCiphertext []byte     `json:"download_ciphertext"`
	DownloadToken      string     `json:"-"`
	CreatedAt          time.Time  `json:"created_at"`
	LastSeenAt         time.Time  `json:"last_seen_at,omitempty"`
}

type passportSession struct {
	PrincipalID string    `json:"principal_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	CSRFHash    [32]byte  `json:"csrf_hash"`
}

type PassportStore struct {
	db            *bbolt.DB
	mu            sync.RWMutex
	principals    map[string]*Principal
	clients       map[string]*ClientCredential
	passwordWork  chan struct{}
	aead          cipher.AEAD
	analyticsSalt string
}

func passportAEAD() (cipher.AEAD, error) {
	secret := os.Getenv("POOL_AUTH_ENCRYPTION_KEY")
	if secret == "" {
		secret = getPoolJWTSecret()
	}
	if secret == "" {
		return nil, errors.New("POOL_AUTH_ENCRYPTION_KEY or POOL_JWT_SECRET required")
	}
	key := sha256.Sum256([]byte("pool-passport-auth-v1|" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newPassportStore(db *bbolt.DB, legacy *PoolUserStore, legacyAnalyticsSalt ...string) (*PassportStore, error) {
	if db == nil {
		return nil, errors.New("passport requires bolt")
	}
	aead, err := passportAEAD()
	if err != nil {
		return nil, err
	}
	p := &PassportStore{db: db, principals: map[string]*Principal{}, clients: map[string]*ClientCredential{}, passwordWork: make(chan struct{}, 4), aead: aead}
	if err := db.Update(func(tx *bbolt.Tx) error {
		for _, n := range []string{bucketPrincipals, bucketPassportSessions, bucketClientCredentials, bucketPassportAvatars, bucketJoinLinks, bucketMemberRecoveryLinks, bucketPassportAudit, bucketWebAuthnCredentials, bucketWebAuthnChallenges} {
			if _, err := tx.CreateBucketIfNotExists([]byte(n)); err != nil {
				return err
			}
		}
		state := tx.Bucket([]byte(bucketAnalyticsState))
		if state == nil {
			return errors.New("analytics state bucket missing")
		}
		salt := string(state.Get([]byte("analytics_salt")))
		if salt == "" {
			if len(legacyAnalyticsSalt) > 0 {
				salt = strings.TrimSpace(legacyAnalyticsSalt[0])
			}
			if salt == "" {
				var err error
				salt, err = secureToken(32)
				if err != nil {
					return err
				}
			}
			if err := state.Put([]byte("analytics_salt"), []byte(salt)); err != nil {
				return err
			}
		}
		p.analyticsSalt = salt
		return nil
	}); err != nil {
		return nil, err
	}
	if err := p.load(); err != nil {
		return nil, err
	}
	if len(p.principals) == 0 && legacy != nil {
		if err := p.migrateLegacy(legacy.List()); err != nil {
			return nil, err
		}
		if err := p.load(); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *PassportStore) load() error {
	principals := map[string]*Principal{}
	clients := map[string]*ClientCredential{}
	err := p.db.View(func(tx *bbolt.Tx) error {
		if err := tx.Bucket([]byte(bucketPrincipals)).ForEach(func(_, v []byte) error {
			var x Principal
			if err := json.Unmarshal(v, &x); err != nil {
				return err
			}
			principals[x.ID] = &x
			return nil
		}); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketClientCredentials)).ForEach(func(_, v []byte) error {
			var x ClientCredential
			if err := json.Unmarshal(v, &x); err != nil {
				return err
			}
			clients[x.ID] = &x
			return nil
		})
	})
	if err == nil {
		p.mu.Lock()
		p.principals = principals
		p.clients = clients
		p.mu.Unlock()
	}
	return err
}

func (p *PassportStore) migrateLegacy(users []*PoolUser) error {
	now := time.Now().UTC()
	return p.db.Update(func(tx *bbolt.Tx) error {
		pb := tx.Bucket([]byte(bucketPrincipals))
		cb := tx.Bucket([]byte(bucketClientCredentials))
		for _, u := range users {
			status := PrincipalActive
			if u.Disabled {
				status = PrincipalSuspended
			}
			pr := Principal{ID: u.ID, Kind: PrincipalGuest, Status: status, Note: "legacy: " + u.Email, Email: u.Email, PlanType: u.PlanType, CreatedAt: u.CreatedAt}
			cl := ClientCredential{ID: "legacy-" + u.ID, PrincipalID: u.ID, Label: "LEGACY DEFAULT", Status: "active", CreatedAt: now}
			digest := hashToken(u.Token)
			cl.DownloadDigest = hex.EncodeToString(digest[:])
			sealed, err := p.seal("client", cl.ID, cl.PrincipalID, u.Token)
			if err != nil {
				return err
			}
			cl.DownloadCiphertext = sealed
			pv, _ := json.Marshal(pr)
			cv, _ := json.Marshal(cl)
			if err := pb.Put([]byte(pr.ID), pv); err != nil {
				return err
			}
			if err := cb.Put([]byte(cl.ID), cv); err != nil {
				return err
			}
		}
		return nil
	})
}

func (p *PassportStore) seal(kind, id, principalID, plaintext string) ([]byte, error) {
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := []byte(kind + "|" + id + "|" + principalID)
	return append(nonce, p.aead.Seal(nil, nonce, []byte(plaintext), aad)...), nil
}
func (p *PassportStore) open(kind, id, principalID string, ciphertext []byte) (string, error) {
	if len(ciphertext) < p.aead.NonceSize() {
		return "", errors.New("invalid ciphertext")
	}
	nonce, body := ciphertext[:p.aead.NonceSize()], ciphertext[p.aead.NonceSize():]
	plain, err := p.aead.Open(nil, nonce, body, []byte(kind+"|"+id+"|"+principalID))
	return string(plain), err
}

func secureToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func secureID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashToken(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}
func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func (p *PassportStore) principal(id string) *Principal {
	p.mu.RLock()
	defer p.mu.RUnlock()
	x := p.principals[id]
	if x == nil {
		return nil
	}
	cp := *x
	return &cp
}
func (p *PassportStore) byEmail(email string) *Principal {
	email = strings.ToLower(strings.TrimSpace(email))
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, x := range p.principals {
		if strings.ToLower(x.Email) == email {
			cp := *x
			return &cp
		}
	}
	return nil
}

func (p *PassportStore) markCredentialSeen(principalID, clientID string, now time.Time) {
	now = now.UTC()
	p.mu.RLock()
	principal := p.principals[principalID]
	client := p.clients[clientID]
	recent := principal != nil && client != nil && now.Sub(principal.LastSeenAt) < time.Minute && now.Sub(client.LastSeenAt) < time.Minute
	p.mu.RUnlock()
	if principal == nil || client == nil || recent {
		return
	}

	var persistedPrincipal Principal
	var persistedClient ClientCredential
	if p.db.Update(func(tx *bbolt.Tx) error {
		principalValue := tx.Bucket([]byte(bucketPrincipals)).Get([]byte(principalID))
		clientValue := tx.Bucket([]byte(bucketClientCredentials)).Get([]byte(clientID))
		if principalValue == nil || clientValue == nil || json.Unmarshal(principalValue, &persistedPrincipal) != nil || json.Unmarshal(clientValue, &persistedClient) != nil {
			return errors.New("credential identity unavailable")
		}
		persistedPrincipal.LastSeenAt = now
		persistedClient.LastSeenAt = now
		if err := putJSON(tx.Bucket([]byte(bucketPrincipals)), principalID, &persistedPrincipal); err != nil {
			return err
		}
		return putJSON(tx.Bucket([]byte(bucketClientCredentials)), clientID, &persistedClient)
	}) != nil {
		return
	}
	p.mu.Lock()
	p.principals[principalID] = &persistedPrincipal
	p.clients[clientID] = &persistedClient
	p.mu.Unlock()
}

func (p *PassportStore) byLogin(login string) *Principal {
	login = strings.ToLower(strings.TrimSpace(login))
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, principal := range p.principals {
		if strings.ToLower(principal.Username) == login || strings.ToLower(principal.Email) == login {
			copy := *principal
			return &copy
		}
	}
	return nil
}

func (p *PassportStore) createSession(principalID string) (token, csrf string, err error) {
	token, err = secureToken(32)
	if err != nil {
		return
	}
	csrf, err = secureToken(24)
	if err != nil {
		return
	}
	s := passportSession{PrincipalID: principalID, ExpiresAt: time.Now().Add(30 * 24 * time.Hour), CSRFHash: hashToken(csrf)}
	v, _ := json.Marshal(s)
	h := hashToken(token)
	err = p.db.Update(func(tx *bbolt.Tx) error { return tx.Bucket([]byte(bucketPassportSessions)).Put(h[:], v) })
	return
}
func (p *PassportStore) renewSession(w http.ResponseWriter, r *http.Request, session *passportSession) {
	if session == nil || time.Until(session.ExpiresAt) > 15*24*time.Hour {
		return
	}
	sessionCookie, err := r.Cookie("pool_session")
	if err != nil {
		return
	}
	csrfCookie, err := r.Cookie("pool_csrf")
	if err != nil || hashToken(csrfCookie.Value) != session.CSRFHash {
		return
	}
	updated := *session
	updated.ExpiresAt = time.Now().UTC().Add(30 * 24 * time.Hour)
	value, err := json.Marshal(updated)
	if err != nil {
		return
	}
	digest := hashToken(sessionCookie.Value)
	if p.db.Update(func(tx *bbolt.Tx) error { return tx.Bucket([]byte(bucketPassportSessions)).Put(digest[:], value) }) != nil {
		return
	}
	*session = updated
	setSessionCookies(w, sessionCookie.Value, csrfCookie.Value)
}

func (p *PassportStore) authenticate(r *http.Request) (*Principal, *passportSession) {
	c, err := r.Cookie("pool_session")
	if err != nil {
		return nil, nil
	}
	h := hashToken(c.Value)
	var s passportSession
	if p.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket([]byte(bucketPassportSessions)).Get(h[:])
		if v == nil {
			return errors.New("missing")
		}
		return json.Unmarshal(v, &s)
	}) != nil || time.Now().After(s.ExpiresAt) {
		return nil, nil
	}
	pr := p.principal(s.PrincipalID)
	if pr == nil || pr.Status != PrincipalActive || (pr.ExpiresAt != nil && time.Now().After(*pr.ExpiresAt)) {
		return nil, nil
	}
	return pr, &s
}
func setSessionCookies(w http.ResponseWriter, token, csrf string) {
	http.SetCookie(w, &http.Cookie{Name: "pool_session", Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: 30 * 86400})
	http.SetCookie(w, &http.Cookie{Name: "pool_csrf", Value: csrf, Path: "/", Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: 30 * 86400})
}

func (p *PassportStore) login(email, password string) (*Principal, string, string, error) {
	select {
	case p.passwordWork <- struct{}{}:
		defer func() { <-p.passwordWork }()
	default:
		return nil, "", "", errors.New("password verification busy")
	}
	pr := p.byLogin(email)
	encoded := "$argon2id$v=19$m=65536,t=3,p=4$MDAwMDAwMDAwMDAwMDAwMA$XGlzLL5oqnlF1hNkoqRj3uiKgA4+J5l+6bV9rQ"
	if pr != nil {
		encoded = pr.PasswordHash
	}
	ok := verifyPassword(encoded, password)
	if !ok || pr == nil || pr.Kind == PrincipalGuest {
		return nil, "", "", errors.New("invalid credentials")
	}
	t, c, e := p.createSession(pr.ID)
	return pr, t, c, e
}

func splitClientIdentity(identity string) (string, string) {
	if principal, client, ok := strings.Cut(identity, "-c-"); ok && principal != "" && client != "" {
		return principal, client
	}
	return identity, "legacy-" + identity
}

func (p *PassportStore) credentialState(identity string) (*Principal, *ClientCredential, bool) {
	principalID, clientID := splitClientIdentity(identity)
	pr := p.principal(principalID)
	if pr == nil || pr.Status != PrincipalActive || (pr.ExpiresAt != nil && time.Now().After(*pr.ExpiresAt)) {
		return nil, nil, false
	}
	p.mu.RLock()
	client := p.clients[clientID]
	if client != nil {
		cp := *client
		client = &cp
	}
	p.mu.RUnlock()
	if client == nil || client.PrincipalID != principalID || client.Status != "active" || (client.ExpiresAt != nil && time.Now().After(*client.ExpiresAt)) {
		return nil, nil, false
	}
	return pr, client, true
}

func (p *PassportStore) authorizeCredential(identity string) (string, string, bool) {
	pr, client, ok := p.credentialState(identity)
	if !ok {
		return "", "", false
	}
	return pr.ID, client.ID, true
}

func (p *PassportStore) authorizeIssuedCredential(identity string, issuedAt time.Time) (string, string, bool) {
	pr, client, ok := p.credentialState(identity)
	if !ok || issuedAt.IsZero() {
		return "", "", false
	}
	issuedUnix := issuedAt.Unix()
	if (!pr.CredentialsValidAfter.IsZero() && issuedUnix < pr.CredentialsValidAfter.Unix()) ||
		(!client.ValidAfter.IsZero() && issuedUnix < client.ValidAfter.Unix()) {
		return "", "", false
	}
	return pr.ID, client.ID, true
}

func (p *PassportStore) authorizeLegacyRefresh(identity string) (string, string, bool) {
	pr, client, ok := p.credentialState(identity)
	if !ok || !pr.CredentialsValidAfter.IsZero() || !client.ValidAfter.IsZero() {
		return "", "", false
	}
	return pr.ID, client.ID, true
}

func (p *PassportStore) clientByDownloadToken(token string) *ClientCredential {
	digest := hashToken(token)
	want := hex.EncodeToString(digest[:])
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, c := range p.clients {
		if subtle.ConstantTimeCompare([]byte(c.DownloadDigest), []byte(want)) == 1 {
			cp := *c
			cp.DownloadToken = token
			return &cp
		}
	}
	return nil
}
func (p *PassportStore) clientDownloadToken(c *ClientCredential) (string, error) {
	if c.DownloadToken != "" {
		return c.DownloadToken, nil
	}
	return p.open("client", c.ID, c.PrincipalID, c.DownloadCiphertext)
}

func (p *PassportStore) createClient(principalID, label string, expires *time.Time) (*ClientCredential, error) {
	label = strings.TrimSpace(label)
	if label == "" || len([]rune(label)) > 80 {
		return nil, errors.New("label required (max 80 characters)")
	}
	p.mu.RLock()
	n := 0
	for _, c := range p.clients {
		if c.PrincipalID == principalID && c.Status == "active" {
			n++
		}
	}
	p.mu.RUnlock()
	if n >= 20 {
		return nil, errors.New("client credential limit reached")
	}
	idRaw, err := secureID(9)
	if err != nil {
		return nil, err
	}
	dl, err := secureToken(24)
	if err != nil {
		return nil, err
	}
	c := &ClientCredential{ID: idRaw, PrincipalID: principalID, Label: label, Status: "active", ExpiresAt: expires, DownloadToken: dl, CreatedAt: time.Now().UTC()}
	digest := hashToken(dl)
	c.DownloadDigest = hex.EncodeToString(digest[:])
	sealed, err := p.seal("client", c.ID, c.PrincipalID, dl)
	if err != nil {
		return nil, err
	}
	c.DownloadCiphertext = sealed
	v, _ := json.Marshal(c)
	if err = p.db.Update(func(tx *bbolt.Tx) error { return tx.Bucket([]byte(bucketClientCredentials)).Put([]byte(c.ID), v) }); err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.clients[c.ID] = c
	p.mu.Unlock()
	return c, nil
}

func encodeSequence(n uint64) []byte { var b [8]byte; binary.BigEndian.PutUint64(b[:], n); return b[:] }
func (h *proxyHandler) originHashSalt() string {
	if h != nil && h.passport != nil && h.passport.analyticsSalt != "" {
		return h.passport.analyticsSalt
	}
	if h != nil && h.cfg != nil {
		return poolHashSalt(h.cfg.legacyFriendCode)
	}
	return poolHashSalt("")
}

func tokenFingerprint(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}
