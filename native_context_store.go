package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"go.etcd.io/bbolt"
)

const (
	bucketContextSessions   = "native_context_sessions"
	bucketContextSettings   = "native_context_settings"
	bucketContextPrincipals = "native_context_principals"
	contextKeyName          = "envelope_key"
	contextKeySize          = 32
	contextParticipantLimit = 32
	contextEnvelopeLimit    = 64 << 20
	contextEnvelopePrefix   = "codex-pool-context-v1:"
)

type contextAccount struct {
	Alias    string `json:"alias"`
	Identity string `json:"identity"`
}

type contextSession struct {
	Owner        contextAccount   `json:"owner"`
	Participants []contextAccount `json:"participants"`
}

type contextResult struct {
	Account contextAccount  `json:"account"`
	Value   json.RawMessage `json:"value"`
}

type savedContextSession struct {
	contextSession
	// Remember renamed aliases even when their physical identity was deduplicated.
	Aliases map[string]string `json:"aliases"`
}

type nativeContextStore struct {
	db   *bbolt.DB
	aead cipher.AEAD
}

func newNativeContextStore(db *bbolt.DB) (*nativeContextStore, error) {
	if db == nil {
		return nil, errors.New("native context store requires a database")
	}

	var key []byte
	// One transaction makes concurrent constructors share the same persistent key.
	err := db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketContextSessions)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketContextPrincipals)); err != nil {
			return err
		}
		settings, err := tx.CreateBucketIfNotExists([]byte(bucketContextSettings))
		if err != nil {
			return err
		}
		stored := settings.Get([]byte(contextKeyName))
		if stored != nil {
			if len(stored) != contextKeySize {
				return errors.New("invalid native context envelope key")
			}
			key = append([]byte(nil), stored...)
			return nil
		}

		key = make([]byte, contextKeySize)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		return settings.Put([]byte(contextKeyName), key)
	})
	if err != nil {
		return nil, fmt.Errorf("initialize native context store: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &nativeContextStore{db: db, aead: aead}, nil
}

func contextTuple(scope, session string) ([]byte, error) {
	// JSON replaces invalid UTF-8, which could otherwise collapse distinct keys.
	if !utf8.ValidString(scope) || !utf8.ValidString(session) {
		return nil, errors.New("native context scope and session must be valid UTF-8")
	}
	return json.Marshal([2]string{scope, session})
}

func (s *nativeContextStore) claim(scope, session string) error {
	if scope == "" || session == "" || !utf8.ValidString(scope) || !utf8.ValidString(session) {
		return errors.New("invalid context principal or session")
	}
	// The backend sees only session_id, so local tuple keys alone cannot isolate pool users.
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketContextPrincipals))
		owner := bucket.Get([]byte(session))
		if owner != nil {
			if string(owner) != scope {
				return errors.New("context session belongs to another principal")
			}
			return nil
		}
		return bucket.Put([]byte(session), []byte(scope))
	})
}

func (s *nativeContextStore) lookup(scope, session string) (*contextSession, error) {
	key, err := contextTuple(scope, session)
	if err != nil {
		return nil, err
	}
	var result *contextSession
	err = s.db.View(func(tx *bbolt.Tx) error {
		data := tx.Bucket([]byte(bucketContextSessions)).Get(key)
		if data == nil {
			return nil
		}
		result = new(contextSession)
		return json.Unmarshal(data, result)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *nativeContextStore) record(scope, session string, account contextAccount) (*contextSession, error) {
	key, err := contextTuple(scope, session)
	if err != nil {
		return nil, err
	}
	var saved savedContextSession
	err = s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketContextSessions))
		data := bucket.Get(key)
		if data == nil {
			saved.Owner = account
			saved.Aliases = make(map[string]string)
		} else if err := json.Unmarshal(data, &saved); err != nil {
			return err
		}

		if identity, found := saved.Aliases[account.Alias]; found && identity != account.Identity {
			return errors.New("native context account alias changed identity")
		}
		known := false
		for _, participant := range saved.Participants {
			if participant.Identity == account.Identity {
				known = true
				break
			}
		}
		if !known {
			if len(saved.Participants) >= contextParticipantLimit {
				return errors.New("native context participant limit exceeded")
			}
			saved.Participants = append(saved.Participants, account)
		}
		if saved.Aliases == nil {
			return errors.New("native context session has no alias bindings")
		}
		saved.Aliases[account.Alias] = account.Identity

		encoded, err := json.Marshal(saved)
		if err != nil {
			return err
		}
		return bucket.Put(key, encoded)
	})
	if err != nil {
		return nil, err
	}
	return &saved.contextSession, nil
}

func (s *nativeContextStore) pack(scope, session string, sources []contextResult) (string, error) {
	tuple, err := contextTuple(scope, session)
	if err != nil {
		return "", err
	}
	remaining := contextEnvelopeLimit
	for _, source := range sources {
		if len(source.Value) > remaining {
			return "", errors.New("native context envelope limit exceeded")
		}
		remaining -= len(source.Value)
	}
	plaintext, err := json.Marshal(sources)
	if err != nil {
		return "", err
	}
	if len(plaintext) > contextEnvelopeLimit {
		return "", errors.New("native context envelope limit exceeded")
	}

	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	aad := append([]byte(contextEnvelopePrefix), tuple...)
	payload := s.aead.Seal(nonce, nonce, plaintext, aad)
	return contextEnvelopePrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func (s *nativeContextStore) unpack(scope, session, encoded string) ([]contextResult, error) {
	tuple, err := contextTuple(scope, session)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(encoded, contextEnvelopePrefix) {
		return nil, errors.New("invalid native context envelope version")
	}
	body := strings.TrimPrefix(encoded, contextEnvelopePrefix)
	maxPayload := contextEnvelopeLimit + s.aead.NonceSize() + s.aead.Overhead()
	// Bound the encoded input before base64 allocates a decoded buffer.
	if len(body) > base64.RawURLEncoding.EncodedLen(maxPayload) {
		return nil, errors.New("native context envelope limit exceeded")
	}
	if strings.ContainsAny(body, "\r\n") {
		return nil, errors.New("invalid native context envelope encoding")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("decode native context envelope: %w", err)
	}
	if len(payload) < s.aead.NonceSize()+s.aead.Overhead() {
		return nil, errors.New("native context envelope is truncated")
	}
	aad := append([]byte(contextEnvelopePrefix), tuple...)
	nonce := payload[:s.aead.NonceSize()]
	plaintext, err := s.aead.Open(nil, nonce, payload[s.aead.NonceSize():], aad)
	if err != nil {
		return nil, fmt.Errorf("authenticate native context envelope: %w", err)
	}
	var sources []contextResult
	if err := json.Unmarshal(plaintext, &sources); err != nil {
		return nil, fmt.Errorf("decode native context results: %w", err)
	}
	return sources, nil
}
