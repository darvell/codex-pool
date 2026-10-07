package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const codexRefreshTimeout = 30 * time.Second

var (
	codexFileGates  sync.Map
	errCodexStale   = errors.New("Codex credentials changed; retry with the current account")
	errCodexBlocked = errors.New("Codex refresh token is blocked; reconnect the account")
)

type codexRefreshGuard struct {
	TokenHash string    `json:"token_hash"`
	AttemptAt time.Time `json:"attempt_at"`
	Blocked   bool      `json:"blocked"`
}

// All Codex file writers share this boundary. The refresh keeps it through
// rotation, so a cookie/model save cannot restore the credential it consumed.
func lockCodexFile(ctx context.Context, path string) (func(), error) {
	if path == "" {
		return nil, errors.New("Codex account has no credential file")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	gate := make(chan struct{}, 1)
	value, _ := codexFileGates.LoadOrStore(key, gate)
	gate = value.(chan struct{})
	select {
	case gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-gate
			return nil, err
		}
		return func() { <-gate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func writeCodexFile(path string, root map[string]any) error {
	if err := atomicWriteJSON(path, root); err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	err = file.Sync()
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func codexTokenHash(tokens *TokenData) string {
	if tokens == nil {
		return ""
	}
	encoded, _ := json.Marshal(tokens)
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:])
}

func readCodexFile(path string) (map[string]any, CodexAuthJSON, error) {
	var auth CodexAuthJSON
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, auth, err
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, auth, fmt.Errorf("parse Codex credential file: %w", err)
	}
	if err := json.Unmarshal(raw, &auth); err != nil || auth.Tokens == nil {
		return nil, auth, errors.New("invalid Codex credential file")
	}
	return root, auth, nil
}

func applyCodexGuard(a *Account, auth CodexAuthJSON) {
	a.codexTokenHash = codexTokenHash(auth.Tokens)
	a.codexLoadedDead, a.codexLoadedDisabled = auth.Dead, auth.Disabled
	a.RefreshBlocked = false
	a.refreshAttemptAt = time.Time{}
	if guard := auth.RefreshGuard; guard != nil && guard.TokenHash == a.codexTokenHash {
		a.RefreshBlocked = guard.Blocked
		a.refreshAttemptAt = guard.AttemptAt
	}
}

func codexFileMatches(a *Account, auth CodexAuthJSON) bool {
	if a.codexTokenHash != "" {
		return a.codexTokenHash == codexTokenHash(auth.Tokens)
	}
	if auth.Tokens == nil || a.AccessToken != auth.Tokens.AccessToken || a.RefreshToken != auth.Tokens.RefreshToken || a.IDToken != auth.Tokens.IDToken {
		return false
	}
	accountID := parseCodexClaims(auth.Tokens.IDToken).ChatGPTAccountID
	if auth.Tokens.AccountID != nil {
		accountID = *auth.Tokens.AccountID
	}
	if a.AccountID != accountID {
		return false
	}
	a.codexTokenHash = codexTokenHash(auth.Tokens)
	return true
}

func adoptCodexAuth(a *Account, auth CodexAuthJSON) error {
	raw, err := json.Marshal(auth)
	if err != nil {
		return err
	}
	loaded, err := (&CodexProvider{}).LoadAccount(a.ID+".json", a.File, raw)
	if err != nil || loaded == nil {
		return errors.New("invalid Codex credential file")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if auth.Dead || auth.Disabled || a.AccountID != loaded.AccountID || a.ChatGPTUserID != loaded.ChatGPTUserID {
		return errCodexStale
	}
	a.AccessToken, a.RefreshToken, a.IDToken = loaded.AccessToken, loaded.RefreshToken, loaded.IDToken
	a.ExpiresAt, a.LastRefresh = loaded.ExpiresAt, loaded.LastRefresh
	a.PlanType, a.IDTokenChatGPTAccountID = loaded.PlanType, loaded.IDTokenChatGPTAccountID
	applyCodexGuard(a, auth)
	return nil
}

func syncCodexAuth(a *Account) error {
	ctx, cancel := context.WithTimeout(context.Background(), codexRefreshTimeout)
	defer cancel()
	unlock, err := lockCodexFile(ctx, a.File)
	if err != nil {
		return err
	}
	defer unlock()
	_, auth, err := readCodexFile(a.File)
	if err != nil {
		return err
	}
	return adoptCodexAuth(a, auth)
}
