package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

// A release can replay a paired backup without opening or changing the live DB.
func TestReleaseCredentialReplay(t *testing.T) {
	var passport *PassportStore
	if source := os.Getenv("POOL_RELEASE_REPLAY_DB"); source != "" {
		if configPath := os.Getenv("POOL_RELEASE_REPLAY_CONFIG"); configPath != "" {
			config, err := loadConfigFile(configPath)
			if err != nil {
				t.Fatal("release configuration cannot be loaded")
			}
			previous := globalConfigFile
			globalConfigFile = config
			t.Cleanup(func() { globalConfigFile = previous })
		}
		copyPath := filepath.Join(t.TempDir(), "proxy.db")
		if err := copyFile(source, copyPath, 0o600); err != nil {
			t.Fatal(err)
		}
		db, err := bbolt.Open(copyPath, 0o600, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		passport, err = newPassportStore(db, nil)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		t.Setenv("POOL_AUTH_ENCRYPTION_KEY", "release-fixture-key")
		var err error
		passport, err = newPassportStore(testUsageStore(t).db, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, err := passport.createGuest("operator", "Release fixture", "Release", nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(passport.clients) == 0 {
		t.Fatal("no credentials to replay")
	}
	active := 0
	for _, client := range passport.clients {
		token, err := passport.clientDownloadToken(client)
		if err != nil {
			t.Fatal("stored client credential cannot be decrypted")
		}
		matched := passport.clientByDownloadToken(token)
		if matched == nil || matched.ID != client.ID || matched.PrincipalID != client.PrincipalID {
			t.Fatal("stored client credential no longer matches its digest")
		}
		principal := passport.principal(client.PrincipalID)
		if principal == nil {
			t.Fatal("credential lost its principal")
		}
		now := time.Now()
		want := principal.Status == PrincipalActive && client.Status == "active" &&
			(principal.ExpiresAt == nil || !now.After(*principal.ExpiresAt)) &&
			(client.ExpiresAt == nil || !now.After(*client.ExpiresAt))
		_, _, allowed := passport.authorizeCredential(principal.ID + "-c-" + client.ID)
		if allowed != want {
			t.Fatal("credential authority changed across release")
		}
		if allowed {
			active++
		}
	}
	t.Logf("replayed %d stored client credentials; %d active, %d denied", len(passport.clients), active, len(passport.clients)-active)
}
