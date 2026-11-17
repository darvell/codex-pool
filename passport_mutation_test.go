package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"sync"
	"testing"

	"go.etcd.io/bbolt"
)

func TestPassportCommitRollsBackPublication(t *testing.T) {
	p, operator := testPassportWithOperator(t)
	before := p.principal(operator.ID)
	updated := *before
	updated.DisplayName = "Changed"
	failure := errors.New("audit unavailable")
	p.mu.Lock()
	err := p.commitLocked(&updated, nil, func(tx *bbolt.Tx) error {
		if err := putJSON(tx.Bucket([]byte(bucketPrincipals)), operator.ID, &updated); err != nil {
			return err
		}
		return failure
	})
	p.mu.Unlock()
	if !errors.Is(err, failure) {
		t.Fatalf("commit error=%v", err)
	}
	if got := p.principal(operator.ID); got.DisplayName != before.DisplayName {
		t.Fatalf("failed commit published nickname=%q", got.DisplayName)
	}
	if err := p.db.View(func(tx *bbolt.Tx) error {
		var stored Principal
		if err := json.Unmarshal(tx.Bucket([]byte(bucketPrincipals)).Get([]byte(operator.ID)), &stored); err != nil {
			return err
		}
		if stored.DisplayName != before.DisplayName {
			t.Fatalf("failed commit persisted nickname=%q", stored.DisplayName)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPassportProfileFailureKeepsCache(t *testing.T) {
	p, operator := testPassportWithOperator(t)
	before := p.principal(operator.ID)
	var avatar bytes.Buffer
	if err := png.Encode(&avatar, image.NewRGBA(image.Rect(0, 0, 32, 32))); err != nil {
		t.Fatal(err)
	}
	if err := p.db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.updateNickname(operator.ID, "Changed"); err == nil {
		t.Fatal("nickname accepted with a closed database")
	}
	if _, err := p.saveAvatar(operator.ID, avatar.Bytes()); err == nil {
		t.Fatal("avatar accepted with a closed database")
	}
	got := p.principal(operator.ID)
	if got.DisplayName != before.DisplayName || got.AvatarUpdatedAt != before.AvatarUpdatedAt {
		t.Fatalf("failed profile write changed cached principal: %+v", got)
	}
}

func TestConcurrentMemberOnboarding(t *testing.T) {
	p, operator := testPassportWithOperator(t)
	var work sync.WaitGroup
	results := make(chan error, 6)
	for range 6 {
		work.Add(1)
		go func() {
			defer work.Done()
			_, err := p.createMemberLink(operator.ID, "same@example.com", "Member", "onboard")
			results <- err
		}()
	}
	work.Wait()
	close(results)
	created := 0
	for err := range results {
		if err == nil {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("created %d principals for the same email", created)
	}
}

func TestConcurrentClientLimit(t *testing.T) {
	p, operator := testPassportWithOperator(t)
	var work sync.WaitGroup
	results := make(chan error, 24)
	for range 24 {
		work.Add(1)
		go func() {
			defer work.Done()
			_, err := p.createClient(operator.ID, "Client", nil)
			results <- err
		}()
	}
	work.Wait()
	close(results)
	created := 0
	for err := range results {
		if err == nil {
			created++
		}
	}
	// The guest used to create this operator already has a default credential.
	if created != 19 {
		t.Fatalf("created %d clients, want 19 remaining slots", created)
	}
}

func TestPassportProfilePersists(t *testing.T) {
	p, operator := testPassportWithOperator(t)
	var raw bytes.Buffer
	if err := png.Encode(&raw, image.NewRGBA(image.Rect(0, 0, 32, 32))); err != nil {
		t.Fatal(err)
	}
	avatar, err := p.saveAvatar(operator.ID, raw.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.updateNickname(operator.ID, " New name "); err != nil {
		t.Fatal(err)
	}
	reloaded, err := newPassportStore(p.db, nil, passportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	principal := reloaded.principal(operator.ID)
	storedAvatar, err := reloaded.avatar(operator.ID)
	if err != nil {
		t.Fatal(err)
	}
	if principal.DisplayName != "New name" || principal.AvatarUpdatedAt == nil || !principal.AvatarUpdatedAt.Equal(avatar.UpdatedAt) || storedAvatar.ETag != avatar.ETag || !bytes.Equal(storedAvatar.PNG, avatar.PNG) {
		t.Fatalf("profile did not persist: principal=%+v avatar=%+v", principal, storedAvatar)
	}
}
