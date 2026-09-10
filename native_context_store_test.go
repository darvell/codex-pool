package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"go.etcd.io/bbolt"
)

func openContextDB(t *testing.T, path string) *bbolt.DB {
	t.Helper()
	db, err := bbolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func testContextStore(t *testing.T) *nativeContextStore {
	t.Helper()
	db := openContextDB(t, filepath.Join(t.TempDir(), "shared.db"))
	s, err := newNativeContextStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNativeContextNilDB(t *testing.T) {
	if s, err := newNativeContextStore(nil); err == nil || s != nil {
		t.Fatalf("nil DB: store=%v err=%v", s, err)
	}
}

func TestNativeContextDBFailures(t *testing.T) {
	db := openContextDB(t, filepath.Join(t.TempDir(), "shared.db"))
	if err := db.Update(func(tx *bbolt.Tx) error {
		settings, err := tx.CreateBucket([]byte(bucketContextSettings))
		if err != nil {
			return err
		}
		return settings.Put([]byte(contextKeyName), []byte("corrupt"))
	}); err != nil {
		t.Fatal(err)
	}
	if store, err := newNativeContextStore(db); err == nil || store != nil {
		t.Fatalf("accepted corrupt persistent key: store=%v err=%v", store, err)
	}
	if err := db.View(func(tx *bbolt.Tx) error {
		if tx.Bucket([]byte(bucketContextSessions)) != nil {
			t.Error("failed initialization did not roll back session bucket")
		}
		key := tx.Bucket([]byte(bucketContextSettings)).Get([]byte(contextKeyName))
		if string(key) != "corrupt" {
			t.Error("failed initialization replaced persistent key")
		}
		return nil
	}); err != nil {
		t.Fatalf("constructor closed shared database: %v", err)
	}

	s := testContextStore(t)
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.lookup("scope", "session"); err == nil {
		t.Fatal("lookup hid closed database error")
	}
	if _, err := s.record("scope", "session", contextAccount{}); err == nil {
		t.Fatal("record hid closed database error")
	}
	if _, err := newNativeContextStore(s.db); err == nil {
		t.Fatal("constructor hid closed database error")
	}
}

func TestNativeContextRecords(t *testing.T) {
	s := testContextStore(t)
	if got, err := s.lookup("scope", "session"); err != nil || got != nil {
		t.Fatalf("missing session: got=%v err=%v", got, err)
	}
	owner := contextAccount{Alias: "first", Identity: "physical-a"}
	second := contextAccount{Alias: "second", Identity: "physical-b"}
	for _, account := range []contextAccount{owner, second, owner, {Alias: "renamed", Identity: owner.Identity}} {
		got, err := s.record("scope", "session", account)
		if err != nil || got.Owner != owner {
			t.Fatalf("record: got=%v err=%v", got, err)
		}
	}
	want := &contextSession{Owner: owner, Participants: []contextAccount{owner, second}}
	got, err := s.lookup("scope", "session")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("lookup: got=%v want=%v err=%v", got, want, err)
	}
	for _, alias := range []string{"first", "second", "renamed"} {
		if got, err := s.record("scope", "session", contextAccount{Alias: alias, Identity: "replacement"}); err == nil || got != nil {
			t.Fatalf("alias replacement %q: got=%v err=%v", alias, got, err)
		}
	}
	got, err = s.lookup("scope", "session")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("failed write changed state: got=%v err=%v", got, err)
	}
	got.Owner.Alias = "mutated"
	got.Participants[0].Alias = "mutated"
	got, err = s.lookup("scope", "session")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("returned state aliases stored state: got=%v err=%v", got, err)
	}
}

func TestNativeContextCap(t *testing.T) {
	s := testContextStore(t)
	for i := 0; i < 32; i++ {
		account := contextAccount{Alias: fmt.Sprint(i), Identity: fmt.Sprint(i)}
		if _, err := s.record("scope", "session", account); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.record("scope", "session", contextAccount{Alias: "overflow", Identity: "overflow"}); err == nil {
		t.Fatal("accepted participant 33")
	}
	got, err := s.record("scope", "session", contextAccount{Alias: "0", Identity: "0"})
	if err != nil || len(got.Participants) != 32 || got.Owner.Identity != "0" {
		t.Fatalf("dedupe at cap: got=%v err=%v", got, err)
	}
}

func TestNativeContextIsolation(t *testing.T) {
	s := testContextStore(t)
	pairs := [][2]string{{"a|b", "c"}, {"a", "b|c"}, {"a", "c"}, {"a|b", "b|c"}, {"", ""}, {"\"", "\\"}}
	for i, pair := range pairs {
		if _, err := s.record(pair[0], pair[1], contextAccount{Alias: "same", Identity: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	for i, pair := range pairs {
		got, err := s.lookup(pair[0], pair[1])
		if err != nil || got.Owner.Identity != fmt.Sprint(i) || len(got.Participants) != 1 {
			t.Fatalf("tuple %v: got=%v err=%v", pair, got, err)
		}
	}
}

func TestContextClaimConcurrent(t *testing.T) {
	s := testContextStore(t)
	const writers = 16
	var wg sync.WaitGroup
	winners := make(chan string, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			principal := fmt.Sprint(i)
			if err := s.claim(principal, "shared-session"); err == nil {
				winners <- principal
			}
		}()
	}
	wg.Wait()
	close(winners)
	var winner string
	count := 0
	for principal := range winners {
		winner = principal
		count++
	}
	if count != 1 {
		t.Fatalf("session acquired by %d principals", count)
	}
	reopened, err := newNativeContextStore(s.db)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.claim(winner, "shared-session"); err != nil {
		t.Fatal(err)
	}
	if err := reopened.claim("other", "shared-session"); err == nil {
		t.Fatal("principal claim was not retained")
	}
}

func TestNativeContextConcurrent(t *testing.T) {
	db := openContextDB(t, filepath.Join(t.TempDir(), "shared.db"))
	const writers = 16
	type outcome struct {
		store *nativeContextStore
		state *contextSession
		err   error
	}
	results := make(chan outcome, writers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s, err := newNativeContextStore(db)
			if err != nil {
				results <- outcome{err: err}
				return
			}
			state, err := s.record("scope", "session", contextAccount{Alias: fmt.Sprint(i), Identity: fmt.Sprint(i)})
			results <- outcome{store: s, state: state, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var first *nativeContextStore
	var owner contextAccount
	var encoded string
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if first == nil {
			first, owner = result.store, result.state.Owner
			var err error
			encoded, err = first.pack("scope", "session", []contextResult{{Account: owner, Value: json.RawMessage(`{"ok":true}`)}})
			if err != nil {
				t.Fatal(err)
			}
		}
		if result.state.Owner != owner {
			t.Fatalf("concurrent owners differ: %v and %v", result.state.Owner, owner)
		}
		if _, err := result.store.unpack("scope", "session", encoded); err != nil {
			t.Fatalf("concurrent constructors used different keys: %v", err)
		}
	}
	state, err := first.lookup("scope", "session")
	if err != nil || len(state.Participants) != writers || state.Participants[0] != owner {
		t.Fatalf("lost concurrent writes: state=%v err=%v", state, err)
	}
}

func TestNativeContextRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	db := openContextDB(t, path)
	s, err := newNativeContextStore(db)
	if err != nil {
		t.Fatal(err)
	}
	account := contextAccount{Alias: "owner", Identity: "physical"}
	if err := s.claim("scope", "session"); err != nil {
		t.Fatal(err)
	}
	state, err := s.record("scope", "session", account)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.record("scope", "session", contextAccount{Alias: "renamed", Identity: account.Identity}); err != nil {
		t.Fatal(err)
	}
	want := []contextResult{{Account: account, Value: json.RawMessage(`{"context":[1,"private"]}`)}}
	encoded, err := s.pack("scope", "session", want)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = newNativeContextStore(openContextDB(t, path))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.lookup("scope", "session")
	if err != nil || !reflect.DeepEqual(got, state) {
		t.Fatalf("restarted state: got=%v err=%v", got, err)
	}
	values, err := s.unpack("scope", "session", encoded)
	if err != nil || !reflect.DeepEqual(values, want) {
		t.Fatalf("restarted key: got=%v err=%v", values, err)
	}
	if _, err := s.record("scope", "session", contextAccount{Alias: "renamed", Identity: "other"}); err == nil {
		t.Fatal("alias identity binding did not survive restart")
	}
	if err := s.claim("other-principal", "session"); err == nil {
		t.Fatal("session principal binding did not survive restart")
	}
}

func TestNativeContextEnvelopes(t *testing.T) {
	s := testContextStore(t)
	want := []contextResult{
		{Account: contextAccount{Alias: "first", Identity: "a"}, Value: json.RawMessage(`{"secret":"native"}`)},
		{Account: contextAccount{Alias: "second", Identity: "b"}, Value: json.RawMessage(`[1,true,null]`)},
	}
	encoded, err := s.pack("a|b", "c", want)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "codex-pool-context-v1:") || strings.Contains(encoded, "secret") {
		t.Fatalf("unexpected envelope format")
	}
	got, err := s.unpack("a|b", "c", encoded)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("roundtrip: got=%v err=%v", got, err)
	}
	next, err := s.pack("a|b", "c", want)
	if err != nil || encoded == next {
		t.Fatalf("nonce not randomized: err=%v", err)
	}
	for _, pair := range [][2]string{{"other", "c"}, {"a|b", "other"}, {"a", "b|c"}} {
		if _, err := s.unpack(pair[0], pair[1], encoded); err == nil {
			t.Fatalf("accepted foreign tuple %v", pair)
		}
	}
	foreign := testContextStore(t)
	if _, err := foreign.unpack("a|b", "c", encoded); err == nil {
		t.Fatal("accepted foreign database key")
	}
	if _, err := s.pack("a", "b", []contextResult{{Value: json.RawMessage(`{`)}}); err == nil {
		t.Fatal("packed invalid JSON")
	}
}

func TestNativeContextMalformed(t *testing.T) {
	s := testContextStore(t)
	encoded, err := s.pack("scope", "session", []contextResult{{Value: json.RawMessage(`null`)}})
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "codex-pool-context-v1:"
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encoded, prefix))
	if err != nil {
		t.Fatal(err)
	}
	invalid := []string{"", "plain text", prefix, prefix + "!", prefix + "AA", strings.Replace(encoded, "v1:", "v2:", 1), encoded[:len(encoded)-1], encoded + "=", encoded + "\n"}
	for _, index := range []int{0, len(payload) / 2, len(payload) - 1} {
		modified := append([]byte(nil), payload...)
		modified[index] ^= 1
		invalid = append(invalid, prefix+base64.RawURLEncoding.EncodeToString(modified))
	}
	for i, value := range invalid {
		if got, err := s.unpack("scope", "session", value); err == nil || got != nil {
			t.Fatalf("malformed %d accepted: got=%v err=%v", i, got, err)
		}
	}
}

func TestNativeContextLimits(t *testing.T) {
	s := testContextStore(t)
	value := json.RawMessage(`"` + strings.Repeat("x", contextEnvelopeLimit) + `"`)
	if _, err := s.pack("scope", "session", []contextResult{{Value: value}}); err == nil {
		t.Fatal("packed oversized plaintext")
	}
	encoded := "codex-pool-context-v1:" + strings.Repeat("A", base64.RawURLEncoding.EncodedLen(contextEnvelopeLimit+s.aead.NonceSize()+s.aead.Overhead())+1)
	if _, err := s.unpack("scope", "session", encoded); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized encoding should fail before decrypt: %v", err)
	}
}
