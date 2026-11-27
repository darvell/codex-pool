package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// Codex reports a per-machine installation id and a per-window id with every
// request. Forwarded unchanged, one developer's ids would appear on every
// ChatGPT account the pool routes them to, which ties those accounts to a
// single machine. The pool replaces each id with a value derived from the
// pool principal, the serving account, and the original id. The pair still
// presents one stable device to its account, and the ids on two accounts no
// longer match.
//
// Session, thread, and turn ids and prompt_cache_key pass through untouched:
// the native context relay and upstream prompt caching resolve them across
// requests and accounts.

const codexDeviceIdentityVersion = "v1"

// minCodexDeviceIDLength keeps short tokens out of the body-wide replacement.
const minCodexDeviceIDLength = 16

var codexDeviceIdentityFields = []struct {
	name string
	kind string
}{
	{name: "x-codex-installation-id", kind: "installation"},
	{name: "installation_id", kind: "installation"},
	{name: "x-codex-window-id", kind: "window"},
	{name: "window_id", kind: "window"},
}

// codexIdentityNamespace names the upstream seat, so two pool entries for the
// same ChatGPT login present the same device.
func codexIdentityNamespace(acc *Account) string {
	acc.mu.Lock()
	defer acc.mu.Unlock()

	seat := acc.AccountID
	if seat == "" {
		seat = acc.IDTokenChatGPTAccountID
	}
	if seat == "" {
		return "pool:" + acc.ID
	}
	return "chatgpt:" + seat + ":" + acc.ChatGPTUserID
}

func scopedCodexDeviceID(acc *Account, userID, kind, raw string) string {
	principal, _ := splitClientIdentity(userID)
	seed := strings.Join([]string{"codex-pool/codex-device", codexDeviceIdentityVersion, principal, codexIdentityNamespace(acc), kind, raw}, "\x00")
	sum := sha256.Sum256([]byte(seed))

	if len(raw) != 36 {
		encoded := hex.EncodeToString(sum[:])
		if len(raw) < len(encoded) {
			return encoded[:len(raw)]
		}
		return encoded
	}
	original, err := uuid.Parse(raw)
	if err != nil {
		return hex.EncodeToString(sum[:])[:len(raw)]
	}

	// Keep the original version and variant so the replacement has the same
	// shape. A v7 id also keeps its timestamp prefix.
	var scoped uuid.UUID
	copy(scoped[:], sum[:16])
	if original.Version() == 7 {
		copy(scoped[:6], original[:6])
	}
	scoped[6] = scoped[6]&0x0f | original[6]&0xf0
	scoped[8] = scoped[8]&0x3f | original[8]&0xc0
	if raw != strings.ToLower(raw) {
		return strings.ToUpper(scoped.String())
	}
	return scoped.String()
}

func scopeCodexDeviceHeaders(h http.Header, acc *Account, userID string) {
	if h == nil || acc == nil || acc.Type != AccountTypeCodex {
		return
	}
	for _, field := range codexDeviceIdentityFields {
		raw := strings.TrimSpace(h.Get(field.name))
		if !validCodexDeviceID(raw) {
			continue
		}
		h.Set(field.name, scopedCodexDeviceID(acc, userID, field.kind, raw))
	}
}

// scopeCodexDeviceBody rewrites device ids in a request body or websocket
// frame. Bodies reach megabytes, so it locates the ids by key instead of
// decoding the document, then replaces every occurrence of each id. That
// covers client_metadata and the escaped copy inside x-codex-turn-metadata
// without re-encoding anything else.
func scopeCodexDeviceBody(body []byte, acc *Account, userID string) []byte {
	if acc == nil || acc.Type != AccountTypeCodex || !mayCarryCodexDeviceID(body) {
		return body
	}
	found := map[string]string{}
	for _, field := range codexDeviceIdentityFields {
		for _, raw := range jsonStringValuesForKey(body, field.name) {
			if validCodexDeviceID(raw) {
				found[raw] = field.kind
			}
		}
	}
	if len(found) == 0 {
		return body
	}
	out := body
	for raw, kind := range found {
		out = bytes.ReplaceAll(out, []byte(raw), []byte(scopedCodexDeviceID(acc, userID, kind, raw)))
	}
	return out
}

func mayCarryCodexDeviceID(body []byte) bool {
	return bytes.Contains(body, []byte("installation")) || bytes.Contains(body, []byte("window-id")) || bytes.Contains(body, []byte("window_id"))
}

func validCodexDeviceID(value string) bool {
	if len(value) < minCodexDeviceIDLength || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// jsonStringValuesForKey returns the string values stored under key, either
// as a plain JSON member or inside a JSON-encoded string, where the quotes
// arrive escaped.
func jsonStringValuesForKey(body []byte, key string) []string {
	var values []string
	for _, quote := range []string{`"`, `\"`} {
		needle := []byte(quote + key + quote)
		rest := body
		for {
			at := bytes.Index(rest, needle)
			if at < 0 {
				break
			}
			rest = rest[at+len(needle):]
			value := bytes.TrimLeft(rest, " \t\r\n")
			if !bytes.HasPrefix(value, []byte(":")) {
				continue
			}
			value = bytes.TrimLeft(value[1:], " \t\r\n")
			if !bytes.HasPrefix(value, []byte(quote)) {
				continue
			}
			value = value[len(quote):]
			end := bytes.IndexAny(value, `"\`)
			if end < 0 {
				continue
			}
			values = append(values, string(value[:end]))
		}
	}
	return values
}
