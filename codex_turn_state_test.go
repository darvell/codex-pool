package main

import (
	"net/http"
	"testing"
	"time"
)

func TestCodexTurnStateSeedRequiresBothParts(t *testing.T) {
	if got := codexTurnStateSeed("", "conv"); got != "" {
		t.Fatalf("seed with empty user = %q, want empty", got)
	}
	if got := codexTurnStateSeed("user", ""); got != "" {
		t.Fatalf("seed with empty conversation = %q, want empty", got)
	}
	if got := codexTurnStateSeed("user", "conv"); got == "" {
		t.Fatal("seed with both parts must not be empty")
	}
}

func TestGuardKeepsSameAccountEcho(t *testing.T) {
	h := &proxyHandler{}
	acc := &Account{Type: AccountTypeCodex, ID: "a"}
	h.noteCodexTurnState("user", "conv", acc, "blob-from-a")

	header := http.Header{"X-Codex-Turn-State": {"blob-from-a"}}
	h.guardCodexTurnStateEcho("user", "conv", acc, header)
	if got := header.Get("x-codex-turn-state"); got != "blob-from-a" {
		t.Fatalf("same-account echo = %q, want it kept", got)
	}
}

func TestGuardStripsForeignAccountEcho(t *testing.T) {
	h := &proxyHandler{}
	h.noteCodexTurnState("user", "conv", &Account{Type: AccountTypeCodex, ID: "a"}, "blob-from-a")

	header := http.Header{
		"X-Codex-Turn-State": {"blob-from-a"},
		"Content-Type":       {"application/json"},
	}
	h.guardCodexTurnStateEcho("user", "conv", &Account{Type: AccountTypeCodex, ID: "b"}, header)
	if got := header.Get("x-codex-turn-state"); got != "" {
		t.Fatalf("foreign echo = %q, want it stripped", got)
	}
	if got := header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("unrelated header = %q, want it kept", got)
	}
}

func TestGuardKeepsEchoWithUnknownOrigin(t *testing.T) {
	h := &proxyHandler{}
	header := http.Header{"X-Codex-Turn-State": {"blob"}}
	h.guardCodexTurnStateEcho("user", "new-conv", &Account{Type: AccountTypeCodex, ID: "b"}, header)
	if got := header.Get("x-codex-turn-state"); got != "blob" {
		t.Fatalf("unknown-origin echo = %q, want it kept", got)
	}
}

func TestGuardKeepsEchoWithExpiredOrigin(t *testing.T) {
	h := &proxyHandler{}
	h.turnStateOrigins = map[string]codexTurnStateOrigin{
		codexTurnStateSeed("user", "conv"): {accountID: "a", expiresAt: time.Now().Add(-time.Minute)},
	}
	header := http.Header{"X-Codex-Turn-State": {"blob-from-a"}}
	h.guardCodexTurnStateEcho("user", "conv", &Account{Type: AccountTypeCodex, ID: "b"}, header)
	if got := header.Get("x-codex-turn-state"); got != "blob-from-a" {
		t.Fatalf("expired-origin echo = %q, want it kept", got)
	}
	if len(h.turnStateOrigins) != 0 {
		t.Fatal("expired origin should be collected on read")
	}
}

func TestNoteIgnoresEmptyStateAndNonCodex(t *testing.T) {
	h := &proxyHandler{}
	h.noteCodexTurnState("user", "conv", &Account{Type: AccountTypeCodex, ID: "a"}, "")
	h.noteCodexTurnState("user", "conv", &Account{Type: AccountTypeClaude, ID: "c"}, "blob")
	h.noteCodexTurnState("user", "", &Account{Type: AccountTypeCodex, ID: "a"}, "blob")
	if len(h.turnStateOrigins) != 0 {
		t.Fatalf("origins = %d entries, want none recorded", len(h.turnStateOrigins))
	}

	header := http.Header{"X-Codex-Turn-State": {"blob"}}
	h.guardCodexTurnStateEcho("user", "conv", &Account{Type: AccountTypeClaude, ID: "c"}, header)
	if got := header.Get("x-codex-turn-state"); got != "blob" {
		t.Fatalf("non-codex guard = %q, want untouched", got)
	}
}

func TestGuardNilSafe(t *testing.T) {
	var h *proxyHandler
	header := http.Header{"X-Codex-Turn-State": {"blob"}}
	h.guardCodexTurnStateEcho("user", "conv", &Account{Type: AccountTypeCodex, ID: "b"}, header)
	h.noteCodexTurnState("user", "conv", &Account{Type: AccountTypeCodex, ID: "a"}, "blob")
	if got := header.Get("x-codex-turn-state"); got != "blob" {
		t.Fatalf("nil-handler guard = %q, want untouched", got)
	}
}
