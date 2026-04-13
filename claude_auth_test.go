package main

import (
	"net/url"
	"testing"
)

func TestClaudeAuthorizeUsesExpandedScopes(t *testing.T) {
	t.Parallel()

	rawURL, session, err := ClaudeAuthorize("acct")
	if err != nil {
		t.Fatalf("ClaudeAuthorize: %v", err)
	}
	if session == nil || session.PKCE == nil {
		t.Fatal("expected oauth session with pkce")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	if got := u.Query().Get("scope"); got != ClaudeOAuthAllScopes {
		t.Fatalf("scope = %q, want %q", got, ClaudeOAuthAllScopes)
	}
	if got := u.Query().Get("state"); got != session.State {
		t.Fatalf("state = %q, want %q", got, session.State)
	}
	if got := u.Query().Get("code_challenge"); got != session.PKCE.Challenge {
		t.Fatalf("code_challenge = %q, want %q", got, session.PKCE.Challenge)
	}
}
