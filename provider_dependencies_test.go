package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeAuthDependencies(t *testing.T) {
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "refresh")
	account := &Account{Type: AccountTypeClaude, ID: "claude", File: filepath.Join(t.TempDir(), "claude.json"), AccessToken: "sk-ant-oat-old", RefreshToken: "refresh-old"}
	if err := os.WriteFile(account.File, []byte(`{"legacy_extra":"preserved"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var destinations []string
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Context().Value(contextKey{}) != "refresh" {
			t.Fatal("caller context missing")
		}
		destinations = append(destinations, req.URL.String())
		body := ""
		switch req.URL.String() {
		case ClaudeOAuthTokenURL:
			if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("token request: %s %v", req.Method, req.Header)
			}
			var payload map[string]string
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["refresh_token"] != "refresh-old" || payload["scope"] != ClaudeOAuthRefreshScopes || payload["client_id"] != ClaudeOAuthClientID || payload["grant_type"] != "refresh_token" {
				t.Fatalf("refresh payload = %#v", payload)
			}
			body = `{"access_token":"sk-ant-oat-new","refresh_token":"refresh-new","expires_in":3600}`
		case ClaudeOAuthProfileURL:
			body = `{"organization":{"organization_type":"claude_max","rate_limit_tier":"max-test"}}`
		case "https://api.anthropic.com/api/claude_cli/bootstrap":
			body = `{"account_uuid":"learned-uuid"}`
		default:
			t.Fatalf("unexpected request destination: %s", req.URL)
		}
		if req.Method == http.MethodGet {
			if req.Header.Get("Authorization") != "Bearer sk-ant-oat-new" || req.Header.Get("Anthropic-Version") != ccAnthropicVersion || req.Header.Get("Anthropic-Beta") != ccMinimalBetaHeader() || req.Header.Get("User-Agent") != ccClaudeCodeUserAgent() || req.Header.Get("X-App") != "cli" || req.Header.Get("X-Claude-Code-Session-Id") == "" {
				t.Fatalf("OAuth headers = %v", req.Header)
			}
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	base, _ := url.Parse("https://configured.invalid")
	provider := NewClaudeProvider(base)
	if err := provider.RefreshToken(ctx, account, transport); err != nil {
		t.Fatal(err)
	}
	if len(destinations) != 3 {
		t.Fatalf("request destinations = %v", destinations)
	}
	saved, err := os.ReadFile(account.File)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(saved, &root); err != nil {
		t.Fatal(err)
	}
	if root["legacy_extra"] != "preserved" {
		t.Fatalf("saved extra field = %v", root["legacy_extra"])
	}
	reloaded, err := provider.LoadAccount("claude.json", account.File, saved)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.AccessToken != "sk-ant-oat-new" || reloaded.RefreshToken != "refresh-new" || reloaded.PlanType != "max" || reloaded.RateLimitTier != "max-test" || reloaded.AccountUUID != "learned-uuid" || reloaded.ExpiresAt.IsZero() {
		t.Fatalf("reloaded account = %#v", reloaded)
	}
}

func TestClaudeAuthCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, req.Context().Err()
	})
	account := &Account{AccessToken: "sk-ant-oat-old", RefreshToken: "refresh-old"}
	err := NewClaudeProvider(nil).RefreshToken(ctx, account, transport)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("refresh error = %v", err)
	}
	if account.AccessToken != "sk-ant-oat-old" || account.RefreshToken != "refresh-old" {
		t.Fatal("canceled refresh changed credentials")
	}
}

func TestClaudeAdminProfileRequest(t *testing.T) {
	base, _ := url.Parse("https://configured.invalid/prefix?configured=yes")
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://configured.invalid/prefix/api/oauth/profile?configured=yes" || req.Header.Get("Authorization") != "Bearer profile-token" || req.Header.Get("Anthropic-Dangerous-Direct-Browser-Access") != "true" {
			t.Fatalf("profile request: %s %v", req.URL, req.Header)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"organization":{"organization_type":"claude_pro"}}`))}, nil
	})
	h := &proxyHandler{cfg: &config{claudeBase: base}, transport: transport}
	profile, err := h.fetchClaudeOAuthProfile(context.Background(), "profile-token")
	if err != nil {
		t.Fatal(err)
	}
	if extractProfileInfo(profile).SubscriptionType != "pro" {
		t.Fatalf("profile = %#v", profile)
	}
}

func TestClaudeAdminProfileRedirect(t *testing.T) {
	base, _ := url.Parse("https://configured.invalid")
	calls := 0
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusFound, Status: "302 Found", Header: http.Header{"Location": []string{"https://redirect.invalid"}}, Body: io.NopCloser(strings.NewReader("redirect"))}, nil
	})
	h := &proxyHandler{cfg: &config{claudeBase: base}, transport: transport}
	if _, err := h.fetchClaudeOAuthProfile(context.Background(), "profile-token"); err == nil || calls != 1 {
		t.Fatalf("profile error=%v requests=%d", err, calls)
	}
}

func TestClaudeExchangeRequest(t *testing.T) {
	for _, state := range []string{"", "explicit-state"} {
		t.Run(state, func(t *testing.T) {
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				var payload map[string]string
				if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				expectedState := state
				if expectedState == "" {
					expectedState = "copied-state"
				}
				if req.Method != http.MethodPost || req.URL.String() != ClaudeOAuthTokenURL || req.Header.Get("Content-Type") != "application/json" || payload["code"] != "copied-code" || payload["state"] != expectedState || payload["code_verifier"] != "verifier" || payload["grant_type"] != "authorization_code" || payload["client_id"] != ClaudeOAuthClientID || payload["redirect_uri"] != ClaudeOAuthRedirectURI {
					t.Fatalf("exchange request: %s %s %v %#v", req.Method, req.URL, req.Header, payload)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"exchanged-access"}`))}, nil
			})
			token, err := newClaudeAuth(transport).exchange(context.Background(), "copied-code#copied-state", "verifier", state)
			if err != nil {
				t.Fatal(err)
			}
			if token.AccessToken != "exchanged-access" {
				t.Fatalf("access token = %q", token.AccessToken)
			}
		})
	}
}
