package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFriendAuthRejectsQueryStringSecret(t *testing.T) {
	h := &proxyHandler{cfg: &config{friendCode: "secret-friend-code"}}

	queryRequest := httptest.NewRequest(http.MethodGet, "/api/pool/stats?code=secret-friend-code", nil)
	queryResponse := httptest.NewRecorder()
	if h.checkAdminOrFriendAuth(queryResponse, queryRequest) {
		t.Fatal("friend code in query string must not authenticate")
	}
	if queryResponse.Code != http.StatusUnauthorized {
		t.Fatalf("query auth status = %d, want %d", queryResponse.Code, http.StatusUnauthorized)
	}

	headerRequest := httptest.NewRequest(http.MethodGet, "/api/pool/stats", nil)
	headerRequest.Header.Set("X-Friend-Code", "secret-friend-code")
	headerResponse := httptest.NewRecorder()
	if !h.checkAdminOrFriendAuth(headerResponse, headerRequest) {
		t.Fatalf("friend header rejected with status %d", headerResponse.Code)
	}
}

func TestFriendCanStartCodexAccountContributionWithoutAdminAccess(t *testing.T) {
	h := &proxyHandler{cfg: &config{friendCode: "secret-friend-code"}}

	request := httptest.NewRequest(http.MethodPost, "/api/pool/accounts/codex/add", nil)
	request.Header.Set("X-Friend-Code", "secret-friend-code")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"oauth_url"`) || !strings.Contains(body, `"verifier"`) {
		t.Fatalf("missing OAuth contribution payload: %s", body)
	}
	if strings.Contains(body, "secret-friend-code") {
		t.Fatal("friend code leaked into account contribution response")
	}
}

func TestFriendAccountContributionRequiresAuthentication(t *testing.T) {
	h := &proxyHandler{cfg: &config{friendCode: "secret-friend-code"}}
	request := httptest.NewRequest(http.MethodPost, "/api/pool/accounts/codex/add", nil)
	response := httptest.NewRecorder()

	h.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}
