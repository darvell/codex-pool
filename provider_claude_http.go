package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type claudeAuthClient struct {
	do func(*http.Request) (*http.Response, error)
}

func newClaudeAuth(transport http.RoundTripper) claudeAuthClient {
	client := &http.Client{Transport: transport}
	return claudeAuthClient{do: client.Do}
}

func (c claudeAuthClient) profileInfo(ctx context.Context, accessToken string) (*ClaudeProfileInfo, error) {
	payload, err := c.profile(ctx, ClaudeOAuthProfileURL, accessToken)
	if err != nil {
		return nil, err
	}
	return extractProfileInfo(payload), nil
}

func (c claudeAuthClient) exchange(ctx context.Context, code, verifier, state string) (*ClaudeTokenResponse, error) {
	// Manual copy/paste can still provide code#state; prefer the explicit
	// session state from ClaudeAuthorize, but preserve compatibility.
	codeOnly := code
	if idx := indexOf(code, '#'); idx >= 0 {
		codeOnly = code[:idx]
		if state == "" {
			state = code[idx+1:]
		}
	}

	body := map[string]string{
		"code":          codeOnly,
		"grant_type":    "authorization_code",
		"client_id":     ClaudeOAuthClientID,
		"redirect_uri":  ClaudeOAuthRedirectURI,
		"code_verifier": verifier,
		"state":         state,
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ClaudeOAuthTokenURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("exchange failed: %s: %s", resp.Status, string(respBody))
	}

	var result ClaudeTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

func (c claudeAuthClient) refresh(ctx context.Context, refreshToken string) (*ClaudeTokenResponse, error) {
	body := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     ClaudeOAuthClientID,
		"scope":         ClaudeOAuthRefreshScopes,
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ClaudeOAuthTokenURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("refresh failed: %s: %s", resp.Status, string(respBody))
	}

	var result ClaudeTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

func (c claudeAuthClient) profile(ctx context.Context, target, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("anthropic-version", ccAnthropicVersion)
	req.Header.Set("anthropic-dangerous-direct-browser-access", "true")
	req.Header.Set("anthropic-beta", ccMinimalBetaHeader())
	req.Header.Set("User-Agent", ccClaudeCodeUserAgent())
	req.Header.Set("X-Claude-Code-Session-Id", ccAccountSessionID(accessToken))
	req.Header.Set("X-App", "cli")
	req.Header.Set("Accept", "application/json")
	ccStainlessHeaders(req.Header.Set)

	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("profile status=%s body=%s", resp.Status, string(body))
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	return payload, nil
}

// Anthropic bootstrap returns the account UUID used in Claude Code metadata.
func (c claudeAuthClient) accountUUID(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.anthropic.com/api/claude_cli/bootstrap", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("anthropic-version", ccAnthropicVersion)
	req.Header.Set("anthropic-dangerous-direct-browser-access", "true")
	req.Header.Set("anthropic-beta", ccMinimalBetaHeader())
	req.Header.Set("User-Agent", ccClaudeCodeUserAgent())
	req.Header.Set("X-Claude-Code-Session-Id", ccAccountSessionID(accessToken))
	req.Header.Set("X-App", "cli")
	req.Header.Set("Accept", "application/json")
	ccStainlessHeaders(req.Header.Set)

	resp, err := c.do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("bootstrap status=%s body=%s", resp.Status, string(body))
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}

	if uuid, ok := payload["account_uuid"].(string); ok && uuid != "" {
		return uuid, nil
	}
	if user, ok := payload["user"].(map[string]any); ok {
		if uuid, ok := user["uuid"].(string); ok && uuid != "" {
			return uuid, nil
		}
	}
	if account, ok := payload["account"].(map[string]any); ok {
		if uuid, ok := account["uuid"].(string); ok && uuid != "" {
			return uuid, nil
		}
	}

	return "", fmt.Errorf("account_uuid not found in bootstrap response")
}
