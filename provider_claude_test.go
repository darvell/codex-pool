package main

import (
	"encoding/json"
	"net/url"
	"testing"
)

func TestClaudeProviderLoadAccountFlags(t *testing.T) {
	t.Parallel()

	baseURL, err := url.Parse("https://api.anthropic.com")
	if err != nil {
		t.Fatalf("parse base url: %v", err)
	}
	p := NewClaudeProvider(baseURL)

	data := []byte(`{
  "dead": true,
  "disabled": true,
  "allowed_ip": "199.45.144.95",
  "allowed_source_ips": ["199.45.144.95"],
  "claudeAiOauth": {
    "accessToken": "sk-ant-oat-test",
    "refreshToken": "rt-test",
    "expiresAt": 1893456000000,
    "subscriptionType": "pro"
  }
}`)

	acc, err := p.LoadAccount("claude_test.json", "/tmp/claude_test.json", data)
	if err != nil {
		t.Fatalf("LoadAccount error: %v", err)
	}
	if acc == nil {
		t.Fatal("LoadAccount returned nil account")
	}
	if !acc.Dead {
		t.Fatal("expected dead=true")
	}
	if !acc.Disabled {
		t.Fatal("expected disabled=true")
	}
	if len(acc.AllowedSourceIPs) != 2 || acc.AllowedSourceIPs[0] != "199.45.144.95" || acc.AllowedSourceIPs[1] != "199.45.144.95" {
		t.Fatalf("expected allowed source IPs loaded, got %#v", acc.AllowedSourceIPs)
	}
}

func TestClaudeInjectMetadataAddsClaudeCodeShape(t *testing.T) {
	body := map[string]any{}
	ccInjectMetadata(body, "")

	metadata, ok := body["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata missing or wrong type: %#v", body["metadata"])
	}
	userID, ok := metadata["user_id"].(string)
	if !ok || userID == "" {
		t.Fatalf("metadata.user_id missing: %#v", metadata["user_id"])
	}

	var payload map[string]string
	if err := json.Unmarshal([]byte(userID), &payload); err != nil {
		t.Fatalf("unmarshal metadata.user_id: %v", err)
	}
	if payload["device_id"] == "" {
		t.Fatal("device_id missing")
	}
	if payload["session_id"] != ccSessionHeader() {
		t.Fatalf("session_id = %q, want %q", payload["session_id"], ccSessionHeader())
	}
	if payload["account_uuid"] != "" {
		t.Fatalf("account_uuid = %q, want empty", payload["account_uuid"])
	}
}

func TestClaudeInjectMetadataPreservesExistingMetadata(t *testing.T) {
	body := map[string]any{
		"metadata": map[string]any{"user_id": "keep-me"},
	}
	ccInjectMetadata(body, "ignored")

	metadata := body["metadata"].(map[string]any)
	if metadata["user_id"] != "keep-me" {
		t.Fatalf("metadata overwritten: %#v", metadata)
	}
}
