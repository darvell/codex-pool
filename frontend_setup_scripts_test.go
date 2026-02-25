package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServeCodexSetupScript_PowerShell(t *testing.T) {
	h := &proxyHandler{}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/setup/codex/testtoken?shell=powershell", nil)
	rr := httptest.NewRecorder()
	h.serveCodexSetupScript(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain*", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Set-StrictMode -Version Latest") {
		t.Fatalf("expected PowerShell script body, got:\n%s", body)
	}
	if !strings.Contains(body, "Join-Path $HOME '.codex'") {
		t.Fatalf("expected codex paths in script body, got:\n%s", body)
	}
	if !strings.Contains(body, "model_catalog_json = ") {
		t.Fatalf("expected model catalog config in script body, got:\n%s", body)
	}
	if !strings.Contains(body, "[mcp_servers.model_sync]") {
		t.Fatalf("expected MCP sidecar config in script body, got:\n%s", body)
	}
	if !strings.Contains(body, "model_sync.ps1") {
		t.Fatalf("expected MCP sidecar script install in PowerShell body, got:\n%s", body)
	}
	if !strings.Contains(body, "$firstLine = [Console]::In.ReadLine()") {
		t.Fatalf("expected MCP JSONL transport support in PowerShell body, got:\n%s", body)
	}
}

func TestServeCodexSetupScript_Bash(t *testing.T) {
	h := &proxyHandler{}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/setup/codex/testtoken", nil)
	rr := httptest.NewRecorder()
	h.serveCodexSetupScript(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/x-shellscript") {
		t.Fatalf("Content-Type = %q, want text/x-shellscript*", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "model_sync.sh") {
		t.Fatalf("expected MCP sidecar script install in bash body, got:\n%s", body)
	}
	if !strings.Contains(body, "model_catalog_json = ") {
		t.Fatalf("expected model catalog config in bash script body, got:\n%s", body)
	}
	if !strings.Contains(body, "[mcp_servers.model_sync]") {
		t.Fatalf("expected MCP sidecar config in bash script body, got:\n%s", body)
	}
	if !strings.Contains(body, "MCP_TRANSPORT_MODE=\"jsonl\"") {
		t.Fatalf("expected MCP JSONL transport support in bash body, got:\n%s", body)
	}
}

func TestServeGeminiSetupScript_PowerShell(t *testing.T) {
	secret := "test-secret-key-12345678901234567890"
	t.Setenv("POOL_JWT_SECRET", secret)

	tmpDir := t.TempDir()
	usersPath := filepath.Join(tmpDir, "pool_users.json")
	store, err := newPoolUserStore(usersPath)
	if err != nil {
		t.Fatalf("newPoolUserStore: %v", err)
	}

	user := &PoolUser{
		ID:        "user123",
		Token:     "tok123",
		Email:     "test@example.com",
		PlanType:  "pro",
		CreatedAt: time.Now(),
	}
	if err := store.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	h := &proxyHandler{poolUsers: store}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/setup/gemini/tok123?shell=powershell", nil)
	rr := httptest.NewRecorder()
	h.serveGeminiSetupScript(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain*", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "$env:CODE_ASSIST_ENDPOINT = $BaseUrl") {
		t.Fatalf("expected PowerShell env setup in body, got:\n%s", body)
	}
	if strings.Contains(body, "`") {
		t.Fatalf("PowerShell script should not contain backticks (Go raw string safety), got:\n%s", body)
	}
}

func TestServeClaudeSetupScript_PowerShell(t *testing.T) {
	secret := "test-secret-key-12345678901234567890"
	t.Setenv("POOL_JWT_SECRET", secret)

	// Ensure env is not contaminated by user-specific settings during test runs.
	t.Setenv("PUBLIC_URL", "")

	tmpDir := t.TempDir()
	usersPath := filepath.Join(tmpDir, "pool_users.json")
	store, err := newPoolUserStore(usersPath)
	if err != nil {
		t.Fatalf("newPoolUserStore: %v", err)
	}

	user := &PoolUser{
		ID:        "user456",
		Token:     "tok456",
		Email:     "test2@example.com",
		PlanType:  "pro",
		CreatedAt: time.Now(),
	}
	if err := store.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	h := &proxyHandler{poolUsers: store}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/setup/claude/tok456?shell=powershell", nil)
	rr := httptest.NewRecorder()
	h.serveClaudeSetupScript(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain*", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "$env:ANTHROPIC_BASE_URL = $BaseUrl") {
		t.Fatalf("expected PowerShell env setup in body, got:\n%s", body)
	}
	if !strings.Contains(body, "ConvertTo-Json -Depth 10") {
		t.Fatalf("expected PowerShell JSON update logic in body, got:\n%s", body)
	}
	if strings.Contains(body, "`") {
		t.Fatalf("PowerShell script should not contain backticks (Go raw string safety), got:\n%s", body)
	}
}
