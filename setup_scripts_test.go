package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupBashSyntax(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}
	t.Setenv("PUBLIC_URL", "https://pool.test")
	t.Setenv("POOL_JWT_SECRET", "test-secret-key-12345678901234567890")
	h := &proxyHandler{poolUsers: newTestPoolUserStoreWithUser(t, "test-setup-token")}
	for _, script := range []struct {
		name  string
		serve http.HandlerFunc
	}{
		{name: "codex", serve: h.serveCodexSetupScript},
		{name: "claude", serve: h.serveClaudeSetupScript},
		{name: "gemini", serve: h.serveGeminiSetupScript},
		{name: "cute-code", serve: h.serveCuteCodeSetupScript},
		{name: "grok", serve: h.serveGrokSetupScript},
		{name: "pi", serve: h.servePiSetupScript},
	} {
		t.Run(script.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			script.serve(rr, httptest.NewRequest(http.MethodGet, "https://pool.test/setup/"+script.name+"/test-setup-token", nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("setup status = %d: %s", rr.Code, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), "{{") {
				t.Fatal("setup contains an unexpanded template value")
			}
			command := exec.Command(bash, "-n")
			command.Stdin = strings.NewReader(rr.Body.String())
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("bash rejected setup: %v\n%s", err, output)
			}
		})
	}
}

func setupTestEnv(t *testing.T, home string, responses map[string]string) []string {
	t.Helper()
	bin := t.TempDir()
	curl := "#!/bin/sh\nset -eu\nurl=\noutput=\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    -o) output=$2; shift 2 ;;\n    -H|--connect-timeout|--max-time) shift 2 ;;\n    http://*|https://*) url=$1; shift ;;\n    *) shift ;;\n  esac\ndone\ncase \"$url\" in\n"
	for url, body := range responses {
		response := filepath.Join(t.TempDir(), "response.json")
		if err := os.WriteFile(response, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		curl += fmt.Sprintf("  %q) cp %q \"$output\" ;;\n", url, response)
	}
	curl += "  *) printf 'Unexpected setup request: %s\\n' \"$url\" >&2; exit 1 ;;\nesac\n"
	for name, script := range map[string]string{"curl": curl, "codex": "#!/bin/sh\nexit 0\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if node, err := exec.LookPath("node"); err == nil {
		if err := os.Symlink(node, filepath.Join(bin, "node")); err != nil {
			t.Fatal(err)
		}
	}
	return []string{"HOME=" + home, "CLAUDE_CONFIG_DIR=" + filepath.Join(home, "claude-config"), "PATH=" + bin + ":/usr/bin:/bin"}
}
