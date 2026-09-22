package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestParseWhamUsageIgnoresSparkAdditionalLimits(t *testing.T) {
	payload := map[string]any{
		"rate_limit": map[string]any{
			"allowed":       true,
			"limit_reached": false,
			"primary_window": map[string]any{
				"used_percent":         0.0,
				"limit_window_seconds": 604800.0,
				"reset_at":             1789767898.0,
			},
			"secondary_window": nil,
		},
		"additional_rate_limits": []any{
			map[string]any{
				"limit_name": "GPT-5.3-Codex-Spark",
				"rate_limit": map[string]any{
					"primary_window": map[string]any{
						"used_percent":         99.0,
						"limit_window_seconds": 18000.0,
						"reset_at":             1789180722.0,
					},
					"secondary_window": map[string]any{
						"used_percent":         44.0,
						"limit_window_seconds": 604800.0,
						"reset_at":             1789767522.0,
					},
				},
			},
			map[string]any{
				"limit_name": "gpt-reserve",
				"rate_limit": map[string]any{
					"primary_window": map[string]any{
						"used_percent":         0.0,
						"limit_window_seconds": 604800.0,
					},
				},
			},
		},
	}

	snap, ok := parseWhamUsage(payload, time.Unix(1788480000, 0))
	if !ok {
		t.Fatal("expected WHAM payload to parse")
	}
	// Spark's 99% 5h quota is model-specific and must not become the default
	// 5h window. The default 5h window is absent, so no primary window data.
	if usagePrimaryWindowAvailable(snap) {
		t.Fatalf("primary window should be unavailable, got used=%.2f minutes=%d",
			usagePrimaryUsed(snap), snap.PrimaryWindowMinutes)
	}
	if got := usageSecondaryUsed(snap); got != 0 {
		t.Fatalf("weekly used = %.2f, want 0 from top-level default window", got)
	}
	if snap.SecondaryWindowMinutes != 10080 {
		t.Fatalf("weekly window minutes = %d, want 10080", snap.SecondaryWindowMinutes)
	}
}

func TestParseWhamUsageKeepsLegacyDualWindows(t *testing.T) {
	payload := map[string]any{
		"rate_limit": map[string]any{
			"primary_window": map[string]any{
				"used_percent":         12.0,
				"limit_window_seconds": 18000.0,
				"reset_at":             1788503384.0,
			},
			"secondary_window": map[string]any{
				"used_percent":         34.0,
				"limit_window_seconds": 604800.0,
				"reset_at":             1789090184.0,
			},
		},
	}

	snap, ok := parseWhamUsage(payload, time.Unix(1788480000, 0))
	if !ok {
		t.Fatal("expected legacy WHAM payload to parse")
	}
	if got := usagePrimaryUsed(snap); got != 0.12 {
		t.Fatalf("5h used = %.2f, want 0.12", got)
	}
	if got := usageSecondaryUsed(snap); got != 0.34 {
		t.Fatalf("weekly used = %.2f, want 0.34", got)
	}
}

func TestRetireAfterRefreshFailKeepsLiveCodex(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	live := &Account{
		Type:        AccountTypeCodex,
		AccessToken: jwtWithExp(now.Add(10 * 24 * time.Hour).Unix()),
	}
	err := fmt.Errorf(`refresh unauthorized: 401 Unauthorized: {"error":{"code":"refresh_token_reused"}}`)
	if retireAfterRefreshFail(live, err, now) {
		t.Fatal("live Codex access token should keep the account routable")
	}

	expired := &Account{
		Type:        AccountTypeCodex,
		AccessToken: jwtWithExp(now.Add(-time.Minute).Unix()),
	}
	if !retireAfterRefreshFail(expired, err, now) {
		t.Fatal("expired Codex access token with a reused refresh token should retire")
	}
}

func TestPersistDeadAccountSkipsRewrite(t *testing.T) {
	acc := &Account{ID: "x", Type: AccountTypeCodex, Dead: true, File: "/no/such/codex.json"}
	persistDeadAccount(acc, "refresh token revoked")
	if !acc.Dead {
		t.Fatal("expected account to stay dead")
	}
}

func TestCodexAccessFarFromExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	live := &Account{Type: AccountTypeCodex, ExpiresAt: now.Add(9 * 24 * time.Hour)}
	if !codexAccessFarFromExpiry(live, now) {
		t.Fatal("expected days of remaining life to skip refresh")
	}
	dying := &Account{Type: AccountTypeCodex, ExpiresAt: now.Add(time.Hour)}
	if codexAccessFarFromExpiry(dying, now) {
		t.Fatal("expected headroom window to allow refresh")
	}
}

func jwtWithExp(exp int64) string {
	payload, _ := json.Marshal(map[string]any{"exp": exp})
	return "h." + base64.RawURLEncoding.EncodeToString(payload) + ".s"
}
