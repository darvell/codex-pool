package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestParseWhamUsageFillsFiveHourFromAdditional(t *testing.T) {
	payload := map[string]any{
		"rate_limit": map[string]any{
			"allowed":       true,
			"limit_reached": false,
			"primary_window": map[string]any{
				"used_percent":         100.0,
				"limit_window_seconds": 604800.0,
				"reset_at":             1788748328.0,
			},
		},
		"additional_rate_limits": []any{
			map[string]any{
				"limit_name": "GPT-5.3-Codex-Spark",
				"rate_limit": map[string]any{
					"primary_window": map[string]any{
						"used_percent":         0.0,
						"limit_window_seconds": 18000.0,
						"reset_at":             1788503384.0,
					},
					"secondary_window": map[string]any{
						"used_percent":         0.0,
						"limit_window_seconds": 604800.0,
						"reset_at":             1789090184.0,
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
	if got := usagePrimaryUsed(snap); got != 0 {
		t.Fatalf("5h used = %.2f, want 0 from additional Spark window", got)
	}
	if snap.PrimaryWindowMinutes != 300 {
		t.Fatalf("5h window minutes = %d, want 300", snap.PrimaryWindowMinutes)
	}
	if got := usageSecondaryUsed(snap); got != 1 {
		t.Fatalf("weekly used = %.2f, want 1 from top-level default window", got)
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

func jwtWithExp(exp int64) string {
	payload, _ := json.Marshal(map[string]any{"exp": exp})
	return "h." + base64.RawURLEncoding.EncodeToString(payload) + ".s"
}
