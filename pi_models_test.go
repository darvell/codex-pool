package main

import (
	"encoding/json"
	"testing"
)

func TestClaudeCanonicalModelHandlesShortOneMillionAliases(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"sonnet":      "claude-sonnet-4-6",
		"sonnet[1m]":  "claude-sonnet-4-6 [1m]",
		"sonnet [1m]": "claude-sonnet-4-6 [1m]",
		"opus":        "claude-opus-4-6",
		"opus[1m]":    "claude-opus-4-6 [1m]",
		"opus [1m]":   "claude-opus-4-6 [1m]",
		"haiku":       "claude-haiku-4-5-20251001",
	}

	for input, want := range tests {
		if got := claudeCanonicalModel(input); got != want {
			t.Fatalf("claudeCanonicalModel(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestGeneratePiModelsJSON(t *testing.T) {
	t.Parallel()

	data, err := generatePiModelsJSON(
		"https://pool.example.com/",
		"eyJhbGciOiJIUzI1NiJ9.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdF90ZXN0In19.sig",
		"sk-ant-oat01-pool-test",
	)
	if err != nil {
		t.Fatalf("generatePiModelsJSON error: %v", err)
	}

	var cfg piModelsConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal pi models json: %v", err)
	}

	if got := cfg.Providers["codex"].BaseURL; got != "https://pool.example.com/backend-api" {
		t.Fatalf("codex baseUrl = %q", got)
	}
	if got := cfg.Providers["codex"].APIKey; got != "eyJhbGciOiJIUzI1NiJ9.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdF90ZXN0In19.sig" {
		t.Fatalf("codex apiKey = %q", got)
	}
	if got := cfg.Providers["codex"].API; got != "openai-codex-responses" {
		t.Fatalf("codex api = %q", got)
	}
	if len(cfg.Providers["codex"].Models) == 0 {
		t.Fatalf("codex models missing")
	}
	wantCodexLimits := map[string]struct {
		contextWindow int
		maxTokens     int
	}{
		"gpt-5.4":             {contextWindow: 1050000, maxTokens: 128000},
		"gpt-5.3-codex":       {contextWindow: 400000, maxTokens: 128000},
		"gpt-5.3-codex-spark": {contextWindow: 128000, maxTokens: 128000},
	}
	for _, model := range cfg.Providers["codex"].Models {
		if len(model.Input) != 2 || model.Input[0] != "text" || model.Input[1] != "image" {
			t.Fatalf("codex model %q inputs = %#v, want text+image", model.ID, model.Input)
		}
		if want, ok := wantCodexLimits[model.ID]; ok {
			if model.ContextWindow != want.contextWindow || model.MaxTokens != want.maxTokens {
				t.Fatalf(
					"codex model %q limits = (%d, %d), want (%d, %d)",
					model.ID,
					model.ContextWindow,
					model.MaxTokens,
					want.contextWindow,
					want.maxTokens,
				)
			}
		}
	}

	claude := cfg.Providers["claude"]
	if claude.API != "anthropic-messages" {
		t.Fatalf("claude api = %q", claude.API)
	}
	if claude.BaseURL != "https://pool.example.com" {
		t.Fatalf("claude baseUrl = %q", claude.BaseURL)
	}
	if claude.APIKey != "sk-ant-oat01-pool-test" {
		t.Fatalf("claude apiKey = %q", claude.APIKey)
	}

	needClaudeIDs := map[string]bool{
		"claude-haiku-4-5":       false,
		"claude-sonnet-4-6":      false,
		"claude-sonnet-4-6 [1m]": false,
		"claude-opus-4-6":        false,
		"claude-opus-4-6 [1m]":   false,
	}
	for _, model := range claude.Models {
		if _, ok := needClaudeIDs[model.ID]; ok {
			needClaudeIDs[model.ID] = true
		}
	}
	for id, found := range needClaudeIDs {
		if !found {
			t.Fatalf("missing claude model %q", id)
		}
	}

	kimi := cfg.Providers["kimi"]
	if kimi.API != "anthropic-messages" {
		t.Fatalf("kimi api = %q", kimi.API)
	}
	if len(kimi.Models) != 2 {
		t.Fatalf("kimi model count = %d", len(kimi.Models))
	}
	needKimiIDs := map[string]bool{
		"k2p5":             false,
		"kimi-k2-thinking": false,
	}
	for _, model := range kimi.Models {
		if _, ok := needKimiIDs[model.ID]; ok {
			needKimiIDs[model.ID] = true
		}
		if len(model.Input) != 2 || model.Input[0] != "text" || model.Input[1] != "image" {
			t.Fatalf("kimi model %q inputs = %#v, want text+image", model.ID, model.Input)
		}
	}
	for id, found := range needKimiIDs {
		if !found {
			t.Fatalf("missing kimi model %q", id)
		}
	}

	minimax := cfg.Providers["minimax"]
	if minimax.API != "anthropic-messages" {
		t.Fatalf("minimax api = %q", minimax.API)
	}
	if len(minimax.Models) != 2 {
		t.Fatalf("minimax model count = %d", len(minimax.Models))
	}
	needMinimaxIDs := map[string]bool{
		"MiniMax-M2.7":           false,
		"MiniMax-M2.7-highspeed": false,
	}
	for _, model := range minimax.Models {
		if _, ok := needMinimaxIDs[model.ID]; ok {
			needMinimaxIDs[model.ID] = true
		}
		if len(model.Input) != 2 || model.Input[0] != "text" || model.Input[1] != "image" {
			t.Fatalf("minimax model %q inputs = %#v, want text+image", model.ID, model.Input)
		}
	}
	for id, found := range needMinimaxIDs {
		if !found {
			t.Fatalf("missing minimax model %q", id)
		}
	}

	zai := cfg.Providers["zai"]
	if zai.API != "anthropic-messages" {
		t.Fatalf("zai api = %q", zai.API)
	}
	if len(zai.Models) != 1 {
		t.Fatalf("zai model count = %d", len(zai.Models))
	}
	if zai.Models[0].ID != "glm-5.1" {
		t.Fatalf("unexpected zai model id = %q", zai.Models[0].ID)
	}
	if len(zai.Models[0].Input) != 2 || zai.Models[0].Input[0] != "text" || zai.Models[0].Input[1] != "image" {
		t.Fatalf("zai model inputs = %#v, want text+image", zai.Models[0].Input)
	}
}

func TestIsKimiModelHandlesPiBuiltInIDs(t *testing.T) {
	t.Parallel()

	for _, model := range []string{"kimi", "kimi-for-coding", "k2p5", "kimi-k2-thinking"} {
		if !isKimiModel(model) {
			t.Fatalf("expected %q to route to kimi", model)
		}
	}
}

func TestMinimaxCanonicalModelHandlesPiBuiltInIDs(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"minimax":                "MiniMax-M2.5",
		"MiniMax-M2":             "MiniMax-M2",
		"MiniMax-M2.1":           "MiniMax-M2.1",
		"MiniMax-M2.5":           "MiniMax-M2.5",
		"MiniMax-M2.7":           "MiniMax-M2.7",
		"MiniMax-M2.7-highspeed": "MiniMax-M2.7-highspeed",
	}

	for input, want := range tests {
		if got := minimaxCanonicalModel(input); got != want {
			t.Fatalf("minimaxCanonicalModel(%q) = %q, want %q", input, got, want)
		}
		if !isMinimaxModel(input) {
			t.Fatalf("expected %q to route to minimax", input)
		}
	}
}
