package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestClaudeCanonicalModelHandlesShortOneMillionAliases(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"sonnet":      "claude-sonnet-5",
		"sonnet[1m]":  "claude-sonnet-5 [1m]",
		"sonnet [1m]": "claude-sonnet-5 [1m]",
		"opus":        "claude-opus-4-8",
		"opus[1m]":    "claude-opus-4-8 [1m]",
		"opus [1m]":   "claude-opus-4-8 [1m]",
		"fable":       "claude-fable-5",
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
		"gpt-5.6-sol":         {contextWindow: 372000, maxTokens: 128000},
		"gpt-5.6-terra":       {contextWindow: 372000, maxTokens: 128000},
		"gpt-5.6-luna":        {contextWindow: 372000, maxTokens: 128000},
		"gpt-5.5":             {contextWindow: 272000, maxTokens: 128000},
		"gpt-5.4":             {contextWindow: 272000, maxTokens: 128000},
		"gpt-5.4-mini":        {contextWindow: 272000, maxTokens: 128000},
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
		if model.ID == "gpt-5.6" || model.ID == "gpt-5.6-sol" || model.ID == "gpt-5.6-terra" || model.ID == "gpt-5.6-luna" {
			if model.ThinkingLevelMap["xhigh"] != "xhigh" || model.ThinkingLevelMap["max"] != "max" {
				t.Fatalf("codex model %q thinking levels = %#v, want xhigh+max", model.ID, model.ThinkingLevelMap)
			}
		} else if len(model.ThinkingLevelMap) != 0 {
			t.Fatalf("codex model %q unexpectedly advertises extended thinking levels: %#v", model.ID, model.ThinkingLevelMap)
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
		"claude-haiku-4-5-20251001": false,
		"claude-sonnet-5":           false,
		"claude-sonnet-4-6":         false,
		"claude-fable-5":            false,
		"claude-opus-4-8":           false,
		"claude-opus-4-7":           false,
		"claude-opus-4-6":           false,
	}
	for _, model := range claude.Models {
		if _, ok := needClaudeIDs[model.ID]; ok {
			needClaudeIDs[model.ID] = true
		}
		if !ccModelSupportsEffort(model.ID) {
			if model.Compat != nil || len(model.ThinkingLevelMap) != 0 {
				t.Fatalf("claude model %q unexpectedly advertises adaptive thinking: %#v %#v", model.ID, model.Compat, model.ThinkingLevelMap)
			}
			continue
		}
		if model.Compat == nil || !model.Compat.ForceAdaptiveThinking || model.ThinkingLevelMap["max"] != "max" {
			t.Fatalf("claude model %q missing adaptive max metadata: %#v %#v", model.ID, model.Compat, model.ThinkingLevelMap)
		}
		canonical := ccCanonicalClaudeModel(model.ID)
		wantXHigh := strings.Contains(canonical, "sonnet-5") || strings.Contains(canonical, "opus-4-7") || strings.Contains(canonical, "fable-5")
		if gotXHigh := model.ThinkingLevelMap["xhigh"] == "xhigh"; gotXHigh != wantXHigh {
			t.Fatalf("claude model %q xhigh support = %v, want %v", model.ID, gotXHigh, wantXHigh)
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
		"kimi-for-coding":           false,
		"kimi-for-coding-highspeed": false,
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
	if len(minimax.Models) != 3 {
		t.Fatalf("minimax model count = %d", len(minimax.Models))
	}
	needMinimaxIDs := map[string]bool{
		"MiniMax-M3":             false,
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
		if model.ID == "MiniMax-M3" && model.ContextWindow != 1000000 {
			t.Fatalf("minimax m3 context window = %d, want 1000000", model.ContextWindow)
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
	wantZAIContexts := map[string]int{
		"glm-5.2": 1000000,
	}
	for _, model := range zai.Models {
		wantContext, ok := wantZAIContexts[model.ID]
		if !ok {
			t.Fatalf("unexpected zai model id = %q", model.ID)
		}
		if model.ContextWindow != wantContext {
			t.Fatalf("zai model %q context window = %d, want %d", model.ID, model.ContextWindow, wantContext)
		}
		if len(model.Input) != 1 || model.Input[0] != "text" {
			t.Fatalf("zai model %q inputs = %#v, want text", model.ID, model.Input)
		}
		delete(wantZAIContexts, model.ID)
	}
	for id := range wantZAIContexts {
		t.Fatalf("missing zai model %q", id)
	}

	grok := cfg.Providers["grok"]
	if grok.API != "openai-responses" {
		t.Fatalf("grok api = %q", grok.API)
	}
	if grok.BaseURL != "https://pool.example.com" {
		t.Fatalf("grok baseUrl = %q", grok.BaseURL)
	}
	if len(grok.Models) != 7 {
		t.Fatalf("grok model count = %d", len(grok.Models))
	}
	wantGrokContexts := map[string]int{
		"grok-4.5":                     500000,
		"grok-composer-2.5-fast":       200000,
		"grok-build":                   512000,
		"grok-4.3":                     1000000,
		"grok-4.20-0309-reasoning":     2000000,
		"grok-4.20-0309-non-reasoning": 2000000,
		"grok-4.20-multi-agent-0309":   2000000,
	}
	for _, model := range grok.Models {
		if want, ok := wantGrokContexts[model.ID]; !ok || model.ContextWindow != want || model.MaxTokens != 30000 {
			t.Fatalf("grok model %q limits = (%d, %d)", model.ID, model.ContextWindow, model.MaxTokens)
		}
	}
}

func TestGeneratedClientConfigsIncludeDiscoveredAntigravityModels(t *testing.T) {
	antigravityModels.Reset()
	t.Cleanup(antigravityModels.Reset)
	antigravityModels.ReplaceAccount("antigravity-test", AntigravityAccountSnapshot{
		FetchedAt: time.Now(),
		Models: map[string]AntigravityModelInfo{
			"gemini-live": {ID: "gemini-live", DisplayName: "Gemini Live", MaxTokens: 1000000, MaxOutputTokens: 65536, SupportsThinking: true},
		},
	})
	piJSON, err := generatePiModelsJSON("https://pool.example.com", "codex-token", "claude-token")
	if err != nil {
		t.Fatal(err)
	}
	var piConfig piModelsConfig
	if err := json.Unmarshal(piJSON, &piConfig); err != nil {
		t.Fatal(err)
	}
	if models := piConfig.Providers["antigravity"].Models; len(models) != 1 || models[0].ID != "antigravity/gemini-live" {
		t.Fatalf("Pi Antigravity models = %#v", models)
	}
	cuteJSON, err := generateCuteCodeSettingsJSON("https://pool.example.com", "pool-token")
	if err != nil {
		t.Fatal(err)
	}
	var cuteConfig cuteCodeSettings
	if err := json.Unmarshal(cuteJSON, &cuteConfig); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, model := range cuteConfig.CustomModels {
		if model.ID == "antigravity/gemini-live" {
			found = true
		}
	}
	if !found {
		t.Fatal("Cute Code Antigravity model missing")
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
		"minimax":                "MiniMax-M3",
		"minimax-m3":             "MiniMax-M3",
		"MiniMax-M3":             "MiniMax-M3",
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

func TestGrokCanonicalModelHandlesCodeAliases(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"grok-4.5":                     "grok-4.5",
		"grok-4.5-build":               "grok-4.5",
		"grok-build":                   "grok-build",
		"grok-composer-2.5-fast":       "grok-composer-2.5-fast",
		"grok-composer":                "grok-composer-2.5-fast",
		"grok-code-fast":               "grok-composer-2.5-fast",
		"grok-4.3":                     "grok-4.3",
		"grok-4.20-0309-reasoning":     "grok-4.20-0309-reasoning",
		"grok-4.20-0309-non-reasoning": "grok-4.20-0309-non-reasoning",
		"grok-4.20-multi-agent-0309":   "grok-4.20-multi-agent-0309",
	}

	for input, want := range tests {
		if got := grokCanonicalModel(input); got != want {
			t.Fatalf("grokCanonicalModel(%q) = %q, want %q", input, got, want)
		}
		if !isGrokModel(input) {
			t.Fatalf("expected %q to route to grok", input)
		}
	}
}
