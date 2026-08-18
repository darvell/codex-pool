package main

import (
	"testing"
	"time"
)

func TestCodexProLiteSubscriptionCost(t *testing.T) {
	t.Parallel()

	for _, plan := range []string{"prolite", "PROLITE", " ProLite "} {
		monthly, label := getSubscriptionCost(AccountTypeCodex, plan)
		if monthly != 100 || label != "Codex Pro Lite" {
			t.Fatalf("getSubscriptionCost(codex, %q) = (%v, %q), want (100, %q)", plan, monthly, label, "Codex Pro Lite")
		}
	}
}

func TestUnknownTokenPlanTierDoesNotInventSubscriptionSpend(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		accountType AccountType
		plan        string
		label       string
	}{
		{AccountTypeKimi, "kimi", "Kimi Token Plan"},
		{AccountTypeMinimax, "minimax", "MiniMax Token Plan"},
	} {
		monthly, label := getSubscriptionCost(test.accountType, test.plan)
		if monthly != 0 || label != test.label {
			t.Fatalf("getSubscriptionCost(%s, %q) = (%v, %q), want (0, %q)", test.accountType, test.plan, monthly, label, test.label)
		}
	}
}

func TestEstimateSubscriptionSpendUsesObservedBillingCycles(t *testing.T) {
	now := time.Date(2026, time.July, 13, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		firstSeen  time.Time
		wantSpend  float64
		wantCycles int
	}{
		{name: "current cycle", firstSeen: now, wantSpend: 200, wantCycles: 1},
		{name: "before first renewal", firstSeen: now.Add(-29 * 24 * time.Hour), wantSpend: 200, wantCycles: 1},
		{name: "first renewal", firstSeen: now.Add(-30 * 24 * time.Hour), wantSpend: 400, wantCycles: 2},
		{name: "six observed cycles", firstSeen: now.Add(-171 * 24 * time.Hour), wantSpend: 1200, wantCycles: 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spend, cycles := estimateSubscriptionSpend(200, tt.firstSeen, now)
			if spend != tt.wantSpend || cycles != tt.wantCycles {
				t.Fatalf("estimateSubscriptionSpend() = (%v, %d), want (%v, %d)", spend, cycles, tt.wantSpend, tt.wantCycles)
			}
		})
	}
}

func TestAccountPlanForSubscriptionPreservesProLite(t *testing.T) {
	t.Parallel()

	for _, plan := range []string{"prolite", "PROLITE", "Codex ProLite"} {
		if got := accountPlanForSubscription(plan); got != "prolite" {
			t.Fatalf("accountPlanForSubscription(%q) = %q, want prolite", plan, got)
		}
	}
}

func TestLookupPricingUsesClaudeSonnet5Aliases(t *testing.T) {
	t.Parallel()

	pd := newPricingData()
	want, ok := pd.lookupPricing("claude-sonnet-5")
	if !ok {
		t.Fatal("missing Claude Sonnet 5 pricing")
	}
	for _, model := range []string{"claude-sonnet-5 [1m]", "claude-sonnet-5[1m]"} {
		got, ok := pd.lookupPricing(model)
		if !ok || got != want {
			t.Fatalf("lookupPricing(%q) = %#v, %v; want %#v, true", model, got, ok, want)
		}
	}
}

func TestLookupPricingIncludesClaudeOpus5Fallback(t *testing.T) {
	t.Parallel()

	pd := newPricingData()
	got, ok := pd.lookupPricing("claude-opus-5")
	if !ok {
		t.Fatal("missing Claude Opus 5 fallback pricing")
	}
	if got.InputCostPerToken != 5e-6 || got.OutputCostPerToken != 25e-6 || got.CacheReadCost != 0.5e-6 {
		t.Fatalf("Claude Opus 5 pricing = %#v", got)
	}
	for _, model := range []string{"claude-opus-5 [1m]", "claude-opus-5[1m]"} {
		if aliased, ok := pd.lookupPricing(model); !ok || aliased != got {
			t.Fatalf("lookupPricing(%q) = %#v, %v; want %#v, true", model, aliased, ok, got)
		}
	}
}

func TestLookupPricingGLM53UsesPublishedRates(t *testing.T) {
	t.Parallel()

	pd := newPricingData()
	want := ModelPricing{
		InputCostPerToken:  1.4e-6,
		OutputCostPerToken: 4.4e-6,
		CacheReadCost:      0.26e-6,
	}
	// "zai.glm-5.3" must not fall through the prefix search to "zai.glm-5",
	// which is priced at the cheaper GLM-5 rates.
	for _, model := range []string{"glm-5.3", "zai.glm-5.3", "glm-5.2", "zai.glm-5.2"} {
		got, ok := pd.lookupPricing(model)
		if !ok {
			t.Fatalf("missing pricing for %q", model)
		}
		if got != want {
			t.Fatalf("lookupPricing(%q) = %#v, want %#v", model, got, want)
		}
	}
}

func TestAdvertisedPoolModelsHavePricing(t *testing.T) {
	t.Parallel()

	for _, accountType := range []AccountType{
		AccountTypeCodex, AccountTypeClaude, AccountTypeKimi, AccountTypeMinimax,
		AccountTypeZAI, AccountTypeXiaomi, AccountTypeAdverserial,
	} {
		for _, model := range modelsForProvider(accountType) {
			cost := advertisedModelCost(model.ID, time.Now())
			if cost.Input <= 0 || cost.Output <= 0 {
				t.Errorf("%s/%s advertised cost = %#v", accountType, model.ID, cost)
			}
		}
	}
	for _, model := range grokModelCatalog {
		cost := advertisedModelCost(model.ID, time.Now())
		if cost.Input <= 0 || cost.Output <= 0 {
			t.Errorf("grok/%s advertised cost = %#v", model.ID, cost)
		}
	}
}

func TestLoadFromJSONParsesLongContextRates(t *testing.T) {
	t.Parallel()

	pd := &PricingData{}
	pd.loadFromJSON([]byte(`{
		"tiered-test": {
			"input_cost_per_token": 0.000001,
			"output_cost_per_token": 0.000002,
			"cache_read_input_token_cost": 0.0000001,
			"input_cost_per_token_above_200k_tokens": 0.000003,
			"output_cost_per_token_above_200k_tokens": 0.000004,
			"cache_read_input_token_cost_above_200k_tokens": 0.0000002
		}
	}`))
	got, ok := pd.lookupPricing("tiered-test")
	if !ok {
		t.Fatal("missing parsed tiered pricing")
	}
	if got.LongContextThreshold != 200000 || got.LongInputCost != 3e-6 || got.LongOutputCost != 4e-6 || got.LongCacheReadCost != 0.2e-6 {
		t.Fatalf("tiered pricing = %#v", got)
	}
}

func TestCalculateCostUsesProviderTokenSemantics(t *testing.T) {
	t.Parallel()

	pd := newPricingData()
	claude := pd.calculateCost(RequestUsage{
		AccountType:         AccountTypeClaude,
		Model:               "claude-sonnet-5",
		InputTokens:         100,
		CachedInputTokens:   900,
		CacheCreationTokens: 100,
		OutputTokens:        10,
		InputTokenMode:      "exclusive",
	})
	wantClaude := 100*2e-6 + 900*0.2e-6 + 100*2.5e-6 + 10*10e-6
	if claude < wantClaude-1e-12 || claude > wantClaude+1e-12 {
		t.Fatalf("Claude cost = %.12f, want %.12f", claude, wantClaude)
	}

	openAI := pd.calculateCost(RequestUsage{
		AccountType:       AccountTypeCodex,
		Model:             "gpt-5.6-sol",
		InputTokens:       1000,
		CachedInputTokens: 900,
		OutputTokens:      10,
		InputTokenMode:    "inclusive",
	})
	wantOpenAI := 100*5e-6 + 900*0.5e-6 + 10*30e-6
	if openAI < wantOpenAI-1e-12 || openAI > wantOpenAI+1e-12 {
		t.Fatalf("OpenAI cost = %.12f, want %.12f", openAI, wantOpenAI)
	}
}

func TestCalculateCostAppliesLongContextTier(t *testing.T) {
	t.Parallel()

	pd := newPricingData()
	cost := pd.calculateCost(RequestUsage{
		AccountType:       AccountTypeCodex,
		Model:             "gpt-5.6-sol",
		InputTokens:       300_000,
		CachedInputTokens: 200_000,
		OutputTokens:      1_000,
		InputTokenMode:    "inclusive",
	})
	want := 100_000*10e-6 + 200_000*1e-6 + 1_000*45e-6
	if cost < want-1e-12 || cost > want+1e-12 {
		t.Fatalf("long-context cost = %.12f, want %.12f", cost, want)
	}
}

func TestLookupPricingDoesNotGuessByPrefix(t *testing.T) {
	t.Parallel()

	pd := newPricingData()
	if _, ok := pd.lookupPricing("zai.glm-5.99"); ok {
		t.Fatal("unknown model inherited a price by prefix")
	}
}

func TestCalculateCostZAIRequestIsNotFree(t *testing.T) {
	t.Parallel()

	pd := newPricingData()
	cost := pd.calculateCost(RequestUsage{
		AccountType:  AccountTypeZAI,
		Model:        "glm-5.3",
		InputTokens:  1_000_000,
		OutputTokens: 1_000_000,
	})
	if cost <= 0 {
		t.Fatalf("GLM-5.3 request cost = %v, want > 0", cost)
	}
	if want := 1.4 + 4.4; cost < want-1e-9 || cost > want+1e-9 {
		t.Fatalf("GLM-5.3 request cost = %v, want %v", cost, want)
	}
}
