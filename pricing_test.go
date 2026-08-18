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

func TestLookupPricingUsesClaudeSonnet5Alias(t *testing.T) {
	t.Parallel()

	pd := &PricingData{models: map[string]ModelPricing{
		"claude-sonnet-4-6": {
			InputCostPerToken:  0.000003,
			OutputCostPerToken: 0.000015,
			CacheReadCost:      0.0000003,
		},
	}}

	want, ok := pd.lookupPricing("claude-sonnet-4-6")
	if !ok {
		t.Fatal("missing seed pricing for claude-sonnet-4-6")
	}

	for _, model := range []string{"claude-sonnet-5", "claude-sonnet-5 [1m]", "claude-sonnet-5[1m]"} {
		got, ok := pd.lookupPricing(model)
		if !ok {
			t.Fatalf("lookupPricing(%q) did not resolve alias", model)
		}
		if got != want {
			t.Fatalf("lookupPricing(%q) = %#v, want %#v", model, got, want)
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
