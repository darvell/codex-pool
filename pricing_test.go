package main

import "testing"

func TestCodexProLiteSubscriptionCost(t *testing.T) {
	t.Parallel()

	for _, plan := range []string{"prolite", "PROLITE", " ProLite "} {
		monthly, label := getSubscriptionCost(AccountTypeCodex, plan)
		if monthly != 100 || label != "Codex Pro Lite" {
			t.Fatalf("getSubscriptionCost(codex, %q) = (%v, %q), want (100, %q)", plan, monthly, label, "Codex Pro Lite")
		}
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
