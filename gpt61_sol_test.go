package main

import "testing"

func TestGPT61SolRegistry(t *testing.T) {
	model, ok := modelForProvider(AccountTypeCodex, "gpt-6.1-sol")
	if !ok || model.ContextWindow != 500000 || model.MaxTokens != 128000 || !model.Reasoning || !model.RequiresDiscovery {
		t.Fatalf("GPT-6.1-Sol catalog metadata = %+v, present=%v", model, ok)
	}

	variant, ok := modelForProvider(AccountTypeCodex, "gpt-6.1-sol[1m]")
	if !ok || variant.ContextWindow != 1000000 || variant.MaxTokens != 128000 || !variant.Reasoning || !variant.RequiresDiscovery {
		t.Fatalf("GPT-6.1-Sol 1M catalog metadata = %+v, present=%v", variant, ok)
	}

	if resolved, aliased := newModelAliases(nil).resolve("gpt-6.1-sol[1m]"); !aliased || resolved != "gpt-6.1-sol" {
		t.Fatalf("GPT-6.1-Sol 1M alias = %q, aliased=%v", resolved, aliased)
	}
}
