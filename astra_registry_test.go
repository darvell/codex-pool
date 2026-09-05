package main

import (
	"encoding/json"
	"testing"
)

func TestAstraRegistry(t *testing.T) {
	model, ok := modelForProvider(AccountTypeCodex, "gpt-6-astra")
	if !ok || model.ContextWindow != 272000 || model.MaxTokens != 128000 || !model.Reasoning || !model.WebSearch {
		t.Fatalf("Astra catalog metadata = %+v, present=%v", model, ok)
	}
	variant, ok := modelForProvider(AccountTypeCodex, "gpt-6-astra[1m]")
	if !ok || variant.ContextWindow != 1000000 || variant.MaxTokens != 128000 || !variant.Reasoning || !variant.WebSearch {
		t.Fatalf("Astra 1M catalog metadata = %+v, present=%v", variant, ok)
	}
	if resolved, aliased := newModelAliases(nil).resolve("gpt-6-astra[1m]"); !aliased || resolved != "gpt-6-astra" {
		t.Fatalf("Astra 1M alias = %q, aliased=%v", resolved, aliased)
	}
	if defaultModelForProvider[AccountTypeCodex] != model.ID {
		t.Fatalf("Codex default = %q", defaultModelForProvider[AccountTypeCodex])
	}
	found := false
	for _, item := range piModelsForProvider(AccountTypeCodex) {
		if item.ID != model.ID {
			continue
		}
		found = true
		if item.ContextWindow != model.ContextWindow || item.MaxTokens != model.MaxTokens || item.ThinkingLevelMap["max"] != "max" || item.ThinkingLevelMap["xhigh"] != "xhigh" {
			t.Fatalf("Astra client metadata = %+v", item)
		}
	}
	if !found {
		t.Fatal("Astra missing from client model export")
	}
	body, err := generateCuteCodeSettingsJSON("https://pool.example", "test-key")
	if err != nil {
		t.Fatal(err)
	}
	var settings cuteCodeSettings
	if err := json.Unmarshal(body, &settings); err != nil {
		t.Fatal(err)
	}
	if settings.Model != model.ID {
		t.Fatalf("generated model default = %q", settings.Model)
	}
	if legacy, ok := modelForProvider(AccountTypeCodex, "gpt-5.6"); !ok || legacy.ID != "gpt-5.6-sol" {
		t.Fatal("explicit GPT-5.6 selection was redirected")
	}
}

func TestAstraAccountEntitlement(t *testing.T) {
	entitled := &Account{ID: "entitled", Type: AccountTypeCodex, PlanType: "pro", Models: map[string]DiscoveredModel{"gpt-6-astra": {ID: "gpt-6-astra", ContextWindow: 272000}}}
	other := &Account{ID: "other", Type: AccountTypeCodex, PlanType: "pro"}
	pool := newPoolState([]*Account{entitled, other}, false)
	if !pool.discoveredModelRequiresEntitlement(AccountTypeCodex, "gpt-6-astra") {
		t.Fatal("catalog inclusion bypassed account entitlement")
	}
	if got := pool.candidateForModel("", map[string]bool{entitled.ID: true}, AccountTypeCodex, "", "", "gpt-6-astra"); got != nil {
		t.Fatalf("selected account without Astra: %s", got.ID)
	}
	found := 0
	for _, model := range poolModelDescriptors(pool) {
		if model.ID != "gpt-6-astra" {
			continue
		}
		found++
		if model.ContextWindow != 272000 || model.MaxOutputTokens != 128000 || model.SupportingAccounts != 1 || model.AvailableAccounts != 1 {
			t.Fatalf("Astra descriptor = %+v", model)
		}
	}
	if found != 1 {
		t.Fatalf("Astra descriptor count = %d", found)
	}
	cold := newPoolState([]*Account{other}, false)
	if got := cold.candidateForModel("", nil, AccountTypeCodex, "", "", "gpt-6-astra"); got != nil {
		t.Fatal("Astra routed before an account advertised access")
	}
}
