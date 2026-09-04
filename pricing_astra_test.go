package main

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

func TestAstraPublishedPricing(t *testing.T) {
	want := tieredPricing(10, 50, 1, 12.5, 272000, 20, 75, 2, 25)
	pd := newPricingData()
	for _, model := range []string{"gpt-6-astra", "gpt-6-astra[1m]", "gpt-6-astra [1m]", "gpt-6-astra-high", "gpt-6-astra[1m]-xhigh", "gpt-6-astra-none"} {
		got, ok := pd.lookupPricing(model)
		if !ok || got != want {
			t.Errorf("lookupPricing(%q) = %#v, %v; want %#v", model, got, ok, want)
		}
	}
	cost := advertisedModelCost("gpt-6-astra", time.Now())
	if cost.Input != 10 || cost.Output != 50 || cost.CacheRead != 1 || cost.CacheWrite != 12.5 {
		t.Errorf("advertised Astra cost = %#v", cost)
	}
	pd.loadFromJSON([]byte(`{"gpt-6-astra":{"input_cost_per_token":0.000001,"output_cost_per_token":0.000002}}`))
	if got, ok := pd.lookupPricing("gpt-6-astra"); !ok || got != want {
		t.Errorf("stale fetched pricing won: %#v, %v", got, ok)
	}
	if _, ok := pd.lookupPricing("gpt-6-astra-unknown"); ok {
		t.Error("unknown Astra suffix inherited pricing")
	}
}

func TestAstraCostThreshold(t *testing.T) {
	pd := newPricingData()
	for _, tt := range []struct {
		name  string
		input int64
		want  float64
	}{
		{"below", 271999, 161999*10e-6 + 100000*1e-6 + 10000*12.5e-6 + 1000*50e-6},
		{"at", 272000, 162000*10e-6 + 100000*1e-6 + 10000*12.5e-6 + 1000*50e-6},
		{"above", 272001, 162001*20e-6 + 100000*2e-6 + 10000*25e-6 + 1000*75e-6},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := pd.calculateCost(RequestUsage{AccountType: AccountTypeCodex, Model: "gpt-6-astra", InputTokens: tt.input, CachedInputTokens: 100000, CacheCreationTokens: 10000, OutputTokens: 1000, ReasoningTokens: 800, InputTokenMode: "inclusive"})
			if math.Abs(got-tt.want) > 1e-12 {
				t.Fatalf("cost = %.12f, want %.12f", got, tt.want)
			}
		})
	}
}

func TestCodexReasoningCost(t *testing.T) {
	pd := newPricingData()
	var event map[string]any
	// The Responses reasoning guide reports reasoning as a subset of output.
	if err := json.Unmarshal([]byte(`{"response":{"model":"gpt-5.6-sol","usage":{"input_tokens":75,"input_tokens_details":{"cached_tokens":0},"output_tokens":1186,"output_tokens_details":{"reasoning_tokens":1024},"total_tokens":1261}}}`), &event); err != nil {
		t.Fatal(err)
	}
	ru := (&CodexProvider{}).ParseUsage(event)
	if ru == nil || ru.OutputTokens != 1186 || ru.ReasoningTokens != 1024 {
		t.Fatalf("parsed usage = %#v", ru)
	}
	ru.AccountType = AccountTypeCodex
	want := 75*5e-6 + 1186*30e-6
	if got := pd.calculateCost(*ru); math.Abs(got-want) > 1e-12 {
		t.Fatalf("Codex cost = %.12f, want %.12f", got, want)
	}
}

func TestAstraCacheWriteUsage(t *testing.T) {
	var event map[string]any
	if err := json.Unmarshal([]byte(`{"response":{"model":"gpt-6-astra","usage":{"input_tokens":272001,"input_tokens_details":{"cached_tokens":100000,"cache_write_tokens":10000},"output_tokens":1000,"output_tokens_details":{"reasoning_tokens":800}}}}`), &event); err != nil {
		t.Fatal(err)
	}
	ru := (&CodexProvider{}).ParseUsage(event)
	if ru == nil || ru.CacheCreationTokens != 10000 || ru.CachedInputTokens != 100000 || ru.InputTokens != 272001 {
		t.Fatalf("parsed cache usage = %#v", ru)
	}
	ru.AccountType = AccountTypeCodex
	if got, want := newPricingData().calculateCost(*ru), 3.76502; math.Abs(got-want) > 1e-12 {
		t.Fatalf("parsed Astra cost = %.12f, want %.12f", got, want)
	}
}

func TestNonCodexReasoningCost(t *testing.T) {
	pd := newPricingData()
	for _, provider := range []AccountType{AccountTypeGemini, AccountTypeAntigravity, AccountTypeClaude} {
		usage := RequestUsage{AccountType: provider, Model: "gemini-3.1-pro-preview", OutputTokens: 100, ReasoningTokens: 200}
		want := 300 * 12e-6
		if got := pd.calculateCost(usage); math.Abs(got-want) > 1e-12 {
			t.Errorf("%s cost = %.12f, want %.12f", provider, got, want)
		}
	}
}
