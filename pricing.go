package main

import (
	_ "embed"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed pricing_fallback.json
var fallbackPricingJSON []byte

const litellmPricingURL = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"

// ModelPricing holds per-token costs (in USD per token).
type ModelPricing struct {
	InputCostPerToken  float64 `json:"input_cost_per_token"`
	OutputCostPerToken float64 `json:"output_cost_per_token"`
	CacheReadCost      float64 `json:"cache_read_input_token_cost"`
	CacheWriteCost     float64 `json:"cache_creation_input_token_cost"`
}

// PricingData holds the loaded pricing map and provides thread-safe lookup.
type PricingData struct {
	mu     sync.RWMutex
	models map[string]ModelPricing
}

// subscriptionCosts maps (account_type, plan_type) to monthly cost in USD.
type subscriptionKey struct {
	accountType AccountType
	planType    string
}

var subscriptionCosts = map[subscriptionKey]struct {
	monthly float64
	label   string
}{
	{AccountTypeClaude, "pro"}:                    {20, "Claude Pro"},
	{AccountTypeClaude, "max_5x"}:                 {100, "Claude Max 5x"},
	{AccountTypeClaude, "default_claude_max_5x"}:  {100, "Claude Max 5x"},
	{AccountTypeClaude, "max_20x"}:                {200, "Claude Max 20x"},
	{AccountTypeClaude, "default_claude_max_20x"}: {200, "Claude Max 20x"},
	{AccountTypeClaude, "team"}:                   {25, "Claude Team"},
	{AccountTypeCodex, "plus"}:                    {20, "Codex Plus"},
	{AccountTypeCodex, "pro"}:                     {200, "Codex Pro"},
	{AccountTypeCodex, "team"}:                    {25, "Codex Team"},
	{AccountTypeGemini, "api"}:                    {0, "Gemini API"},
	{AccountTypeKimi, "api"}:                      {49, "Kimi Coding"},
	{AccountTypeKimi, ""}:                         {49, "Kimi Coding"},
	{AccountTypeMinimax, "api"}:                   {5, "MiniMax API"},
	{AccountTypeMinimax, ""}:                      {5, "MiniMax API"},
	{AccountTypeZAI, "zai"}:                       {0, "Z.ai Coding Plan"},
	{AccountTypeZAI, ""}:                          {0, "Z.ai Coding Plan"},
}

// getSubscriptionCost returns monthly cost and label for an account.
func getSubscriptionCost(accType AccountType, planType string) (monthly float64, label string) {
	// Try exact match first
	if info, ok := subscriptionCosts[subscriptionKey{accType, planType}]; ok {
		return info.monthly, info.label
	}
	// Try empty plan fallback
	if info, ok := subscriptionCosts[subscriptionKey{accType, ""}]; ok {
		return info.monthly, info.label
	}
	return 0, string(accType)
}

// newPricingData loads pricing from the embedded fallback.
func newPricingData() *PricingData {
	pd := &PricingData{
		models: make(map[string]ModelPricing),
	}
	pd.loadFromJSON(fallbackPricingJSON)
	return pd
}

// loadFromJSON parses the LiteLLM pricing JSON format into the models map.
func (pd *PricingData) loadFromJSON(data []byte) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Printf("pricing: failed to parse JSON: %v", err)
		return
	}

	models := make(map[string]ModelPricing, len(raw))
	for key, val := range raw {
		if key == "sample_spec" {
			continue
		}
		var entry struct {
			InputCost      *float64 `json:"input_cost_per_token"`
			OutputCost     *float64 `json:"output_cost_per_token"`
			CacheCost      *float64 `json:"cache_read_input_token_cost"`
			CacheWriteCost *float64 `json:"cache_creation_input_token_cost"`
		}
		if err := json.Unmarshal(val, &entry); err != nil {
			continue
		}
		if entry.InputCost == nil || entry.OutputCost == nil {
			continue
		}
		mp := ModelPricing{
			InputCostPerToken:  *entry.InputCost,
			OutputCostPerToken: *entry.OutputCost,
		}
		if entry.CacheCost != nil {
			mp.CacheReadCost = *entry.CacheCost
		}
		if entry.CacheWriteCost != nil {
			mp.CacheWriteCost = *entry.CacheWriteCost
		}
		models[key] = mp
	}

	pd.mu.Lock()
	pd.models = models
	pd.mu.Unlock()
	log.Printf("pricing: loaded %d model prices", len(models))
}

// fetchAndUpdate fetches the latest pricing from LiteLLM and updates the models map.
func (pd *PricingData) fetchAndUpdate() {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(litellmPricingURL)
	if err != nil {
		log.Printf("pricing: fetch failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("pricing: fetch returned %s", resp.Status)
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		log.Printf("pricing: read failed: %v", err)
		return
	}
	pd.loadFromJSON(data)
}

// startPricingRefresh fetches pricing on startup and refreshes every 24h.
func (pd *PricingData) startPricingRefresh() {
	// Fetch fresh data on startup (in background)
	go pd.fetchAndUpdate()

	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		for range ticker.C {
			pd.fetchAndUpdate()
		}
	}()
}

// lookupPricing finds pricing for a model. Tries exact match, then prefix match, then provider-type fallback.
func (pd *PricingData) lookupPricing(model string) (ModelPricing, bool) {
	if model == "" {
		return ModelPricing{}, false
	}

	pd.mu.RLock()
	defer pd.mu.RUnlock()

	// Exact match
	if mp, ok := pd.models[model]; ok {
		return mp, true
	}

	// Try without date suffix (e.g., "claude-sonnet-4-5-20250929" -> "claude-sonnet-4-5")
	// LiteLLM often has both versioned and unversioned entries
	parts := strings.Split(model, "-")
	for i := len(parts) - 1; i >= 1; i-- {
		// Check if the last part looks like a date (8 digits)
		if len(parts[i]) == 8 && isAllDigits(parts[i]) {
			prefix := strings.Join(parts[:i], "-")
			if mp, ok := pd.models[prefix]; ok {
				return mp, true
			}
		}
	}

	// Prefix match: find longest matching prefix
	var bestMatch string
	var bestPricing ModelPricing
	for key, mp := range pd.models {
		if strings.HasPrefix(model, key) && len(key) > len(bestMatch) {
			bestMatch = key
			bestPricing = mp
		}
	}
	if bestMatch != "" {
		return bestPricing, true
	}

	return ModelPricing{}, false
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// calculateCost computes the estimated API cost for a request.
// Formula: uncached_input * input_price + cache_read * cache_read_price
//        + cache_creation * cache_write_price + (output + reasoning) * output_price
// defaultModelForProvider returns a fallback model name when the request didn't include one.
var defaultModelForProvider = map[AccountType]string{
	AccountTypeCodex:   "gpt-5.2-codex",
	AccountTypeClaude:  "claude-sonnet-4-5",
	AccountTypeKimi:    "moonshot.kimi-k2-thinking",
	AccountTypeMinimax: "minimax.minimax-m2",
	AccountTypeZAI:     "zai.glm-5.1",
}

func (pd *PricingData) calculateCost(ru RequestUsage) float64 {
	model := ru.Model
	if model == "" {
		model = defaultModelForProvider[ru.AccountType]
	}
	mp, ok := pd.lookupPricing(model)
	if !ok {
		return 0
	}

	uncachedInput := ru.InputTokens - ru.CachedInputTokens - ru.CacheCreationTokens
	if uncachedInput < 0 {
		uncachedInput = 0
	}

	cost := float64(uncachedInput) * mp.InputCostPerToken
	cost += float64(ru.CachedInputTokens) * mp.CacheReadCost
	cost += float64(ru.CacheCreationTokens) * mp.CacheWriteCost
	cost += float64(ru.OutputTokens+ru.ReasoningTokens) * mp.OutputCostPerToken

	return cost
}
