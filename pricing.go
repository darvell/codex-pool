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
	InputCostPerToken    float64 `json:"input_cost_per_token"`
	OutputCostPerToken   float64 `json:"output_cost_per_token"`
	CacheReadCost        float64 `json:"cache_read_input_token_cost"`
	CacheWriteCost       float64 `json:"cache_creation_input_token_cost"`
	LongContextThreshold int64   `json:"-"`
	LongInputCost        float64 `json:"-"`
	LongOutputCost       float64 `json:"-"`
	LongCacheReadCost    float64 `json:"-"`
	LongCacheWriteCost   float64 `json:"-"`
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
	{AccountTypeCodex, "prolite"}:                 {100, "Codex Pro Lite"},
	{AccountTypeCodex, "pro"}:                     {200, "Codex Pro"},
	{AccountTypeCodex, "team"}:                    {25, "Codex Team"},
	{AccountTypeGemini, "api"}:                    {0, "Gemini API"},
	{AccountTypeAntigravity, "antigravity"}:       {0, "Google Antigravity"},
	// The provider auth files identify Kimi and MiniMax token-plan credentials,
	// but not their paid tier. Reporting a guessed $49 or $5 monthly spend made
	// ROI look precise while being unrelated to the account's actual plan.
	{AccountTypeKimi, "kimi"}:               {0, "Kimi Token Plan"},
	{AccountTypeKimi, ""}:                   {0, "Kimi Token Plan"},
	{AccountTypeMinimax, "minimax"}:         {0, "MiniMax Token Plan"},
	{AccountTypeMinimax, ""}:                {0, "MiniMax Token Plan"},
	{AccountTypeZAI, "zai"}:                 {0, "Z.ai Coding Plan"},
	{AccountTypeZAI, ""}:                    {0, "Z.ai Coding Plan"},
	{AccountTypeXiaomi, "xiaomi"}:           {0, "Xiaomi MiMo Token Plan"},
	{AccountTypeXiaomi, ""}:                 {0, "Xiaomi MiMo Token Plan"},
	{AccountTypeAdverserial, "adverserial"}: {0, "Adverserial Platform"},
	{AccountTypeAdverserial, ""}:            {0, "Adverserial Platform"},
}

// getSubscriptionCost returns monthly cost and label for an account.
func getSubscriptionCost(accType AccountType, planType string) (monthly float64, label string) {
	planType = strings.ToLower(strings.TrimSpace(planType))
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

// estimateSubscriptionSpend counts the initial paid month plus one billing
// cycle for each completed 30-day period covered by the API-cost analytics.
func estimateSubscriptionSpend(monthly float64, firstSeen, now time.Time) (spend float64, billingCycles int) {
	if monthly <= 0 || firstSeen.IsZero() {
		return 0, 0
	}
	if now.Before(firstSeen) {
		now = firstSeen
	}
	billingCycles = int(now.Sub(firstSeen)/(30*24*time.Hour)) + 1
	return monthly * float64(billingCycles), billingCycles
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
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(val, &entry); err != nil {
			continue
		}
		input, inputOK := pricingJSONFloat(entry, "input_cost_per_token")
		output, outputOK := pricingJSONFloat(entry, "output_cost_per_token")
		if !inputOK || !outputOK {
			continue
		}
		cacheRead, _ := pricingJSONFloat(entry, "cache_read_input_token_cost")
		cacheWrite, _ := pricingJSONFloat(entry, "cache_creation_input_token_cost")
		mp := ModelPricing{
			InputCostPerToken:  input,
			OutputCostPerToken: output,
			CacheReadCost:      cacheRead,
			CacheWriteCost:     cacheWrite,
		}
		for _, threshold := range []struct {
			tokens int64
			suffix string
		}{
			{128000, "128k"},
			{200000, "200k"},
			{256000, "256k"},
			{272000, "272k"},
			{512000, "512k"},
		} {
			longInput, ok := pricingJSONFloat(entry, "input_cost_per_token_above_"+threshold.suffix+"_tokens")
			if !ok {
				continue
			}
			mp.LongContextThreshold = threshold.tokens
			mp.LongInputCost = longInput
			mp.LongOutputCost, _ = pricingJSONFloat(entry, "output_cost_per_token_above_"+threshold.suffix+"_tokens")
			mp.LongCacheReadCost, _ = pricingJSONFloat(entry, "cache_read_input_token_cost_above_"+threshold.suffix+"_tokens")
			mp.LongCacheWriteCost, _ = pricingJSONFloat(entry, "cache_creation_input_token_cost_above_"+threshold.suffix+"_tokens")
			break
		}
		models[key] = mp
	}
	// Fill IDs absent from LiteLLM and override the small set whose pool-facing
	// name, promotion schedule, or provider rate cannot be represented there.
	for id, pricing := range publishedModelPricing(time.Now()) {
		if _, present := models[id]; !present || forcePublishedPricing[id] {
			models[id] = pricing
		}
	}

	pd.mu.Lock()
	pd.models = models
	pd.mu.Unlock()
	log.Printf("pricing: loaded %d model prices", len(models))
}

func pricingJSONFloat(entry map[string]json.RawMessage, key string) (float64, bool) {
	raw, ok := entry[key]
	if !ok {
		return 0, false
	}
	var value float64
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, false
	}
	return value, true
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

var pricingModelAliases = map[string]string{
	"claude-opus-5 [1m]":   "claude-opus-5",
	"claude-opus-5[1m]":    "claude-opus-5",
	"claude-sonnet-5 [1m]": "claude-sonnet-5",
	"claude-sonnet-5[1m]":  "claude-sonnet-5",
	"gpt-5.6-sol[1m]":      "gpt-5.6-sol",
	"gpt-5.6-terra[1m]":    "gpt-5.6-terra",
	"gpt-5.6-luna[1m]":     "gpt-5.6-luna",
	"glm-5.2":              "glm-5.3",
	"zai.glm-5.2":          "glm-5.3",
	"zai.glm-5.3":          "glm-5.3",
	"grok-4.5-build":       "grok-4.5",
	"grok-build-latest":    "grok-4.5",
	"gemini-pro-agent":     "gemini-3.1-pro-preview",
	"gemini-3-flash-agent": "gemini-3-flash-preview",
	"gemini-3.1-pro":       "gemini-3.1-pro-preview",
	"mimo-v2.5-pro[1m]":    "mimo-v2.5-pro",
	"kimi":                 "kimi-for-coding",
	"k2p5":                 "kimi-for-coding",
	"kimi-k2-thinking":     "kimi-for-coding",
	"minimax":              "MiniMax-M3",
	"minimax-m3":           "MiniMax-M3",
	"cyberkimi":            "lordx64/cyberkimi",
}

func canonicalPricingModel(model string) string {
	model = strings.TrimSpace(model)
	model = strings.TrimPrefix(model, "antigravity/")
	if alias, ok := pricingModelAliases[model]; ok {
		model = alias
	}
	for _, effort := range []string{"-minimal", "-low", "-medium", "-high", "-xhigh", "-max"} {
		if strings.HasSuffix(model, effort) {
			model = strings.TrimSuffix(model, effort)
			break
		}
	}
	if alias, ok := pricingModelAliases[model]; ok {
		model = alias
	}
	return model
}

// lookupPricing uses exact IDs and explicit aliases. It deliberately avoids
// arbitrary prefix matching: "zai.glm-5.3" previously matched "zai.glm-5"
// and silently used the wrong rate.
func (pd *PricingData) lookupPricing(model string) (ModelPricing, bool) {
	model = canonicalPricingModel(model)
	if model == "" {
		return ModelPricing{}, false
	}

	pd.mu.RLock()
	defer pd.mu.RUnlock()

	if mp, ok := pd.models[model]; ok {
		return mp, true
	}

	// Try without a dated suffix (e.g. claude-sonnet-4-5-20250929).
	parts := strings.Split(model, "-")
	for i := len(parts) - 1; i >= 1; i-- {
		if len(parts[i]) == 8 && isAllDigits(parts[i]) {
			if mp, ok := pd.models[strings.Join(parts[:i], "-")]; ok {
				return mp, true
			}
		}
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
// Formula: uncached_input * input_price + cache_read * cache_read_price plus
// cache_creation * cache_write_price + (output + reasoning) * output_price.
// defaultModelForProvider returns a fallback model name when the request didn't include one.
var defaultModelForProvider = map[AccountType]string{
	AccountTypeCodex:       "gpt-5.6-sol",
	AccountTypeClaude:      "claude-sonnet-5",
	AccountTypeAntigravity: "gemini-3.6-flash",
	AccountTypeKimi:        "k3",
	AccountTypeMinimax:     "MiniMax-M3",
	AccountTypeZAI:         "glm-5.3",
	AccountTypeXiaomi:      "mimo-v2.5-pro",
	AccountTypeGrok:        "grok-4.5",
	AccountTypeAdverserial: "lordx64/cyberkimi",
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

	totalInput := ru.InputTokens
	uncachedInput := ru.InputTokens - ru.CachedInputTokens - ru.CacheCreationTokens
	if inputTokensExcludeCached(ru) {
		uncachedInput = ru.InputTokens
		totalInput += ru.CachedInputTokens + ru.CacheCreationTokens
	}
	if uncachedInput < 0 {
		uncachedInput = 0
	}

	inputCost := mp.InputCostPerToken
	outputCost := mp.OutputCostPerToken
	cacheReadCost := mp.CacheReadCost
	cacheWriteCost := mp.CacheWriteCost
	if mp.LongContextThreshold > 0 && totalInput > mp.LongContextThreshold {
		inputCost = nonzeroPrice(mp.LongInputCost, inputCost)
		outputCost = nonzeroPrice(mp.LongOutputCost, outputCost)
		cacheReadCost = nonzeroPrice(mp.LongCacheReadCost, cacheReadCost)
		cacheWriteCost = nonzeroPrice(mp.LongCacheWriteCost, cacheWriteCost)
	}

	cost := float64(uncachedInput) * inputCost
	cost += float64(ru.CachedInputTokens) * cacheReadCost
	cost += float64(ru.CacheCreationTokens) * cacheWriteCost
	cost += float64(ru.OutputTokens+ru.ReasoningTokens) * outputCost
	return cost
}

func nonzeroPrice(candidate, fallback float64) float64 {
	if candidate > 0 {
		return candidate
	}
	return fallback
}

func inputTokensExcludeCached(ru RequestUsage) bool {
	switch ru.InputTokenMode {
	case "exclusive":
		return true
	case "inclusive":
		return false
	}
	// Historical records predate InputTokenMode. These providers expose the
	// Anthropic usage shape, where input_tokens is uncached input only.
	switch ru.AccountType {
	case AccountTypeClaude, AccountTypeKimi, AccountTypeMinimax, AccountTypeZAI, AccountTypeXiaomi, AccountTypeAdverserial:
		return true
	default:
		return false
	}
}
