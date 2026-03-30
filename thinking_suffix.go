package main

import (
	"encoding/json"
	"strconv"
	"strings"
)

// parseThinkingSuffix extracts a thinking budget from a model name suffix.
// Format: "model-name(budget)" where budget is an integer token count.
// Returns the base model name, the budget, and whether a suffix was found.
//
// Examples:
//
//	"claude-sonnet-4-5(16384)" -> ("claude-sonnet-4-5", 16384, true)
//	"gemini-2.5-pro(8192)"    -> ("gemini-2.5-pro", 8192, true)
//	"gpt-4.1"                 -> ("gpt-4.1", 0, false)
func parseThinkingSuffix(model string) (baseName string, budget int, hasSuffix bool) {
	idx := strings.LastIndex(model, "(")
	if idx < 0 || !strings.HasSuffix(model, ")") {
		return model, 0, false
	}
	budgetStr := model[idx+1 : len(model)-1]

	// Try integer budget first (e.g. "claude-sonnet-4-5(16384)")
	n, err := strconv.Atoi(budgetStr)
	if err == nil && n > 0 {
		return model[:idx], n, true
	}

	// Try named effort levels (e.g. "gpt-5.3-codex(high)")
	switch strings.ToLower(budgetStr) {
	case "high":
		return model[:idx], 32768, true
	case "medium":
		return model[:idx], 8192, true
	case "low":
		return model[:idx], 1024, true
	}

	return model, 0, false
}

// injectThinkingBudget modifies the request body to include thinking parameters
// appropriate for the target provider. Returns the modified body.
func injectThinkingBudget(body []byte, accountType AccountType, budget int) []byte {
	if len(body) == 0 || budget <= 0 {
		return body
	}

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body
	}

	switch accountType {
	case AccountTypeClaude:
	case AccountTypeZAI:
		// Claude: { "thinking": { "type": "enabled", "budget_tokens": N } }
		thinking := map[string]any{
			"type":          "enabled",
			"budget_tokens": budget,
		}
		raw, err := json.Marshal(thinking)
		if err != nil {
			return body
		}
		parsed["thinking"] = raw

	case AccountTypeGemini:
		// Gemini: { "generationConfig": { ..., "thinkingConfig": { "thinkingBudget": N } } }
		var genConfig map[string]json.RawMessage
		if existing, ok := parsed["generationConfig"]; ok {
			if err := json.Unmarshal(existing, &genConfig); err != nil {
				genConfig = make(map[string]json.RawMessage)
			}
		} else {
			genConfig = make(map[string]json.RawMessage)
		}
		thinkingConfig := map[string]any{"thinkingBudget": budget}
		raw, err := json.Marshal(thinkingConfig)
		if err != nil {
			return body
		}
		genConfig["thinkingConfig"] = raw
		gcRaw, err := json.Marshal(genConfig)
		if err != nil {
			return body
		}
		parsed["generationConfig"] = gcRaw

	case AccountTypeCodex:
		// OpenAI: { "reasoning": { "effort": "high" } } or similar.
		// OpenAI doesn't use token budgets the same way; map budget to effort level.
		effort := "medium"
		if budget >= 10000 {
			effort = "high"
		} else if budget <= 2000 {
			effort = "low"
		}
		reasoning := map[string]any{"effort": effort}
		raw, err := json.Marshal(reasoning)
		if err != nil {
			return body
		}
		parsed["reasoning"] = raw

	default:
		return body
	}

	out, err := json.Marshal(parsed)
	if err != nil {
		return body
	}
	return out
}
