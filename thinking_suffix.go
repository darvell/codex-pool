package main

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Suffixes accept token budgets or named reasoning efforts in parentheses.
func parseThinkingSuffix(model string) (baseName string, budget int, hasSuffix bool) {
	idx := strings.LastIndex(model, "(")
	if idx < 0 || !strings.HasSuffix(model, ")") {
		return model, 0, false
	}
	budgetStr := model[idx+1 : len(model)-1]

	n, err := strconv.Atoi(budgetStr)
	if err == nil && n > 0 {
		return model[:idx], n, true
	}

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
		effort := reasoningEffortFromBudget(float64(budget))
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
