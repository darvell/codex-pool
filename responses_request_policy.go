package main

var codexResponsesDroppedFields = map[string]bool{
	"temperature": true, "top_p": true, "presence_penalty": true, "frequency_penalty": true,
	"max_tokens": true, "max_completion_tokens": true, "max_output_tokens": true, "seed": true,
	"logprobs": true, "top_logprobs": true, "metadata": true, "prompt_cache_scope": true,
}

const (
	lowEffortMaxBudget  = 2000
	highEffortMinBudget = 10000
)

func reasoningEffortFromBudget(budget float64) string {
	switch {
	case budget >= highEffortMinBudget:
		return "high"
	case budget <= lowEffortMaxBudget:
		return "low"
	default:
		return "medium"
	}
}
