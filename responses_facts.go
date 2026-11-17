package main

func responseFinishReason(response map[string]any) string {
	details, _ := response["incomplete_details"].(map[string]any)
	switch details["reason"] {
	case "max_output_tokens":
		return "length"
	case "content_filter":
		return "content_filter"
	default:
		return "stop"
	}
}

type responsesUsageFacts struct {
	inputTokens     int64
	outputTokens    int64
	totalTokens     int64
	cachedTokens    int64
	reasoningTokens int64
	hasInputDetails bool
}

func readResponsesUsage(usage map[string]any) responsesUsageFacts {
	facts := responsesUsageFacts{
		inputTokens:  toInt64(usage["input_tokens"]),
		outputTokens: toInt64(usage["output_tokens"]),
		totalTokens:  toInt64(usage["total_tokens"]),
	}
	if facts.totalTokens == 0 {
		facts.totalTokens = facts.inputTokens + facts.outputTokens
	}
	if details, ok := usage["input_tokens_details"].(map[string]any); ok {
		facts.hasInputDetails = true
		facts.cachedTokens = toInt64(details["cached_tokens"])
	}
	if details, ok := usage["output_tokens_details"].(map[string]any); ok {
		facts.reasoningTokens = toInt64(details["reasoning_tokens"])
	}
	return facts
}

func (f responsesUsageFacts) apply(input, output, cached *int64) {
	*input = f.inputTokens
	if output != nil {
		*output = f.outputTokens
	}
	// A response that omits details does not replace previously observed cache use.
	if cached != nil && f.hasInputDetails {
		*cached = f.cachedTokens
	}
}

func responseErrorMessage(response map[string]any) string {
	if errObj, ok := response["error"].(map[string]any); ok {
		if message, _ := errObj["message"].(string); message != "" {
			return message
		}
	}
	return "response failed"
}
