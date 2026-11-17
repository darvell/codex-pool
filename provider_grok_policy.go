package main

type grokSanitizeContext uint8

const (
	grokNested grokSanitizeContext = iota
	grokRoot
	grokTools
	grokToolSchema
)

type grokToolState uint8

const (
	grokToolsUnchanged grokToolState = iota
	grokToolsRemoved
)

type grokFieldRule uint8

const (
	grokKeepField grokFieldRule = iota
	grokDropField
	grokNullRequired
)

func grokFieldPolicy(key string, context grokSanitizeContext, model string, tools grokToolState) grokFieldRule {
	if key == "external_web_access" {
		return grokDropField
	}
	if context == grokToolSchema && key == "required" {
		// xAI requires an array for optional tool properties rather than JSON null.
		return grokNullRequired
	}
	if context != grokRoot {
		return grokKeepField
	}
	switch key {
	case "metadata", "response_format", "reasoningEffort":
		return grokDropField
	case "reasoning":
		if !grokModelSupportsReasoningEffort(model) {
			return grokDropField
		}
	case "tool_choice", "parallel_tool_calls":
		if tools == grokToolsRemoved {
			return grokDropField
		}
	}
	return grokKeepField
}

func grokDropsTool(toolType string) bool {
	return toolType == "image_generation"
}
