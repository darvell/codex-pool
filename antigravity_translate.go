package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// The Antigravity wire contract and translation behavior are adapted from
// router-for-me/CLIProxyAPI at c8803713c972af0076f55933fdeed4db81d72d24.
// CLIProxyAPI is MIT licensed; see THIRD_PARTY_NOTICES.md.

type antigravityClientFormat int

const (
	antigravityFormatGemini antigravityClientFormat = iota
	antigravityFormatChat
	antigravityFormatResponses
	antigravityFormatAnthropic
)

const antigravityFunctionThoughtSignature = "skip_thought_signature_validator"

func (format antigravityClientFormat) String() string {
	switch format {
	case antigravityFormatGemini:
		return "gemini"
	case antigravityFormatChat:
		return "openai_chat"
	case antigravityFormatResponses:
		return "openai_responses"
	case antigravityFormatAnthropic:
		return "anthropic_messages"
	default:
		return "unknown"
	}
}

type antigravityPreparedRequest struct {
	Body                   []byte
	Format                 antigravityClientFormat
	ClientStream           bool
	PublicModel            string
	UpstreamModel          string
	Operation              string
	ResponsesRequest       map[string]any
	ResponsesFunctionNames map[string]string
}

func shouldRouteAntigravityModel(model string) bool {
	model = strings.TrimSpace(model)
	if strings.HasPrefix(model, "antigravity/") {
		return true
	}
	for _, provider := range []AccountType{AccountTypeCodex, AccountTypeClaude, AccountTypeKimi, AccountTypeMinimax, AccountTypeZAI, AccountTypeXiaomi} {
		if _, ok := modelForProvider(provider, model); ok {
			return false
		}
	}
	if isGrokModel(model) {
		return false
	}
	return isAntigravityModel(model)
}

func antigravityModelFromGeminiPath(path string) string {
	marker := "/v1beta/models/"
	index := strings.Index(path, marker)
	if index < 0 {
		return ""
	}
	model := path[index+len(marker):]
	if colon := strings.IndexByte(model, ':'); colon >= 0 {
		model = model[:colon]
	}
	return strings.TrimSpace(model)
}

func prepareAntigravityRequest(path string, body []byte, requestedModel, projectID, conversationID string) (antigravityPreparedRequest, error) {
	publicModel := strings.TrimSpace(requestedModel)
	if publicModel == "" {
		publicModel = antigravityModelFromGeminiPath(path)
	}
	if publicModel == "" {
		return antigravityPreparedRequest{}, errors.New("Antigravity model is required")
	}
	if strings.TrimSpace(projectID) == "" {
		return antigravityPreparedRequest{}, errors.New("Antigravity project ID is required")
	}
	upstreamModel := antigravityCanonicalModel(publicModel)
	format := antigravityFormatGemini
	switch {
	case strings.HasPrefix(path, "/v1/messages"):
		format = antigravityFormatAnthropic
	case isAntigravityResponsesPath(path):
		format = antigravityFormatResponses
	case strings.HasPrefix(path, "/v1/chat/completions"):
		format = antigravityFormatChat
	}
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return antigravityPreparedRequest{}, fmt.Errorf("invalid JSON request: %w", err)
	}
	clientStream, _ := root["stream"].(bool)
	operation := "streamGenerateContent"
	if strings.Contains(path, "countTokens") {
		operation = "countTokens"
		clientStream = false
	}
	var gemini map[string]any
	var err error
	switch format {
	case antigravityFormatGemini:
		gemini = cloneAnyMap(root)
		delete(gemini, "model")
		clientStream = strings.Contains(path, "streamGenerateContent") || clientStream
	case antigravityFormatChat:
		gemini, err = antigravityChatToGemini(root)
	case antigravityFormatAnthropic:
		gemini, err = antigravityAnthropicToGemini(root)
	case antigravityFormatResponses:
		gemini, err = antigravityResponsesToGemini(root, upstreamModel)
	}
	if err != nil {
		return antigravityPreparedRequest{}, err
	}
	delete(gemini, "stream")
	delete(gemini, "model")
	delete(gemini, "safetySettings")
	if !strings.Contains(strings.ToLower(upstreamModel), "claude") {
		if generationConfig := mapValue(gemini["generationConfig"]); generationConfig != nil {
			delete(generationConfig, "maxOutputTokens")
		}
	}
	requestType := "agent"
	if strings.Contains(strings.ToLower(upstreamModel), "image") {
		requestType = "image_gen"
	}
	requestID := "agent-" + uuid.NewString()
	if requestType == "image_gen" {
		requestID = fmt.Sprintf("image_gen/%d/%s/12", time.Now().UnixMilli(), uuid.NewString())
	}
	if conversationID == "" {
		conversationID = antigravitySessionID(gemini)
	}
	gemini["sessionId"] = conversationID
	envelope := map[string]any{
		"model": upstreamModel, "userAgent": "antigravity", "requestType": requestType,
		"project": projectID, "requestId": requestID, "request": gemini,
	}
	encoded, err := json.Marshal(envelope)
	var responsesRequest map[string]any
	var responsesFunctionNames map[string]string
	if format == antigravityFormatResponses {
		responsesRequest = cloneAnyMap(root)
		responsesFunctionNames = reverseAntigravityFunctionNameMap(antigravityResponsesFunctionNameMap(root))
	}
	return antigravityPreparedRequest{Body: encoded, Format: format, ClientStream: clientStream, PublicModel: publicModel, UpstreamModel: upstreamModel, Operation: operation, ResponsesRequest: responsesRequest, ResponsesFunctionNames: responsesFunctionNames}, err
}

func antigravitySessionID(request map[string]any) string {
	seed := ""
	if contents, ok := request["contents"].([]any); ok {
		for _, content := range contents {
			entry, _ := content.(map[string]any)
			if entry["role"] != "user" {
				continue
			}
			parts, _ := entry["parts"].([]any)
			for _, part := range parts {
				if text, _ := part.(map[string]any)["text"].(string); text != "" {
					seed = text
					break
				}
			}
			if seed != "" {
				break
			}
		}
	}
	if seed == "" {
		seed = uuid.NewString()
	}
	sum := sha256.Sum256([]byte(seed))
	value := int64(0)
	for _, b := range sum[:8] {
		value = value<<8 | int64(b)
	}
	if value > 0 {
		value = -value
	}
	return strconv.FormatInt(value, 10)
}

func cloneAnyMap(input map[string]any) map[string]any {
	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func antigravityChatToGemini(input map[string]any) (map[string]any, error) {
	result := map[string]any{}
	contents := make([]any, 0)
	systemParts := make([]any, 0)
	messages, _ := input["messages"].([]any)
	for _, raw := range messages {
		message, _ := raw.(map[string]any)
		role, _ := message["role"].(string)
		if role == "system" || role == "developer" {
			systemParts = append(systemParts, antigravityContentParts(message["content"])...)
			continue
		}
		geminiRole := "user"
		if role == "assistant" {
			geminiRole = "model"
		}
		parts := antigravityContentParts(message["content"])
		if reasoning := firstAntigravityString(message, "reasoning_content", "reasoning"); reasoning != "" {
			thought := map[string]any{"text": reasoning, "thought": true}
			if signature := firstAntigravityString(message, "reasoning_signature", "thought_signature"); signature != "" {
				thought["thoughtSignature"] = signature
			}
			parts = append([]any{thought}, parts...)
		}
		if calls, ok := message["tool_calls"].([]any); ok {
			for _, rawCall := range calls {
				call, _ := rawCall.(map[string]any)
				function, _ := call["function"].(map[string]any)
				arguments := map[string]any{}
				switch rawArgs := function["arguments"].(type) {
				case string:
					_ = json.Unmarshal([]byte(rawArgs), &arguments)
				case map[string]any:
					arguments = rawArgs
				}
				parts = append(parts, map[string]any{"functionCall": map[string]any{"name": sanitizeAntigravityFunctionName(stringValue(function["name"])), "args": arguments, "id": stringValue(call["id"])}, "thoughtSignature": antigravityFunctionThoughtSignature})
			}
		}
		if role == "tool" {
			parts = []any{map[string]any{"functionResponse": map[string]any{"name": sanitizeAntigravityFunctionName(stringValue(message["name"])), "id": stringValue(message["tool_call_id"]), "response": map[string]any{"content": message["content"]}}}}
		}
		contents = append(contents, map[string]any{"role": geminiRole, "parts": parts})
	}
	result["contents"] = contents
	if len(systemParts) > 0 {
		result["systemInstruction"] = map[string]any{"parts": systemParts}
	}
	antigravityCopyGenerationConfig(input, result)
	antigravityCopyTools(input, result)
	return result, nil
}

func antigravityResponsesToGemini(input map[string]any, model string) (map[string]any, error) {
	result := map[string]any{}
	functionNames := antigravityResponsesFunctionNameMap(input)
	if instructions, _ := input["instructions"].(string); instructions != "" {
		result["systemInstruction"] = map[string]any{"parts": []any{map[string]any{"text": instructions}}}
	}
	contents := make([]any, 0)
	if text, ok := input["input"].(string); ok {
		contents = append(contents, map[string]any{"role": "user", "parts": []any{map[string]any{"text": text}}})
	} else {
		items := antigravityNormalizeResponsesItems(anySlice(input["input"]))
		callNames := make(map[string]string)
		for index := 0; index < len(items); index++ {
			item, _ := items[index].(map[string]any)
			if stringValue(item["type"]) == "function_call" {
				callNames[firstAntigravityString(item, "call_id", "id")] = mapAntigravityFunctionName(functionNames, stringValue(item["name"]))
			}
		}
		for index := 0; index < len(items); index++ {
			item, _ := items[index].(map[string]any)
			switch stringValue(item["type"]) {
			case "function_call":
				arguments := any(map[string]any{})
				if rawArguments, ok := item["arguments"].(string); ok {
					if err := json.Unmarshal([]byte(rawArguments), &arguments); err != nil {
						arguments = rawArguments
					}
				} else if item["arguments"] != nil {
					arguments = item["arguments"]
				}
				call := map[string]any{"name": mapAntigravityFunctionName(functionNames, stringValue(item["name"])), "id": firstAntigravityString(item, "call_id", "id"), "args": arguments}
				contents = append(contents, map[string]any{"role": "model", "parts": []any{map[string]any{"functionCall": call, "thoughtSignature": antigravityFunctionThoughtSignature}}})
			case "function_call_output":
				response := map[string]any{"result": antigravityJSONValue(item["output"])}
				callID := stringValue(item["call_id"])
				functionResponse := map[string]any{"id": callID, "response": response}
				name := callNames[callID]
				if name == "" {
					name = sanitizeAntigravityFunctionName("unknown")
				}
				functionResponse["name"] = name
				contents = append(contents, map[string]any{"role": "user", "parts": []any{map[string]any{"functionResponse": functionResponse}}})
			case "reasoning":
				visible := ""
				if index+1 < len(items) && strings.Contains(strings.ToLower(model), "gemini") {
					if text, ok := antigravityResponsesAssistantVisibleText(mapValue(items[index+1])); ok {
						visible = text
						index++
					}
				}
				parts := antigravityResponsesReasoningParts(item, model, visible)
				if len(parts) > 0 {
					contents = append(contents, map[string]any{"role": "model", "parts": parts})
				}
			default:
				role := strings.ToLower(stringValue(item["role"]))
				if role == "system" || role == "developer" {
					parts := antigravityContentParts(item["content"])
					if len(parts) > 0 {
						system := mapValue(result["systemInstruction"])
						if system == nil {
							system = map[string]any{"parts": []any{}}
						}
						system["parts"] = append(anySlice(system["parts"]), parts...)
						result["systemInstruction"] = system
					}
					continue
				}
				for _, content := range antigravityResponsesMessageContents(item) {
					contents = append(contents, content)
				}
			}
		}
	}
	if len(contents) > 0 && antigravityIsTrailingModelPrefill(mapValue(contents[len(contents)-1])) {
		contents = contents[:len(contents)-1]
	}
	result["contents"] = contents
	antigravityCopyGenerationConfig(input, result)
	antigravityApplyResponsesGenerationConfig(input, result)
	// CLIProxyAPI's Responses translator carries custom functions and drops
	// Responses built-in tools. Sending web_search alongside functions changes
	// the Gemini tool-combination contract and Antigravity rejects the request.
	antigravityCopyToolsFilteredMapped(input, result, false, functionNames)
	return result, nil
}

func antigravityResponsesMessageContents(item map[string]any) []any {
	defaultRole := "user"
	if role := strings.ToLower(stringValue(item["role"])); role == "assistant" || role == "model" {
		defaultRole = "model"
	}
	blocks, ok := item["content"].([]any)
	if !ok {
		parts := antigravityContentParts(item["content"])
		if len(parts) == 0 {
			return nil
		}
		return []any{map[string]any{"role": defaultRole, "parts": parts}}
	}
	contents := make([]any, 0)
	currentRole := ""
	currentParts := make([]any, 0)
	flush := func() {
		if len(currentParts) > 0 {
			contents = append(contents, map[string]any{"role": currentRole, "parts": currentParts})
		}
		currentParts = nil
	}
	for _, raw := range blocks {
		block := mapValue(raw)
		role := defaultRole
		if stringValue(block["type"]) == "output_text" {
			role = "model"
		}
		parts := antigravityContentParts([]any{block})
		if len(parts) == 0 {
			continue
		}
		if currentRole != "" && role != currentRole {
			flush()
		}
		currentRole = role
		currentParts = append(currentParts, parts...)
	}
	flush()
	return contents
}

func antigravityResponsesAssistantVisibleText(item map[string]any) (string, bool) {
	itemType := stringValue(item["type"])
	if itemType != "" && itemType != "message" {
		return "", false
	}
	if text, ok := item["content"].(string); ok {
		role := strings.ToLower(stringValue(item["role"]))
		return text, role == "assistant" || role == "model"
	}
	texts := make([]string, 0)
	for _, raw := range anySlice(item["content"]) {
		part := mapValue(raw)
		if stringValue(part["type"]) == "output_text" {
			texts = append(texts, stringValue(part["text"]))
		}
	}
	return strings.Join(texts, "\n"), len(texts) > 0
}

func antigravityResponsesReasoningParts(item map[string]any, model, visible string) []any {
	texts := make([]string, 0)
	for _, raw := range anySlice(item["summary"]) {
		part := mapValue(raw)
		if stringValue(part["type"]) == "summary_text" {
			texts = append(texts, stringValue(part["text"]))
		}
	}
	if len(texts) == 0 {
		for _, raw := range antigravityContentParts(item["content"]) {
			if text := stringValue(mapValue(raw)["text"]); text != "" {
				texts = append(texts, text)
			}
		}
	}
	thoughtText := strings.Join(texts, "")
	if thoughtText == "" {
		thoughtText = "[reasoning unavailable]"
	}
	signature := normalizeAntigravityGeminiSignature(firstAntigravityString(item, "encrypted_content", "signature"))
	if strings.Contains(strings.ToLower(model), "gemini") {
		return []any{
			map[string]any{"text": thoughtText, "thought": true},
			map[string]any{"text": visible, "thoughtSignature": signature},
		}
	}
	return []any{map[string]any{"text": thoughtText, "thought": true, "thoughtSignature": signature}}
}

func normalizeAntigravityGeminiSignature(signature string) string {
	signature = strings.TrimSpace(signature)
	if strings.HasPrefix(signature, "gemini#") {
		return strings.TrimPrefix(signature, "gemini#")
	}
	if signature == antigravityFunctionThoughtSignature {
		return signature
	}
	if strings.HasPrefix(signature, "gpt#") || strings.HasPrefix(signature, "claude#") || signature == "" {
		return antigravityFunctionThoughtSignature
	}
	decoded, err := base64.StdEncoding.DecodeString(signature)
	if err == nil && len(decoded) >= 16 && strings.HasPrefix(signature, "E") {
		return signature
	}
	return antigravityFunctionThoughtSignature
}

func antigravityIsTrailingModelPrefill(content map[string]any) bool {
	if stringValue(content["role"]) != "model" {
		return false
	}
	for _, raw := range anySlice(content["parts"]) {
		part := mapValue(raw)
		if part["thought"] == true || part["functionCall"] != nil || part["thoughtSignature"] != nil {
			return false
		}
	}
	return true
}

func antigravityNormalizeResponsesItems(items []any) []any {
	normalized := make([]any, 0, len(items))
	for index := 0; index < len(items); {
		item := mapValue(items[index])
		if stringValue(item["type"]) != "function_call" {
			normalized = append(normalized, items[index])
			index++
			continue
		}
		calls := make([]any, 0)
		for index < len(items) && stringValue(mapValue(items[index])["type"]) == "function_call" {
			calls = append(calls, items[index])
			index++
		}
		outputs := make([]any, 0)
		for index < len(items) && stringValue(mapValue(items[index])["type"]) == "function_call_output" {
			outputs = append(outputs, items[index])
			index++
		}
		byCallID := make(map[string]any, len(outputs))
		for _, output := range outputs {
			byCallID[stringValue(mapValue(output)["call_id"])] = output
		}
		for _, call := range calls {
			normalized = append(normalized, call)
			callID := stringValue(mapValue(call)["call_id"])
			if output, ok := byCallID[callID]; ok {
				normalized = append(normalized, output)
				delete(byCallID, callID)
			}
		}
		for _, output := range outputs {
			if _, ok := byCallID[stringValue(mapValue(output)["call_id"])]; ok {
				normalized = append(normalized, output)
			}
		}
	}
	return normalized
}

func firstAntigravityString(input map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, _ := input[key].(string); value != "" {
			return value
		}
	}
	return ""
}

func antigravityJSONValue(value any) any {
	text, ok := value.(string)
	if !ok {
		return value
	}
	var decoded any
	if json.Unmarshal([]byte(text), &decoded) == nil {
		return decoded
	}
	return text
}

func antigravityAnthropicToGemini(input map[string]any) (map[string]any, error) {
	result := map[string]any{}
	if system := antigravityContentParts(input["system"]); len(system) > 0 {
		result["systemInstruction"] = map[string]any{"parts": system}
	}
	contents := make([]any, 0)
	messages, _ := input["messages"].([]any)
	for _, raw := range messages {
		message, _ := raw.(map[string]any)
		role := "user"
		if message["role"] == "assistant" {
			role = "model"
		}
		parts := make([]any, 0)
		switch content := message["content"].(type) {
		case string:
			parts = append(parts, map[string]any{"text": content})
		case []any:
			for _, rawBlock := range content {
				block, _ := rawBlock.(map[string]any)
				switch block["type"] {
				case "text":
					parts = append(parts, map[string]any{"text": stringValue(block["text"])})
				case "thinking", "redacted_thinking":
					part := map[string]any{"text": stringValue(block["thinking"]), "thought": true}
					if signature := stringValue(block["signature"]); signature != "" {
						part["thoughtSignature"] = signature
					}
					parts = append(parts, part)
				case "image", "document":
					source, _ := block["source"].(map[string]any)
					if source["type"] == "base64" {
						parts = append(parts, map[string]any{"inlineData": map[string]any{"mimeType": source["media_type"], "data": source["data"]}})
					} else if sourceURL := stringValue(source["url"]); sourceURL != "" {
						parts = append(parts, map[string]any{"fileData": map[string]any{"fileUri": sourceURL}})
					}
				case "tool_use":
					parts = append(parts, map[string]any{"functionCall": map[string]any{"name": sanitizeAntigravityFunctionName(stringValue(block["name"])), "args": block["input"], "id": block["id"]}, "thoughtSignature": antigravityFunctionThoughtSignature})
				case "tool_result":
					parts = append(parts, map[string]any{"functionResponse": map[string]any{"name": sanitizeAntigravityFunctionName(stringValue(block["name"])), "id": block["tool_use_id"], "response": map[string]any{"content": block["content"], "is_error": block["is_error"]}}})
				}
			}
		}
		contents = append(contents, map[string]any{"role": role, "parts": parts})
	}
	result["contents"] = contents
	antigravityCopyGenerationConfig(input, result)
	antigravityCopyTools(input, result)
	return result, nil
}

func antigravityContentParts(value any) []any {
	parts := make([]any, 0)
	switch content := value.(type) {
	case string:
		if content != "" {
			parts = append(parts, map[string]any{"text": content})
		}
	case []any:
		for _, raw := range content {
			block, _ := raw.(map[string]any)
			typeName := stringValue(block["type"])
			switch typeName {
			case "text", "input_text", "output_text":
				parts = append(parts, map[string]any{"text": stringValue(block["text"])})
			case "image_url":
				imageURL, _ := block["image_url"].(map[string]any)
				if urlText := stringValue(imageURL["url"]); strings.HasPrefix(urlText, "data:") {
					if inline := antigravityDataURL(urlText); inline != nil {
						parts = append(parts, inline)
					}
				} else if urlText != "" {
					parts = append(parts, map[string]any{"fileData": map[string]any{"fileUri": urlText}})
				}
			case "input_image":
				urlText := firstAntigravityString(block, "image_url", "url")
				if strings.HasPrefix(urlText, "data:") {
					if inline := antigravityDataURL(urlText); inline != nil {
						parts = append(parts, inline)
					}
				} else if urlText != "" {
					parts = append(parts, map[string]any{"fileData": map[string]any{"fileUri": urlText}})
				}
			case "input_audio":
				audio, _ := block["input_audio"].(map[string]any)
				if audio == nil {
					audio = block
				}
				if data := stringValue(audio["data"]); data != "" {
					parts = append(parts, map[string]any{"inlineData": map[string]any{"mimeType": antigravityAudioMIME(stringValue(audio["format"])), "data": data}})
				}
			case "file":
				file, _ := block["file"].(map[string]any)
				if data := stringValue(file["file_data"]); strings.HasPrefix(data, "data:") {
					if inline := antigravityDataURL(data); inline != nil {
						parts = append(parts, inline)
					}
				} else if fileID := stringValue(file["file_id"]); fileID != "" {
					parts = append(parts, map[string]any{"fileData": map[string]any{"fileUri": fileID}})
				}
			}
		}
	}
	return parts
}

func antigravityAudioMIME(format string) string {
	if mime := map[string]string{"mp3": "audio/mpeg", "wav": "audio/wav", "ogg": "audio/ogg", "flac": "audio/flac", "aac": "audio/aac", "webm": "audio/webm", "pcm16": "audio/pcm", "g711_ulaw": "audio/basic", "g711_alaw": "audio/basic"}[format]; mime != "" {
		return mime
	}
	if format == "" {
		return "audio/wav"
	}
	return "audio/" + format
}

func antigravityDataURL(value string) map[string]any {
	comma := strings.IndexByte(value, ',')
	if comma < 0 {
		return nil
	}
	header, data := value[5:comma], value[comma+1:]
	mime := strings.TrimSuffix(strings.Split(header, ";")[0], ";base64")
	if _, err := base64.StdEncoding.DecodeString(data); err != nil {
		return nil
	}
	return map[string]any{"inlineData": map[string]any{"mimeType": mime, "data": data}}
}

func antigravityCopyGenerationConfig(input, result map[string]any) {
	config := map[string]any{}
	for source, target := range map[string]string{"temperature": "temperature", "top_p": "topP", "top_k": "topK", "max_tokens": "maxOutputTokens", "max_completion_tokens": "maxOutputTokens", "max_output_tokens": "maxOutputTokens", "stop": "stopSequences"} {
		if value, ok := input[source]; ok {
			config[target] = value
		}
	}
	if responseFormat, ok := input["response_format"].(map[string]any); ok {
		antigravityCopyResponseFormat(responseFormat, config)
	}
	if text, ok := input["text"].(map[string]any); ok {
		if format, ok := text["format"].(map[string]any); ok {
			antigravityCopyResponseFormat(format, config)
		}
	}
	if thinking, ok := input["thinking"].(map[string]any); ok {
		budget := thinking["budget_tokens"]
		if budget == nil {
			budget = thinking["budget"]
		}
		if budget != nil {
			config["thinkingConfig"] = map[string]any{"thinkingBudget": budget, "includeThoughts": true}
		}
	}
	if effort := stringValue(input["reasoning_effort"]); effort != "" {
		budgets := map[string]int{"none": 0, "minimal": 1024, "low": 4096, "medium": 8192, "high": 24576}
		config["thinkingConfig"] = map[string]any{"thinkingBudget": budgets[effort], "includeThoughts": effort != "none"}
	}
	if reasoning, ok := input["reasoning"].(map[string]any); ok {
		if effort := stringValue(reasoning["effort"]); effort != "" {
			budgets := map[string]int{"none": 0, "minimal": 1024, "low": 4096, "medium": 8192, "high": 24576}
			config["thinkingConfig"] = map[string]any{"thinkingBudget": budgets[effort], "includeThoughts": effort != "none"}
		}
	}
	if len(config) > 0 {
		result["generationConfig"] = config
	}
}

func antigravityCopyResponseFormat(format, config map[string]any) {
	if format["type"] == "json_object" || format["type"] == "json_schema" {
		config["responseMimeType"] = "application/json"
	}
	if schema, ok := format["json_schema"].(map[string]any); ok {
		if inner, ok := schema["schema"].(map[string]any); ok {
			config["responseSchema"] = cleanAntigravitySchema(inner)
		}
	}
	if schema, ok := format["schema"].(map[string]any); ok {
		config["responseSchema"] = cleanAntigravitySchema(schema)
	}
}

func antigravityApplyResponsesGenerationConfig(input, result map[string]any) {
	config := mapValue(result["generationConfig"])
	if config == nil {
		config = map[string]any{}
	}
	if text := mapValue(input["text"]); text != nil {
		if format := mapValue(text["format"]); format != nil {
			switch strings.ToLower(stringValue(format["type"])) {
			case "json_object":
				config["responseMimeType"] = "application/json"
				delete(config, "responseSchema")
				delete(config, "responseJsonSchema")
			case "json_schema":
				config["responseMimeType"] = "application/json"
				delete(config, "responseSchema")
				schema := mapValue(format["schema"])
				if schema == nil {
					schema = mapValue(mapValue(format["json_schema"])["schema"])
				}
				if schema != nil {
					config["responseJsonSchema"] = schema
				}
			}
		}
	}
	if reasoning := mapValue(input["reasoning"]); reasoning != nil {
		if effort := strings.ToLower(strings.TrimSpace(stringValue(reasoning["effort"]))); effort != "" {
			if effort == "auto" {
				config["thinkingConfig"] = map[string]any{"thinkingBudget": -1, "includeThoughts": true}
			} else {
				config["thinkingConfig"] = map[string]any{"thinkingLevel": effort, "includeThoughts": effort != "none"}
			}
		}
	}
	if len(config) > 0 {
		result["generationConfig"] = config
	}
}

func antigravityCopyTools(input, result map[string]any) {
	antigravityCopyToolsFiltered(input, result, true)
}

func antigravityCopyToolsFiltered(input, result map[string]any, includeBuiltIns bool) {
	antigravityCopyToolsFilteredMapped(input, result, includeBuiltIns, nil)
}

func antigravityCopyToolsFilteredMapped(input, result map[string]any, includeBuiltIns bool, functionNames map[string]string) {
	rawTools, _ := input["tools"].([]any)
	declarations := make([]any, 0)
	googleTools := make([]any, 0)
	seenDeclarations := make(map[string]bool)
	for _, raw := range rawTools {
		tool, _ := raw.(map[string]any)
		toolType := stringValue(tool["type"])
		if strings.HasPrefix(toolType, "web_search") || tool["google_search"] != nil {
			if includeBuiltIns {
				googleTools = append(googleTools, map[string]any{"googleSearch": map[string]any{}})
			}
			continue
		}
		definition := tool
		if function, ok := tool["function"].(map[string]any); ok {
			definition = function
		}
		name := mapAntigravityFunctionName(functionNames, stringValue(definition["name"]))
		if name == "" {
			continue
		}
		if seenDeclarations[name] {
			continue
		}
		seenDeclarations[name] = true
		declaration := map[string]any{"name": name, "description": definition["description"]}
		if schema, ok := definition["input_schema"].(map[string]any); ok {
			declaration["parameters"] = cleanAntigravitySchema(schema)
		}
		if schema, ok := definition["parameters"].(map[string]any); ok {
			declaration["parameters"] = cleanAntigravitySchema(schema)
		}
		declarations = append(declarations, declaration)
	}
	tools := make([]any, 0)
	if len(declarations) > 0 {
		tools = append(tools, map[string]any{"functionDeclarations": declarations})
	}
	tools = append(tools, googleTools...)
	if len(tools) > 0 {
		result["tools"] = tools
	}
	toolConfig := map[string]any{}
	if len(googleTools) > 0 && len(declarations) > 0 {
		// Antigravity rejects mixed built-in and function tools unless this
		// native flag explicitly permits server-side tool execution.
		toolConfig["includeServerSideToolInvocations"] = true
	}
	if choice, ok := input["tool_choice"].(map[string]any); ok {
		mode := "AUTO"
		if choice["type"] == "none" {
			mode = "NONE"
		}
		if choice["type"] == "any" || choice["type"] == "required" {
			mode = "ANY"
		}
		if len(googleTools) > 0 && len(declarations) > 0 && mode == "AUTO" {
			mode = "VALIDATED"
		}
		config := map[string]any{"mode": mode}
		name := stringValue(choice["name"])
		if function, _ := choice["function"].(map[string]any); name == "" && function != nil {
			name = stringValue(function["name"])
		}
		if name != "" {
			config["allowedFunctionNames"] = []string{mapAntigravityFunctionName(functionNames, name)}
		}
		toolConfig["functionCallingConfig"] = config
	} else if choice, ok := input["tool_choice"].(string); ok {
		mode := "AUTO"
		if choice == "none" {
			mode = "NONE"
		} else if choice == "required" || choice == "any" {
			mode = "ANY"
		}
		if len(googleTools) > 0 && len(declarations) > 0 && mode == "AUTO" {
			mode = "VALIDATED"
		}
		toolConfig["functionCallingConfig"] = map[string]any{"mode": mode}
	}
	if len(toolConfig) > 0 {
		result["toolConfig"] = toolConfig
	}
}

func antigravityResponsesFunctionNameMap(input map[string]any) map[string]string {
	unique := make(map[string]bool)
	baseCounts := make(map[string]int)
	for _, raw := range anySlice(input["tools"]) {
		tool := mapValue(raw)
		definition := tool
		if function := mapValue(tool["function"]); function != nil {
			definition = function
		}
		name := stringValue(definition["name"])
		if name == "" || unique[name] {
			continue
		}
		unique[name] = true
		baseCounts[sanitizeAntigravityFunctionName(name)]++
	}
	if len(unique) == 0 {
		return nil
	}
	names := make([]string, 0, len(unique))
	for name := range unique {
		names = append(names, name)
	}
	sort.Strings(names)
	mapped := make(map[string]string, len(names))
	used := make(map[string]bool, len(names))
	for _, name := range names {
		base := sanitizeAntigravityFunctionName(name)
		value := base
		if baseCounts[base] > 1 || used[value] {
			for attempt := 0; ; attempt++ {
				digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d", name, attempt)))
				suffix := "_" + hex.EncodeToString(digest[:6])
				prefix := base
				if len(prefix) > 64-len(suffix) {
					prefix = prefix[:64-len(suffix)]
				}
				value = prefix + suffix
				if !used[value] {
					break
				}
			}
		}
		mapped[name] = value
		used[value] = true
	}
	return mapped
}

func mapAntigravityFunctionName(nameMap map[string]string, name string) string {
	if mapped := nameMap[name]; mapped != "" {
		return mapped
	}
	return sanitizeAntigravityFunctionName(name)
}

func reverseAntigravityFunctionNameMap(nameMap map[string]string) map[string]string {
	if len(nameMap) == 0 {
		return nil
	}
	reversed := make(map[string]string, len(nameMap))
	for original, mapped := range nameMap {
		reversed[mapped] = original
	}
	return reversed
}

func cleanAntigravitySchema(schema map[string]any) map[string]any {
	return cleanAntigravitySchemaNode(schema, false)
}

var antigravityUnsupportedSchemaKeywords = map[string]bool{
	"$schema": true, "$defs": true, "definitions": true, "$id": true, "additionalProperties": true,
	"propertyNames": true, "patternProperties": true, "$comment": true, "enumDescriptions": true,
	"enumTitles": true, "prefill": true, "deprecated": true, "strict": true, "nullable": true,
	"title": true, "minLength": true, "maxLength": true, "exclusiveMinimum": true,
	"exclusiveMaximum": true, "pattern": true, "minItems": true, "maxItems": true,
	"uniqueItems": true, "format": true, "default": true, "examples": true,
}

var antigravitySchemaConstraintHints = map[string]string{
	"minLength": "minLength", "maxLength": "maxLength", "exclusiveMinimum": "exclusiveMinimum",
	"exclusiveMaximum": "exclusiveMaximum", "pattern": "pattern", "minItems": "minItems",
	"maxItems": "maxItems", "uniqueItems": "uniqueItems", "format": "format", "default": "default",
	"examples": "examples",
}

func cleanAntigravitySchemaNode(schema map[string]any, propertyMap bool) map[string]any {
	if propertyMap {
		result := make(map[string]any, len(schema))
		for name, value := range schema {
			if child, ok := value.(map[string]any); ok {
				result[name] = cleanAntigravitySchemaNode(child, false)
			} else {
				result[name] = value
			}
		}
		return result
	}

	working := cloneAnyMap(schema)
	nullableProperties := make(map[string]bool)
	if properties, ok := working["properties"].(map[string]any); ok {
		for name, raw := range properties {
			if child, ok := raw.(map[string]any); ok && antigravitySchemaAllowsNull(child) {
				nullableProperties[name] = true
			}
		}
	}
	if ref := stringValue(working["$ref"]); ref != "" {
		name := ref
		if index := strings.LastIndexByte(ref, '/'); index >= 0 {
			name = ref[index+1:]
		}
		description := antigravityAppendSchemaHint(stringValue(working["description"]), "See: "+name)
		return map[string]any{"type": "object", "description": description}
	}

	antigravityMergeAllOf(working)
	working = antigravityFlattenSchemaUnion(working)

	result := make(map[string]any, len(working))
	description := stringValue(working["description"])
	for key, value := range working {
		if key == "description" || key == "const" || key == "allOf" || key == "anyOf" || key == "oneOf" || key == "$ref" {
			continue
		}
		if hint, ok := antigravitySchemaConstraintHints[key]; ok {
			description = antigravityAppendSchemaHint(description, fmt.Sprintf("%s: %v", hint, value))
			continue
		}
		if antigravityUnsupportedSchemaKeywords[key] || strings.HasPrefix(key, "x-") {
			if key == "additionalProperties" && value == false {
				description = antigravityAppendSchemaHint(description, "No extra properties allowed")
			}
			continue
		}
		switch key {
		case "properties":
			if properties, ok := value.(map[string]any); ok {
				result[key] = cleanAntigravitySchemaNode(properties, true)
			}
		case "items":
			if child, ok := value.(map[string]any); ok {
				result[key] = cleanAntigravitySchemaNode(child, false)
			} else {
				result[key] = value
			}
		case "type":
			if types, ok := value.([]any); ok {
				selected := "string"
				accepted := make([]string, 0, len(types))
				for _, rawType := range types {
					typeName := stringValue(rawType)
					if typeName == "" || typeName == "null" {
						continue
					}
					if len(accepted) == 0 {
						selected = typeName
					}
					accepted = append(accepted, typeName)
				}
				result[key] = selected
				if len(accepted) > 1 {
					description = antigravityAppendSchemaHint(description, "Accepts: "+strings.Join(accepted, " | "))
				}
				if len(types) != len(accepted) {
					description = antigravityAppendSchemaHint(description, "(nullable)")
				}
			} else {
				result[key] = value
			}
		default:
			result[key] = value
		}
	}

	if constant, exists := working["const"]; exists {
		if _, hasEnum := result["enum"]; !hasEnum {
			result["enum"] = []any{constant}
		}
	}
	if values, ok := result["enum"].([]any); ok {
		converted := make([]any, 0, len(values))
		for _, value := range values {
			converted = append(converted, fmt.Sprint(value))
		}
		result["enum"] = converted
		result["type"] = "string"
		if len(converted) > 1 && len(converted) <= 10 {
			labels := make([]string, len(converted))
			for i, value := range converted {
				labels[i] = fmt.Sprint(value)
			}
			description = antigravityAppendSchemaHint(description, "Allowed: "+strings.Join(labels, ", "))
		}
	}
	if required, ok := result["required"].([]any); ok {
		properties, _ := result["properties"].(map[string]any)
		cleaned := make([]any, 0, len(required))
		for _, value := range required {
			name := stringValue(value)
			if _, exists := properties[name]; exists && !nullableProperties[name] {
				cleaned = append(cleaned, name)
			}
		}
		if len(cleaned) == 0 {
			delete(result, "required")
		} else {
			result["required"] = cleaned
		}
	}
	if description != "" {
		result["description"] = description
	}
	return result
}

func antigravitySchemaAllowsNull(schema map[string]any) bool {
	if types, ok := schema["type"].([]any); ok {
		for _, value := range types {
			if stringValue(value) == "null" {
				return true
			}
		}
	}
	for _, keyword := range []string{"anyOf", "oneOf"} {
		for _, raw := range anySlice(schema[keyword]) {
			if child, ok := raw.(map[string]any); ok && stringValue(child["type"]) == "null" {
				return true
			}
		}
	}
	return false
}

func antigravityMergeAllOf(schema map[string]any) {
	allOf, _ := schema["allOf"].([]any)
	properties, _ := schema["properties"].(map[string]any)
	if properties == nil {
		properties = make(map[string]any)
	}
	required, _ := schema["required"].([]any)
	seenRequired := make(map[string]bool)
	for _, value := range required {
		seenRequired[stringValue(value)] = true
	}
	for _, raw := range allOf {
		item, _ := raw.(map[string]any)
		for name, value := range mapValue(item["properties"]) {
			properties[name] = value
		}
		for _, value := range anySlice(item["required"]) {
			name := stringValue(value)
			if name != "" && !seenRequired[name] {
				required = append(required, name)
				seenRequired[name] = true
			}
		}
	}
	if len(properties) > 0 {
		schema["properties"] = properties
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	delete(schema, "allOf")
}

func antigravityFlattenSchemaUnion(schema map[string]any) map[string]any {
	for _, keyword := range []string{"anyOf", "oneOf"} {
		options, _ := schema[keyword].([]any)
		if len(options) == 0 {
			continue
		}
		bestScore, best := -1, map[string]any{}
		types := make([]string, 0, len(options))
		for _, raw := range options {
			option, _ := raw.(map[string]any)
			typeName := stringValue(option["type"])
			score := 0
			switch {
			case typeName == "object" || option["properties"] != nil:
				score = 3
				typeName = "object"
			case typeName == "array" || option["items"] != nil:
				score = 2
				typeName = "array"
			case typeName != "" && typeName != "null":
				score = 1
			default:
				typeName = "null"
			}
			types = append(types, typeName)
			if score > bestScore {
				bestScore, best = score, option
			}
		}
		selected := cloneAnyMap(best)
		if description := stringValue(schema["description"]); description != "" {
			selected["description"] = antigravityAppendSchemaHint(stringValue(selected["description"]), description)
		}
		if len(types) > 1 {
			selected["description"] = antigravityAppendSchemaHint(stringValue(selected["description"]), "Accepts: "+strings.Join(types, " | "))
		}
		for key, value := range schema {
			if key != keyword && key != "description" {
				if _, exists := selected[key]; !exists {
					selected[key] = value
				}
			}
		}
		return selected
	}
	return schema
}

func antigravityAppendSchemaHint(description, hint string) string {
	if description == "" {
		return hint
	}
	if hint == "" || strings.Contains(description, hint) {
		return description
	}
	return description + " (" + hint + ")"
}

func mapValue(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func sanitizeAntigravityFunctionName(name string) string {
	if name == "" {
		return ""
	}
	var builder strings.Builder
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '-' || char == '.' || char == ':' {
			builder.WriteRune(char)
		} else {
			builder.WriteByte('_')
		}
	}
	value := builder.String()
	if value == "" {
		value = "_"
	}
	first := value[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_') {
		if len(value) >= 64 {
			value = value[:63]
		}
		value = "_" + value
	}
	if len(value) > 64 {
		value = value[:64]
	}
	return value
}

func stringValue(value any) string { text, _ := value.(string); return text }

func (h *proxyHandler) handleAntigravityProxy(w http.ResponseWriter, r *http.Request, body []byte, requestedModel, conversationID, userID, originID, clientIP, reqID string) bool {
	if !shouldRouteAntigravityModel(requestedModel) {
		return false
	}
	canonical := antigravityCanonicalModel(requestedModel)
	provider, _ := h.registry.ForType(AccountTypeAntigravity).(*AntigravityProvider)
	if provider == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "Antigravity provider is not configured")
		return true
	}
	exclude := make(map[string]bool)
	var lastError error
	var lastRateLimitBody []byte
	var lastRateLimitUntil time.Time
	attempts := h.cfg.maxAttempts
	if accountCount := h.pool.countByType(AccountTypeAntigravity); accountCount > attempts {
		attempts = accountCount
	}
	for attempt := 0; attempt < attempts; attempt++ {
		account := h.pool.candidateForAntigravityModel(conversationID, exclude, canonical, clientIP)
		if account == nil {
			break
		}
		exclude[account.ID] = true
		if h.needsRefresh(account) {
			_ = h.refreshAccount(r.Context(), account)
		}
		account.mu.Lock()
		projectID := account.ProjectID
		account.mu.Unlock()
		prepared, err := prepareAntigravityRequest(r.URL.Path, body, requestedModel, projectID, conversationID)
		if err != nil {
			respondJSONError(w, http.StatusBadRequest, err.Error())
			return true
		}
		var replayScope antigravityReplayScope
		prepared.Body, replayScope, _ = antigravityApplyNativeReplay(prepared.Body)
		atomic.AddInt64(&account.Inflight, 1)
		resp, err := h.doAntigravityRequestWithTransientRetry(r.Context(), r.Header, account, provider, prepared)
		atomic.AddInt64(&account.Inflight, -1)
		if err != nil {
			lastError = err
			continue
		}
		if resp.StatusCode == http.StatusUnauthorized {
			_ = resp.Body.Close()
			if err := h.refreshAccountAfterAuthFailure(r.Context(), account); err == nil {
				atomic.AddInt64(&account.Inflight, 1)
				resp, err = h.doAntigravityRequestWithTransientRetry(r.Context(), r.Header, account, provider, prepared)
				atomic.AddInt64(&account.Inflight, -1)
				if err != nil {
					lastError = err
					continue
				}
			}
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			antigravityClearNativeReplayOnError(replayScope, resp.StatusCode, errBody)
			until, ok := parseAntigravityRetry(errBody, time.Now())
			if !ok {
				until = time.Now().Add(backoffDuration(attempt))
			}
			setAntigravityModelCooldown(account, canonical, until)
			lastRateLimitBody = append(lastRateLimitBody[:0], errBody...)
			lastRateLimitUntil = until
			lastError = fmt.Errorf("Antigravity %s is rate limited until %s", canonical, until.Format(time.RFC3339))
			continue
		}
		if resp.StatusCode == http.StatusForbidden {
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			antigravityClearNativeReplayOnError(replayScope, resp.StatusCode, errBody)
			needsVerification, banned, verificationURL := classifyAntigravityForbidden(errBody)
			account.mu.Lock()
			account.NeedsVerification = needsVerification
			account.VerificationURL = verificationURL
			account.HealthError = strings.TrimSpace(string(errBody))
			if banned {
				account.Dead = true
			}
			if !needsVerification && !banned {
				account.RateLimitUntil = time.Now().Add(30 * time.Minute)
			}
			account.mu.Unlock()
			_ = saveAccount(account)
			lastError = fmt.Errorf("Antigravity account %s was rejected: %s", account.ID, safeText(errBody))
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			antigravityClearNativeReplayOnError(replayScope, resp.StatusCode, errBody)
			antigravityWriteError(w, prepared.Format, resp.StatusCode, errBody)
			return true
		}
		clearAntigravityModelCooldown(account, canonical)
		account.mu.Lock()
		hadHealthError := account.NeedsVerification || account.VerificationURL != "" || account.HealthError != ""
		account.NeedsVerification, account.VerificationURL, account.HealthError = false, "", ""
		account.mu.Unlock()
		if hadHealthError {
			_ = saveAccount(account)
		}
		if prepared.Operation == "countTokens" {
			defer resp.Body.Close()
			responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
			if readErr != nil {
				antigravityWriteError(w, prepared.Format, http.StatusBadGateway, []byte(readErr.Error()))
				return true
			}
			unwrapped, unwrapErr := unwrapAntigravityResponse(responseBody)
			if unwrapErr != nil {
				antigravityWriteError(w, prepared.Format, http.StatusBadGateway, []byte(unwrapErr.Error()))
				return true
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(unwrapped)
			return true
		}
		h.writeAntigravityResponse(w, resp, prepared, replayScope, account, userID, originID, reqID)
		return true
	}
	if len(lastRateLimitBody) > 0 {
		if !lastRateLimitUntil.IsZero() {
			seconds := int64(time.Until(lastRateLimitUntil).Seconds())
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		}
		antigravityWriteError(w, antigravityFormatForPath(r.URL.Path), http.StatusTooManyRequests, lastRateLimitBody)
		return true
	}
	if lastError == nil {
		lastError = fmt.Errorf("no Antigravity account currently supports %s", requestedModel)
	}
	antigravityWriteError(w, antigravityFormatForPath(r.URL.Path), http.StatusServiceUnavailable, []byte(lastError.Error()))
	return true
}

var antigravityVerificationURLPattern = regexp.MustCompile(`https://[^\s"'<>]+`)

func classifyAntigravityForbidden(body []byte) (needsVerification, banned bool, verificationURL string) {
	lower := strings.ToLower(string(body))
	needsVerification = strings.Contains(lower, "validation_required") || strings.Contains(lower, "verify your account") || strings.Contains(lower, "validation_url")
	banned = strings.Contains(lower, "terms of service") || strings.Contains(lower, "terms violation") || strings.Contains(lower, "policy violation")
	var root any
	if json.Unmarshal(body, &root) == nil {
		var walk func(any) string
		walk = func(value any) string {
			switch node := value.(type) {
			case map[string]any:
				for _, key := range []string{"validation_url", "appeal_url"} {
					if text, _ := node[key].(string); text != "" {
						return text
					}
				}
				for _, child := range node {
					if found := walk(child); found != "" {
						return found
					}
				}
			case []any:
				for _, child := range node {
					if found := walk(child); found != "" {
						return found
					}
				}
			}
			return ""
		}
		verificationURL = walk(root)
	}
	if verificationURL == "" {
		verificationURL = antigravityVerificationURLPattern.FindString(string(body))
	}
	return needsVerification, banned, verificationURL
}

func antigravityFormatForPath(path string) antigravityClientFormat {
	switch {
	case strings.HasPrefix(path, "/v1/messages"):
		return antigravityFormatAnthropic
	case isAntigravityResponsesPath(path):
		return antigravityFormatResponses
	case strings.HasPrefix(path, "/v1/chat/completions"):
		return antigravityFormatChat
	default:
		return antigravityFormatGemini
	}
}

func isAntigravityResponsesPath(path string) bool {
	path = strings.TrimSuffix(path, "/")
	for _, prefix := range []string{"/responses", "/v1/responses", "/api/codex/responses", "/backend-api/codex/responses"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func (h *proxyHandler) doAntigravityRequest(ctx context.Context, incoming http.Header, account *Account, provider *AntigravityProvider, prepared antigravityPreparedRequest) (*http.Response, error) {
	tryBase := func(base *url.URL) (*http.Response, error) {
		u := *base
		operation := prepared.Operation
		if operation == "" {
			operation = "streamGenerateContent"
		}
		u.Path = singleJoin(u.Path, "/v1internal:"+operation)
		if operation == "streamGenerateContent" {
			query := u.Query()
			query.Set("alt", "sse")
			u.RawQuery = query.Encode()
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(prepared.Body))
		provider.SetAuthHeaders(req, account)
		if operation == "streamGenerateContent" {
			req.Header.Set("Accept", "text/event-stream")
		} else {
			req.Header.Set("Accept", "application/json")
		}
		if requestID := incoming.Get("X-Request-ID"); requestID != "" {
			req.Header.Set("X-Request-ID", requestID)
		}
		transport := h.antigravityTransport
		if transport == nil {
			transport = h.transport
		}
		return transport.RoundTrip(req)
	}
	resp, err := tryBase(provider.dailyBase)
	if err == nil && resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
		return resp, nil
	}
	if resp != nil {
		_ = resp.Body.Close()
	}
	return tryBase(provider.prodBase)
}

func (h *proxyHandler) doAntigravityRequestWithTransientRetry(ctx context.Context, incoming http.Header, account *Account, provider *AntigravityProvider, prepared antigravityPreparedRequest) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := h.doAntigravityRequest(ctx, incoming, account, provider, prepared)
		if err != nil || resp == nil {
			return resp, err
		}
		if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable {
			return resp, nil
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		delay, retry := antigravityInstantRetryDelay(body, time.Now())
		if antigravityShouldRetryNoCapacity(resp.StatusCode, body) {
			delay, retry = 250*time.Millisecond, true
		}
		if !retry || attempt+1 >= 2 {
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			return resp, nil
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, fmt.Errorf("Antigravity transient retry exhausted")
}

func antigravityInstantRetryDelay(body []byte, now time.Time) (time.Duration, bool) {
	if !strings.Contains(strings.ToLower(string(body)), "rate_limit_exceeded") {
		return 0, false
	}
	until, ok := parseAntigravityRetry(body, now)
	if !ok {
		return 0, false
	}
	delay := until.Sub(now)
	if delay < 0 || delay >= 3*time.Second {
		return 0, false
	}
	if delay > 0 {
		delay += 800 * time.Millisecond
	}
	return delay, true
}

func antigravityShouldRetryNoCapacity(statusCode int, body []byte) bool {
	return statusCode == http.StatusServiceUnavailable && strings.Contains(strings.ToLower(string(body)), "no capacity available")
}

func parseAntigravityRetry(body []byte, now time.Time) (time.Time, bool) {
	if reset, ok := parseGeminiRateLimitReset(body, now); ok {
		return reset, true
	}
	var root any
	if json.Unmarshal(body, &root) != nil {
		return time.Time{}, false
	}
	var walk func(any) string
	walk = func(value any) string {
		switch node := value.(type) {
		case map[string]any:
			for key, child := range node {
				if key == "retryDelay" {
					if text, ok := child.(string); ok {
						return text
					}
				}
				if found := walk(child); found != "" {
					return found
				}
			}
		case []any:
			for _, child := range node {
				if found := walk(child); found != "" {
					return found
				}
			}
		}
		return ""
	}
	if duration, err := time.ParseDuration(walk(root)); err == nil && duration > 0 {
		return now.Add(duration), true
	}
	return time.Time{}, false
}

func (h *proxyHandler) writeAntigravityResponse(w http.ResponseWriter, resp *http.Response, prepared antigravityPreparedRequest, replayScope antigravityReplayScope, account *Account, userID, originID, reqID string) {
	defer resp.Body.Close()
	w.Header().Set("X-Accel-Buffering", "no")
	if !prepared.ClientStream {
		result, usage, err := collectAntigravitySSE(resp.Body)
		if err != nil {
			antigravityWriteError(w, prepared.Format, http.StatusBadGateway, []byte(err.Error()))
			return
		}
		wrapped, marshalErr := json.Marshal(map[string]any{"response": result})
		if marshalErr != nil {
			antigravityWriteError(w, prepared.Format, http.StatusBadGateway, []byte(marshalErr.Error()))
			return
		}
		antigravityCaptureNativeReplay(replayScope, prepared.Body, wrapped)
		body, err := translateAntigravityResponseWithRequest(wrapped, prepared.Format, prepared.PublicModel, prepared.ResponsesRequest, prepared.ResponsesFunctionNames)
		if err != nil {
			antigravityWriteError(w, prepared.Format, http.StatusBadGateway, []byte(err.Error()))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
		h.recordAntigravityUsage(account, usage, prepared.PublicModel, userID, originID, reqID)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 8<<20)
	translator := newAntigravityStreamWriter(w, prepared.Format, prepared.PublicModel)
	translator.setResponsesRequest(prepared.ResponsesRequest)
	translator.setResponsesFunctionNames(prepared.ResponsesFunctionNames)
	var usage *RequestUsage
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}
		var wrapper map[string]any
		if json.Unmarshal([]byte(data), &wrapper) != nil {
			continue
		}
		response, _ := wrapper["response"].(map[string]any)
		if response == nil {
			response = wrapper
		}
		antigravityCaptureNativeReplay(replayScope, prepared.Body, []byte(data))
		_, _ = translator.Write([]byte("data: " + data + "\n\n"))
		if value := antigravityUsage(response); value != nil {
			usage = value
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
	if flusher != nil {
		flusher.Flush()
	}
	h.recordAntigravityUsage(account, usage, prepared.PublicModel, userID, originID, reqID)
}

func (h *proxyHandler) recordAntigravityUsage(account *Account, usage *RequestUsage, model, userID, originID, reqID string) {
	if usage == nil {
		return
	}
	usage.Model, usage.UserID, usage.OriginID, usage.RequestID, usage.AccountType = model, userID, originID, reqID, AccountTypeAntigravity
	h.recordUsage(account, *usage)
}

func collectAntigravitySSE(reader io.Reader) (map[string]any, *RequestUsage, error) {
	merged := map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{}}}}}
	parts := []any{}
	var usage *RequestUsage
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 8<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}
		var wrapper map[string]any
		if json.Unmarshal([]byte(data), &wrapper) != nil {
			continue
		}
		response, _ := wrapper["response"].(map[string]any)
		if response == nil {
			response = wrapper
		}
		parts = append(parts, antigravityResponseParts(response)...)
		if value := antigravityUsage(response); value != nil {
			usage = value
			merged["usageMetadata"] = response["usageMetadata"]
		}
		if candidates, _ := response["candidates"].([]any); len(candidates) > 0 {
			candidate, _ := candidates[0].(map[string]any)
			if reason := candidate["finishReason"]; reason != nil {
				mergedCandidates, _ := merged["candidates"].([]any)
				mergedCandidate, _ := mergedCandidates[0].(map[string]any)
				mergedCandidate["finishReason"] = reason
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, usage, err
	}
	candidates, _ := merged["candidates"].([]any)
	candidate, _ := candidates[0].(map[string]any)
	content, _ := candidate["content"].(map[string]any)
	content["parts"] = parts
	return merged, usage, nil
}

func antigravityResponseParts(response map[string]any) []any {
	candidates, _ := response["candidates"].([]any)
	if len(candidates) == 0 {
		return nil
	}
	candidate, _ := candidates[0].(map[string]any)
	content, _ := candidate["content"].(map[string]any)
	parts, _ := content["parts"].([]any)
	return parts
}

func antigravityUsage(response map[string]any) *RequestUsage {
	provider := &AntigravityProvider{}
	return provider.ParseUsage(response)
}

func antigravityNonStreamingResponse(format antigravityClientFormat, model string, response map[string]any) ([]byte, error) {
	if format == antigravityFormatGemini {
		return json.Marshal(response)
	}
	parts := antigravityResponseParts(response)
	text := strings.Builder{}
	toolCalls := []any{}
	anthropicContent := []any{}
	responseOutput := []any{}
	for _, raw := range parts {
		part, _ := raw.(map[string]any)
		if value := stringValue(part["text"]); value != "" {
			if thought, _ := part["thought"].(bool); thought {
				anthropicContent = append(anthropicContent, map[string]any{"type": "thinking", "thinking": value, "signature": part["thoughtSignature"]})
				responseOutput = append(responseOutput, map[string]any{"type": "reasoning", "id": "rs_" + uuid.NewString(), "summary": []any{map[string]any{"type": "summary_text", "text": value}}})
			} else {
				text.WriteString(value)
				anthropicContent = append(anthropicContent, map[string]any{"type": "text", "text": value})
			}
		}
		if call, ok := part["functionCall"].(map[string]any); ok {
			id := stringValue(call["id"])
			if id == "" {
				id = "call_" + uuid.NewString()
			}
			args, _ := json.Marshal(call["args"])
			toolCalls = append(toolCalls, map[string]any{"id": id, "type": "function", "function": map[string]any{"name": call["name"], "arguments": string(args)}})
			anthropicContent = append(anthropicContent, map[string]any{"type": "tool_use", "id": id, "name": call["name"], "input": call["args"]})
			responseOutput = append(responseOutput, map[string]any{"type": "function_call", "id": "fc_" + uuid.NewString(), "call_id": id, "name": call["name"], "arguments": string(args), "status": "completed"})
		}
		if inline, ok := part["inlineData"].(map[string]any); ok {
			dataURL := "data:" + stringValue(inline["mimeType"]) + ";base64," + stringValue(inline["data"])
			anthropicContent = append(anthropicContent, map[string]any{"type": "image", "source": map[string]any{"type": "base64", "media_type": inline["mimeType"], "data": inline["data"]}})
			responseOutput = append(responseOutput, map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_image", "image_url": dataURL}}})
		}
	}
	usage := antigravityPublicUsage(response)
	finish := antigravityFinishReason(response)
	switch format {
	case antigravityFormatChat:
		message := map[string]any{"role": "assistant", "content": text.String()}
		if len(toolCalls) > 0 {
			message["tool_calls"] = toolCalls
		}
		return json.Marshal(map[string]any{"id": "chatcmpl-" + uuid.NewString(), "object": "chat.completion", "created": time.Now().Unix(), "model": model, "choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": finish}}, "usage": usage})
	case antigravityFormatAnthropic:
		return json.Marshal(map[string]any{"id": "msg_" + uuid.NewString(), "type": "message", "role": "assistant", "model": model, "content": anthropicContent, "stop_reason": antigravityAnthropicStop(finish), "stop_sequence": nil, "usage": map[string]any{"input_tokens": usage["prompt_tokens"], "output_tokens": usage["completion_tokens"], "cache_read_input_tokens": usage["cached_tokens"]}})
	case antigravityFormatResponses:
		if text.Len() > 0 {
			responseOutput = append(responseOutput, map[string]any{"type": "message", "id": "msg_" + uuid.NewString(), "status": "completed", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": text.String(), "annotations": []any{}}}})
		}
		return json.Marshal(map[string]any{"id": "resp_" + uuid.NewString(), "object": "response", "created_at": time.Now().Unix(), "status": "completed", "model": model, "output": responseOutput, "usage": map[string]any{"input_tokens": usage["prompt_tokens"], "output_tokens": usage["completion_tokens"], "total_tokens": usage["total_tokens"]}})
	}
	return nil, fmt.Errorf("unsupported Antigravity response format")
}

func antigravityPublicUsage(response map[string]any) map[string]any {
	usage, _ := response["usageMetadata"].(map[string]any)
	prompt, completion, cached, thoughts := readInt64(usage, "promptTokenCount"), readInt64(usage, "candidatesTokenCount"), readInt64(usage, "cachedContentTokenCount"), readInt64(usage, "thoughtsTokenCount")
	return map[string]any{"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": prompt + completion, "cached_tokens": cached, "reasoning_tokens": thoughts}
}

func antigravityFinishReason(response map[string]any) string {
	candidates, _ := response["candidates"].([]any)
	if len(candidates) == 0 {
		return "stop"
	}
	candidate, _ := candidates[0].(map[string]any)
	raw := strings.ToUpper(stringValue(candidate["finishReason"]))
	switch raw {
	case "MAX_TOKENS":
		return "length"
	case "STOP", "":
		return "stop"
	default:
		return strings.ToLower(raw)
	}
}
func antigravityAnthropicStop(reason string) string {
	if reason == "length" {
		return "max_tokens"
	}
	if reason == "tool_calls" {
		return "tool_use"
	}
	return "end_turn"
}

type antigravityStreamState struct {
	ID, Model            string
	Started, TextStarted bool
	Index                int
	Usage                *RequestUsage
}

func antigravityStreamingEvents(format antigravityClientFormat, response map[string]any, state *antigravityStreamState) []string {
	if format == antigravityFormatGemini {
		data, _ := json.Marshal(response)
		return []string{"data: " + string(data) + "\n\n"}
	}
	events := []string{}
	parts := antigravityResponseParts(response)
	for _, raw := range parts {
		part, _ := raw.(map[string]any)
		text := stringValue(part["text"])
		switch format {
		case antigravityFormatChat:
			delta := map[string]any{}
			if !state.Started {
				delta["role"] = "assistant"
				state.Started = true
			}
			if text != "" {
				delta["content"] = text
			}
			if call, ok := part["functionCall"].(map[string]any); ok {
				args, _ := json.Marshal(call["args"])
				delta["tool_calls"] = []any{map[string]any{"index": state.Index, "id": call["id"], "type": "function", "function": map[string]any{"name": call["name"], "arguments": string(args)}}}
				state.Index++
			}
			if len(delta) > 0 {
				data, _ := json.Marshal(map[string]any{"id": state.ID, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": state.Model, "choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": nil}}})
				events = append(events, "data: "+string(data)+"\n\n")
			}
		case antigravityFormatAnthropic:
			if !state.Started {
				data, _ := json.Marshal(map[string]any{"type": "message_start", "message": map[string]any{"id": state.ID, "type": "message", "role": "assistant", "model": state.Model, "content": []any{}, "stop_reason": nil, "usage": map[string]any{"input_tokens": 0, "output_tokens": 0}}})
				events = append(events, "event: message_start\ndata: "+string(data)+"\n\n")
				state.Started = true
			}
			if text != "" {
				if !state.TextStarted {
					data, _ := json.Marshal(map[string]any{"type": "content_block_start", "index": state.Index, "content_block": map[string]any{"type": "text", "text": ""}})
					events = append(events, "event: content_block_start\ndata: "+string(data)+"\n\n")
					state.TextStarted = true
				}
				data, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": state.Index, "delta": map[string]any{"type": "text_delta", "text": text}})
				events = append(events, "event: content_block_delta\ndata: "+string(data)+"\n\n")
			}
		case antigravityFormatResponses:
			if !state.Started {
				data, _ := json.Marshal(map[string]any{"type": "response.created", "response": map[string]any{"id": state.ID, "object": "response", "status": "in_progress", "model": state.Model, "output": []any{}}})
				events = append(events, "event: response.created\ndata: "+string(data)+"\n\n")
				state.Started = true
			}
			if text != "" {
				data, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "item_id": "msg_" + state.ID, "output_index": 0, "content_index": 0, "delta": text})
				events = append(events, "event: response.output_text.delta\ndata: "+string(data)+"\n\n")
			}
		}
	}
	return events
}

func antigravityStreamingTerminal(format antigravityClientFormat, state *antigravityStreamState) []string {
	switch format {
	case antigravityFormatGemini:
		return nil
	case antigravityFormatChat:
		data, _ := json.Marshal(map[string]any{"id": state.ID, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": state.Model, "choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}}})
		return []string{"data: " + string(data) + "\n\ndata: [DONE]\n\n"}
	case antigravityFormatAnthropic:
		events := []string{}
		if state.TextStarted {
			data, _ := json.Marshal(map[string]any{"type": "content_block_stop", "index": state.Index})
			events = append(events, "event: content_block_stop\ndata: "+string(data)+"\n\n")
		}
		data, _ := json.Marshal(map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil}, "usage": map[string]any{"output_tokens": 0}})
		events = append(events, "event: message_delta\ndata: "+string(data)+"\n\n", "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		return events
	case antigravityFormatResponses:
		data, _ := json.Marshal(map[string]any{"type": "response.completed", "response": map[string]any{"id": state.ID, "object": "response", "status": "completed", "model": state.Model, "output": []any{}}})
		return []string{"event: response.completed\ndata: " + string(data) + "\n\n"}
	}
	return nil
}

func antigravityWriteError(w http.ResponseWriter, format antigravityClientFormat, status int, body []byte) {
	payload := translateAntigravityError(body, format, status)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}
