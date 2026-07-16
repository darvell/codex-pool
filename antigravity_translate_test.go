package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func decodeMap(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("decode JSON: %v\n%s", err, raw)
	}
	return value
}

func TestBuildAntigravityOpenAIRequest(t *testing.T) {
	body := []byte(`{
      "model":"gemini-3-flash",
	  "stream":true,
      "messages":[
        {"role":"system","content":"be terse"},
        {"role":"user","content":[{"type":"text","text":"inspect"},{"type":"image_url","image_url":{"url":"data:image/png;base64,YQ=="}}]},
        {"role":"assistant","reasoning_content":"plan","reasoning_signature":"sig","tool_calls":[{"id":"call_1","type":"function","function":{"name":"read file","arguments":"{\"path\":\"a\"}"}}]},
        {"role":"tool","tool_call_id":"call_1","name":"read_file","content":"ok"}
      ],
      "tools":[{"type":"function","function":{"name":"read file","parameters":{"type":"object","properties":{"path":{"type":"string","default":"a"}}}}}],
      "tool_choice":{"type":"function","function":{"name":"read file"}},
      "max_completion_tokens":512
    }`)
	request, err := prepareAntigravityRequest("/v1/chat/completions", body, "gemini-3-flash", "project-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if request.PublicModel != "gemini-3-flash" || !request.ClientStream {
		t.Fatalf("unexpected request metadata: %#v", request)
	}
	envelope := decodeMap(t, request.Body)
	if envelope["requestType"] != "agent" || envelope["project"] != "project-1" {
		t.Fatalf("bad envelope: %#v", envelope)
	}
	inner := envelope["request"].(map[string]any)
	if _, ok := inner["safetySettings"]; ok {
		t.Fatal("safety settings must be removed")
	}
	if !strings.HasPrefix(inner["sessionId"].(string), "-") {
		t.Fatalf("bad session ID: %v", inner["sessionId"])
	}
	contents := inner["contents"].([]any)
	userParts := contents[0].(map[string]any)["parts"].([]any)
	if _, ok := userParts[1].(map[string]any)["inlineData"]; !ok {
		t.Fatalf("image was not translated: %#v", userParts)
	}
	modelParts := contents[1].(map[string]any)["parts"].([]any)
	thought := modelParts[0].(map[string]any)
	if thought["thought"] != true || thought["thoughtSignature"] != "sig" {
		t.Fatalf("thinking signature lost: %#v", thought)
	}
	call := modelParts[1].(map[string]any)["functionCall"].(map[string]any)
	if call["name"] != "read_file" {
		t.Fatalf("tool name not sanitized: %#v", call)
	}
	if modelParts[1].(map[string]any)["thoughtSignature"] != "skip_thought_signature_validator" {
		t.Fatalf("function call replay signature missing: %#v", modelParts[1])
	}
	cfg := inner["generationConfig"].(map[string]any)
	if _, exists := cfg["maxOutputTokens"]; exists {
		t.Fatalf("generation config: %#v", cfg)
	}
}

func TestBuildAntigravityResponsesAndClaudeRequests(t *testing.T) {
	responses := []byte(`{"model":"gemini-3-flash","instructions":"system","input":[{"type":"reasoning","encrypted_content":"signed","content":[{"type":"output_text","text":"thought"}]},{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]},{"type":"function_call","call_id":"c1","name":"lookup","arguments":"{\"q\":1}"},{"type":"function_call_output","call_id":"c1","output":"done"}],"tools":[{"type":"web_search_preview"}]}`)
	var inner map[string]any
	for _, path := range []string{"/v1/responses", "/backend-api/codex/responses"} {
		req, err := prepareAntigravityRequest(path, responses, "gemini-3-flash", "p", "")
		if err != nil {
			t.Fatal(err)
		}
		if req.Format != antigravityFormatResponses {
			t.Fatalf("%s format = %s", path, req.Format)
		}
		inner = decodeMap(t, req.Body)["request"].(map[string]any)
		contents := inner["contents"].([]any)
		parts := contents[0].(map[string]any)["parts"].([]any)
		if parts[0].(map[string]any)["thought"] != true || parts[1].(map[string]any)["thoughtSignature"] != "skip_thought_signature_validator" {
			t.Fatalf("native reasoning layout missing: %#v", parts)
		}
		callPart := contents[2].(map[string]any)["parts"].([]any)[0].(map[string]any)
		if callPart["thoughtSignature"] != "skip_thought_signature_validator" {
			t.Fatalf("Responses function call replay signature missing: %#v", callPart)
		}
		if _, exists := inner["input"]; exists {
			t.Fatalf("Responses input leaked into Gemini request: %#v", inner)
		}
		if _, exists := inner["tools"]; exists {
			t.Fatalf("Responses built-in tool leaked upstream: %#v", inner["tools"])
		}
	}

	claude := []byte(`{"model":"claude-sonnet-4-6","system":[{"type":"text","text":"system"}],"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"plan","signature":"sig"},{"type":"tool_use","id":"t1","name":"find","input":{"x":1}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"ok"}]}],"thinking":{"type":"enabled","budget_tokens":1024},"tools":[{"name":"find","input_schema":{"type":"object"}}]}`)
	req, err := prepareAntigravityRequest("/v1/messages", claude, "claude-sonnet-4-6", "p", "")
	if err != nil {
		t.Fatal(err)
	}
	inner = decodeMap(t, req.Body)["request"].(map[string]any)
	thinking := inner["generationConfig"].(map[string]any)["thinkingConfig"].(map[string]any)
	if thinking["thinkingBudget"] != float64(1024) {
		t.Fatalf("thinking config: %#v", thinking)
	}
}

func TestBuildAntigravityResponsesCleansNestedToolSchemas(t *testing.T) {
	body := []byte(`{
		"model":"gemini-3.1-flash-lite",
		"input":"hi",
		"reasoning":{"effort":"low"},
		"tools":[{"type":"function","name":"run","description":"run it","parameters":{
			"type":"object",
			"properties":{
				"count":{"type":"array","items":{"type":"integer","exclusiveMinimum":0}},
				"mode":{"anyOf":[{"type":"string"},{"const":"auto"}]},
				"const":{"type":"string"}
			},
			"required":["count","mode","missing"],
			"additionalProperties":false
		}}]
	}`)
	request, err := prepareAntigravityRequest("/backend-api/codex/responses", body, "gemini-3.1-flash-lite", "p", "")
	if err != nil {
		t.Fatal(err)
	}
	inner := decodeMap(t, request.Body)["request"].(map[string]any)
	encoded, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"exclusiveMinimum":`, `"anyOf":`, `"additionalProperties":`} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("unsupported schema keyword %s leaked upstream: %s", forbidden, encoded)
		}
	}
	declaration := inner["tools"].([]any)[0].(map[string]any)["functionDeclarations"].([]any)[0].(map[string]any)
	schema := declaration["parameters"].(map[string]any)
	properties := schema["properties"].(map[string]any)
	if _, exists := properties["const"]; !exists {
		t.Fatalf("property literally named const was removed: %#v", properties)
	}
	required := schema["required"].([]any)
	if len(required) != 2 {
		t.Fatalf("required = %#v", required)
	}
	config := inner["generationConfig"].(map[string]any)["thinkingConfig"].(map[string]any)
	if config["thinkingLevel"] != "low" || config["includeThoughts"] != true {
		t.Fatalf("reasoning config = %#v", config)
	}
}

func TestBuildAntigravityResponsesDropsBuiltInToolsBesideFunctions(t *testing.T) {
	body := []byte(`{"model":"gemini-3.1-flash-lite","input":"hi","tool_choice":"auto","tools":[{"type":"web_search_preview"},{"type":"function","name":"lookup","parameters":{"type":"object"}}]}`)
	request, err := prepareAntigravityRequest("/backend-api/codex/responses", body, "gemini-3.1-flash-lite", "p", "")
	if err != nil {
		t.Fatal(err)
	}
	inner := decodeMap(t, request.Body)["request"].(map[string]any)
	tools := inner["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("Responses tools = %#v", tools)
	}
	if _, exists := tools[0].(map[string]any)["googleSearch"]; exists {
		t.Fatalf("Responses built-in tool leaked upstream: %#v", tools)
	}
	toolConfig := inner["toolConfig"].(map[string]any)
	if _, exists := toolConfig["includeServerSideToolInvocations"]; exists {
		t.Fatalf("Responses enabled Gemini tool combination: %#v", toolConfig)
	}
	if _, ok := toolConfig["functionCallingConfig"].(map[string]any); !ok {
		t.Fatalf("function calling config missing: %#v", toolConfig)
	}
	if toolConfig["functionCallingConfig"].(map[string]any)["mode"] != "AUTO" {
		t.Fatalf("mixed tool mode = %#v", toolConfig)
	}
}

func TestBuildAntigravityResponsesMapsFunctionNamesDeterministically(t *testing.T) {
	first := "123:mcp/read file"
	second := "123:mcp@read file"
	body := []byte(`{"model":"gemini-3.5-flash","input":[{"type":"function_call","call_id":"c2","name":"` + second + `","arguments":"{}"},{"type":"function_call","call_id":"c1","name":"` + first + `","arguments":"{}"},{"type":"function_call_output","call_id":"c1","output":"one"},{"type":"function_call_output","call_id":"c2","output":"two"}],"tools":[{"type":"function","name":"` + first + `","parameters":{"type":"object"}},{"type":"function","name":"` + second + `","parameters":{"type":"object"}},{"type":"function","name":"` + first + `","parameters":{"type":"object"}}],"tool_choice":{"type":"function","name":"` + second + `"}}`)
	request, err := prepareAntigravityRequest("/v1/responses", body, "gemini-3.5-flash", "p", "")
	if err != nil {
		t.Fatal(err)
	}
	inner := decodeMap(t, request.Body)["request"].(map[string]any)
	declarations := inner["tools"].([]any)[0].(map[string]any)["functionDeclarations"].([]any)
	if len(declarations) != 2 {
		t.Fatalf("declarations = %#v, want two unique tools", declarations)
	}
	firstMapped := stringValue(declarations[0].(map[string]any)["name"])
	secondMapped := stringValue(declarations[1].(map[string]any)["name"])
	if firstMapped == secondMapped || !strings.HasPrefix(firstMapped, "_123:mcp_") || !strings.HasPrefix(secondMapped, "_123:mcp_") {
		t.Fatalf("mapped names = %q, %q", firstMapped, secondMapped)
	}
	if len(firstMapped) > 64 || len(secondMapped) > 64 {
		t.Fatalf("mapped names exceed Gemini limit: %d, %d", len(firstMapped), len(secondMapped))
	}
	allowed := inner["toolConfig"].(map[string]any)["functionCallingConfig"].(map[string]any)["allowedFunctionNames"].([]any)
	if allowed[0] != secondMapped {
		t.Fatalf("tool choice = %#v, want %q", allowed, secondMapped)
	}
	contents := inner["contents"].([]any)
	if len(contents) != 4 {
		t.Fatalf("contents = %#v, want calls paired with outputs by call_id", contents)
	}
	for index, callID := range []string{"c2", "c2", "c1", "c1"} {
		parts := contents[index].(map[string]any)["parts"].([]any)
		part := parts[0].(map[string]any)
		var got string
		if call, ok := part["functionCall"].(map[string]any); ok {
			got = stringValue(call["id"])
		} else {
			got = stringValue(part["functionResponse"].(map[string]any)["id"])
		}
		if got != callID {
			t.Fatalf("contents[%d] call ID = %q, want %q", index, got, callID)
		}
	}
}

func TestBuildAntigravityResponsesPreservesNativeReasoningHistory(t *testing.T) {
	body := []byte(`{"model":"gemini-3.5-flash","input":[{"type":"reasoning","encrypted_content":"gemini#native-signature","summary":[{"type":"summary_text","text":"first "},{"type":"summary_text","text":"second"}]},{"type":"message","role":"user","content":[{"type":"output_text","text":"visible answer"}]},{"type":"message","role":"user","content":[{"type":"input_text","text":"continue"}]}]}`)
	request, err := prepareAntigravityRequest("/v1/responses", body, "gemini-3.5-flash", "p", "")
	if err != nil {
		t.Fatal(err)
	}
	contents := decodeMap(t, request.Body)["request"].(map[string]any)["contents"].([]any)
	if len(contents) != 2 {
		t.Fatalf("contents = %#v", contents)
	}
	parts := contents[0].(map[string]any)["parts"].([]any)
	if len(parts) != 2 || parts[0].(map[string]any)["text"] != "first second" || parts[0].(map[string]any)["thoughtSignature"] != nil {
		t.Fatalf("thought part = %#v", parts)
	}
	if parts[1].(map[string]any)["text"] != "visible answer" || parts[1].(map[string]any)["thoughtSignature"] != "native-signature" {
		t.Fatalf("signed visible part = %#v", parts[1])
	}
}

func TestBuildAntigravityResponsesMapsRolesMediaReasoningAndSchema(t *testing.T) {
	body := []byte(`{
		"model":"gemini-3.5-flash","instructions":"base",
		"input":[
			{"type":"message","role":"developer","content":[{"type":"input_text","text":"developer"}]},
			{"type":"message","role":"user","content":[
				{"type":"input_text","text":"look"},
				{"type":"input_image","url":"https://example.com/a.png"},
				{"type":"input_audio","data":"YQ==","format":"mp3"},
				{"type":"output_text","text":"old model output"},
				{"type":"input_text","text":"next user input"}
			]},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"trailing prefill"}]}
		],
		"reasoning":{"effort":"auto"},
		"text":{"format":{"type":"json_schema","schema":{"type":"object","additionalProperties":false,"properties":{"answer":{"type":"string","minLength":1}}}}}
	}`)
	request, err := prepareAntigravityRequest("/v1/responses", body, "gemini-3.5-flash", "p", "")
	if err != nil {
		t.Fatal(err)
	}
	inner := decodeMap(t, request.Body)["request"].(map[string]any)
	systemParts := inner["systemInstruction"].(map[string]any)["parts"].([]any)
	if len(systemParts) != 2 || mapValue(systemParts[1])["text"] != "developer" {
		t.Fatalf("system instruction = %#v", systemParts)
	}
	contents := inner["contents"].([]any)
	if len(contents) != 3 || mapValue(contents[0])["role"] != "user" || mapValue(contents[1])["role"] != "model" || mapValue(contents[2])["role"] != "user" {
		t.Fatalf("role-split contents = %#v", contents)
	}
	userParts := mapValue(contents[0])["parts"].([]any)
	if mapValue(userParts[1])["fileData"] == nil || mapValue(userParts[2])["inlineData"].(map[string]any)["mimeType"] != "audio/mpeg" {
		t.Fatalf("media parts = %#v", userParts)
	}
	config := inner["generationConfig"].(map[string]any)
	thinking := config["thinkingConfig"].(map[string]any)
	if thinking["thinkingBudget"] != float64(-1) || thinking["includeThoughts"] != true {
		t.Fatalf("thinking config = %#v", thinking)
	}
	if _, exists := config["responseSchema"]; exists {
		t.Fatalf("responseSchema leaked: %#v", config)
	}
	schema := config["responseJsonSchema"].(map[string]any)
	if schema["additionalProperties"] != false || mapValue(mapValue(schema["properties"])["answer"])["minLength"] != float64(1) {
		t.Fatalf("responseJsonSchema was altered: %#v", schema)
	}
}

func TestBuildAntigravityResponsesUsesNamedThinkingLevelAndOrphanOutputName(t *testing.T) {
	body := []byte(`{"model":"gemini-3.1-flash-lite","input":[{"type":"function_call_output","call_id":"orphan","output":"done"}],"reasoning":{"effort":"high"}}`)
	request, err := prepareAntigravityRequest("/v1/responses", body, "gemini-3.1-flash-lite", "p", "")
	if err != nil {
		t.Fatal(err)
	}
	inner := decodeMap(t, request.Body)["request"].(map[string]any)
	thinking := inner["generationConfig"].(map[string]any)["thinkingConfig"].(map[string]any)
	if thinking["thinkingLevel"] != "high" {
		t.Fatalf("thinking config = %#v", thinking)
	}
	response := mapValue(mapValue(inner["contents"].([]any)[0])["parts"].([]any)[0])["functionResponse"].(map[string]any)
	if response["name"] != "unknown" {
		t.Fatalf("orphan response = %#v", response)
	}
}

func antigravityFixture() []byte {
	return []byte(`{"response":{"candidates":[{"finishReason":"STOP","content":{"role":"model","parts":[{"text":"reason","thought":true,"thoughtSignature":"signed"},{"text":"answer"},{"functionCall":{"id":"c1","name":"lookup","args":{"q":1}}},{"inlineData":{"mimeType":"image/png","data":"YQ=="}}]}}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"thoughtsTokenCount":2,"cachedContentTokenCount":3,"totalTokenCount":15}},"traceId":"trace"}`)
}

func TestTranslateAntigravityResponses(t *testing.T) {
	for _, format := range []antigravityClientFormat{antigravityFormatGemini, antigravityFormatChat, antigravityFormatResponses, antigravityFormatAnthropic} {
		t.Run(format.String(), func(t *testing.T) {
			out, err := translateAntigravityResponse(antigravityFixture(), format, "gemini-3-flash")
			if err != nil {
				t.Fatal(err)
			}
			obj := decodeMap(t, out)
			switch format {
			case antigravityFormatGemini:
				if _, ok := obj["candidates"]; !ok {
					t.Fatalf("wrapper was not removed: %#v", obj)
				}
			case antigravityFormatChat:
				message := obj["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)
				if message["reasoning_signature"] != "signed" || len(message["tool_calls"].([]any)) != 1 || len(message["images"].([]any)) != 1 {
					t.Fatalf("OpenAI response lost content: %#v", message)
				}
			case antigravityFormatResponses:
				if obj["object"] != "response" || len(obj["output"].([]any)) != 4 {
					t.Fatalf("bad Responses response: %#v", obj)
				}
			case antigravityFormatAnthropic:
				if obj["stop_reason"] != "tool_use" || len(obj["content"].([]any)) != 4 {
					t.Fatalf("bad Claude response: %#v", obj)
				}
			}
		})
	}
}

func TestPrepareAntigravityDropsMaxOutputTokensForGemini(t *testing.T) {
	prepared, err := prepareAntigravityRequest("/v1/responses", []byte(`{"model":"gemini-3.5-flash","input":"hi","max_output_tokens":1024}`), "gemini-3.5-flash", "project", "session")
	if err != nil {
		t.Fatal(err)
	}
	root := decodeMap(t, prepared.Body)
	request := root["request"].(map[string]any)
	config := request["generationConfig"].(map[string]any)
	if _, exists := config["maxOutputTokens"]; exists {
		t.Fatalf("maxOutputTokens was sent to Gemini Antigravity: %#v", config)
	}
}

func TestAntigravityStreamingTranslations(t *testing.T) {
	for _, format := range []antigravityClientFormat{antigravityFormatGemini, antigravityFormatChat, antigravityFormatResponses, antigravityFormatAnthropic} {
		t.Run(format.String(), func(t *testing.T) {
			var out bytes.Buffer
			writer := newAntigravityStreamWriter(&out, format, "gemini-3-flash")
			fixture := append([]byte("data: "), antigravityFixture()...)
			fixture = append(fixture, []byte("\n\n")...)
			mid := len(fixture) / 2
			if _, err := writer.Write(fixture[:mid]); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(fixture[mid:]); err != nil {
				t.Fatal(err)
			}
			got := out.String()
			switch format {
			case antigravityFormatGemini:
				if strings.Contains(got, `"response"`) || !strings.Contains(got, `"candidates"`) {
					t.Fatalf("bad Gemini stream: %s", got)
				}
			case antigravityFormatChat:
				if !strings.Contains(got, `chat.completion.chunk`) || !strings.Contains(got, `data: [DONE]`) {
					t.Fatalf("bad OpenAI stream: %s", got)
				}
			case antigravityFormatResponses:
				completedIndex := strings.LastIndex(got, `event: response.completed`)
				if !strings.Contains(got, `event: response.created`) || completedIndex < 0 || !strings.Contains(got, `response.function_call_arguments.delta`) || !strings.Contains(got, `event: response.content_part.added`) || !strings.Contains(got, `event: response.content_part.done`) || !strings.Contains(got[completedIndex:], `"output":[{`) {
					t.Fatalf("bad Responses stream: %s", got)
				}
			case antigravityFormatAnthropic:
				if !strings.Contains(got, `event: message_start`) || !strings.Contains(got, `thinking_delta`) || !strings.Contains(got, `event: message_stop`) {
					t.Fatalf("bad Claude stream: %s", got)
				}
			}
		})
	}
}

func TestTranslateAntigravityErrorShapes(t *testing.T) {
	body := []byte(`{"error":{"code":429,"message":"quota exhausted","status":"RESOURCE_EXHAUSTED"}}`)
	claude := decodeMap(t, translateAntigravityError(body, antigravityFormatAnthropic, 429))
	if claude["error"].(map[string]any)["type"] != "rate_limit_error" {
		t.Fatalf("bad Claude error: %#v", claude)
	}
	openAI := decodeMap(t, translateAntigravityError(body, antigravityFormatChat, 429))
	if openAI["error"].(map[string]any)["type"] != "rate_limit_error" {
		t.Fatalf("bad OpenAI error: %#v", openAI)
	}
}
