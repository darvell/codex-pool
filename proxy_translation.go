package main

import (
	"net/http"
	"strings"
)

type proxyTranslation struct {
	body        []byte
	path        string
	direction   TranslateDirection
	source      RequestFormat
	target      RequestFormat
	imageFormat string
}

func translateProxyRequest(r *http.Request, body []byte, accountType AccountType, model string) (proxyTranslation, error) {
	result := proxyTranslation{body: body, path: r.URL.Path}
	source := detectRequestFormat(r.URL.Path)
	target := providerTargetFormat(accountType)
	if accountType == AccountTypeOpencodeGo {
		target = opencodeGoTargetFormat(model)
	}
	if source != FormatUnknown && target != FormatUnknown && source != target {
		switch {
		case source == FormatClaude && target == FormatOpenAI:
			result.direction = TranslateClaudeToOAI
			if accountType == AccountTypeCodex {
				result.direction = TranslateClaudeToResponses
			}
		case source == FormatOpenAI && target == FormatClaude:
			result.direction = TranslateOAIToClaude
		}
	}
	if result.direction == TranslateNone && accountType == AccountTypeCodex {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/images/generations"), strings.HasPrefix(r.URL.Path, "/v1/images/edits"):
			result.direction = TranslateImagesToResponses
		case source == FormatOpenAI:
			result.direction = TranslateChatToResponses
			if strings.HasPrefix(r.URL.Path, "/v1/completions") && !strings.HasPrefix(r.URL.Path, "/v1/chat/completions") {
				result.direction = TranslateCompletionsToResponses
			}
		}
	}
	if result.direction == TranslateNone && accountType == AccountTypeClaude && (strings.HasPrefix(r.URL.Path, "/v1/responses") || strings.HasPrefix(r.URL.Path, "/responses")) {
		result.direction = TranslateResponsesToClaude
	}

	result.source, result.target = source, target
	var err error
	switch result.direction {
	case TranslateClaudeToOAI:
		result.body, err = translateRequestBody(body, source, target)
		result.path = "/v1/chat/completions"
	case TranslateOAIToClaude:
		result.body, err = translateRequestBody(body, source, target)
		result.path = "/v1/messages"
	case TranslateChatToResponses:
		result.body, err = translateChatCompletionsToResponses(body)
		result.path = "/v1/responses"
	case TranslateCompletionsToResponses:
		result.body, err = translateCompletionsToResponses(body)
		result.path = "/v1/responses"
	case TranslateImagesToResponses:
		if strings.HasPrefix(r.URL.Path, "/v1/images/edits") {
			result.body, result.imageFormat, err = translateImagesEditToResponses(body, r.Header.Get("Content-Type"))
		} else {
			result.body, result.imageFormat, err = translateImagesGenerationToResponses(body)
		}
		result.path = "/v1/responses"
	case TranslateResponsesToClaude:
		result.body, err = translateResponsesToClaudeRequest(body)
		result.path = "/v1/messages"
	case TranslateClaudeToResponses:
		result.body, err = translateClaudeToResponsesRequest(body)
		result.path = "/v1/responses"
	}
	return result, err
}
