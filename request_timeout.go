package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func clientOrDefaultTimeout(r *http.Request, reqTimeout, streamTimeout time.Duration, body []byte) time.Duration {
	var obj any
	if json.Unmarshal(body, &obj) != nil {
		obj = nil
	}
	request, _ := obj.(map[string]any)
	stream, _ := request["stream"].(bool)
	return timeoutForRequestIntent(r, reqTimeout, streamTimeout, requestIntent{
		stream: stream,
		image:  valueHasImageGenerationTool(obj),
	})
}

type requestIntent struct {
	stream bool
	image  bool
}

type responsesRequestIntentKey struct{}

func timeoutForRequestIntent(r *http.Request, reqTimeout, streamTimeout time.Duration, intent requestIntent) time.Duration {
	const codexExpectedStreamTimeout = 5 * time.Minute

	isStreaming := intent.stream || strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream")
	isImageGeneration := intent.image

	if isStreaming {
		return streamTimeout
	}

	// Honour SDK/client-requested timeouts for non-streaming requests, but do
	// not let short 60s/120s client defaults cut off image generation before
	// Codex's expected 300s window.
	if v := r.Header.Get("X-Stainless-Timeout"); v != "" {
		if secs, err := strconv.ParseFloat(v, 64); err == nil && secs > 0 {
			requested := time.Duration(secs * float64(time.Second))
			if isImageGeneration && requested < codexExpectedStreamTimeout {
				return codexExpectedStreamTimeout
			}
			return requested
		}
	}
	if isImageGeneration && reqTimeout > 0 && reqTimeout < codexExpectedStreamTimeout {
		return codexExpectedStreamTimeout
	}
	return reqTimeout
}
