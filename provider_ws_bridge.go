package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
)

// The Codex Responses websocket reaches chatgpt.com, which rejects models
// the pool serves from other providers, such as antigravity/gemini-4-neon.
// Codex sends every turn over that socket once websockets are enabled, so
// the relay hands those turns to the pool's HTTP route through the same
// bridge Pro models use and writes the SSE events back as websocket frames.

// webSocketBridgesModel reports models the HTTP route serves from a provider
// other than the Codex backend.
func (h *proxyHandler) webSocketBridgesModel(model string) bool {
	if modelRequiresHTTPProviderRoute(model) {
		return true
	}
	return h.pool != nil && shouldRouteAntigravityModel(&h.pool.antigravityModels, model)
}

// providerWSTranscript lets a websocket client chain turns with
// previous_response_id. The HTTP providers behind the bridge keep no
// server-side conversation, so the bridge records each completed turn's full
// input and output for this socket and replays them ahead of the next
// turn's input.
type providerWSTranscript struct {
	mu      sync.Mutex
	pending []json.RawMessage
	turns   map[string][]json.RawMessage
}

const maxProviderWSTranscriptTurns = 64

func newProviderRoutedWS(ctx context.Context, h *proxyHandler, r *http.Request, write proWSWrite, limit int64, onDone func()) *chatGPTProWS {
	transcript := &providerWSTranscript{turns: map[string][]json.RawMessage{}}
	observe := func(ctx context.Context, data []byte) error {
		transcript.observe(data)
		return write(ctx, data)
	}
	bridge := newChatGPTProWS(ctx, r, h.providerWSHandler(transcript), observe, limit, onDone)
	bridge.claims = h.webSocketBridgesModel
	return bridge
}

func (h *proxyHandler) providerWSHandler(transcript *providerWSTranscript) proWSHandler {
	return func(w http.ResponseWriter, r *http.Request, body []byte, model string) bool {
		expanded, ok := transcript.expand(body)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"type":"invalid_request_error","code":"previous_response_not_found","message":"Previous response is not available on this connection. Resend the conversation without previous_response_id."}}`))
			return true
		}

		for _, key := range []string{"Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions", "Sec-WebSocket-Protocol"} {
			r.Header.Del(key)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "text/event-stream")
		r.Header.Del("Content-Length")
		r.Body = io.NopCloser(bytes.NewReader(expanded))
		r.ContentLength = int64(len(expanded))
		h.ServeHTTP(w, r)
		return true
	}
}

// expand replaces previous_response_id with the recorded turns it names and
// remembers the resulting input until the turn completes. It reports false
// when the id was not produced on this socket.
func (t *providerWSTranscript) expand(body []byte) ([]byte, bool) {
	var request map[string]json.RawMessage
	if json.Unmarshal(body, &request) != nil {
		return body, true
	}
	input := responsesInputItems(request["input"])

	var previous string
	_ = json.Unmarshal(request["previous_response_id"], &previous)

	t.mu.Lock()
	defer t.mu.Unlock()
	if previous != "" {
		history, ok := t.turns[previous]
		if !ok {
			return nil, false
		}
		input = append(append([]json.RawMessage{}, history...), input...)
		delete(request, "previous_response_id")
	}
	t.pending = input

	encoded, err := json.Marshal(input)
	if err != nil {
		return body, true
	}
	request["input"] = encoded
	out, err := json.Marshal(request)
	if err != nil {
		return body, true
	}
	return out, true
}

func (t *providerWSTranscript) observe(data []byte) {
	var event struct {
		Type     string `json:"type"`
		Response struct {
			ID     string            `json:"id"`
			Output []json.RawMessage `json:"output"`
		} `json:"response"`
	}
	if json.Unmarshal(data, &event) != nil || event.Type != "response.completed" || event.Response.ID == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.turns) >= maxProviderWSTranscriptTurns {
		t.turns = map[string][]json.RawMessage{}
	}
	t.turns[event.Response.ID] = append(append([]json.RawMessage{}, t.pending...), event.Response.Output...)
}

func responsesInputItems(raw json.RawMessage) []json.RawMessage {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) == nil {
		return items
	}
	var text string
	if json.Unmarshal(raw, &text) != nil || text == "" {
		return nil
	}
	message, _ := json.Marshal(map[string]any{
		"type":    "message",
		"role":    "user",
		"content": []map[string]string{{"type": "input_text", "text": text}},
	})
	return []json.RawMessage{message}
}
