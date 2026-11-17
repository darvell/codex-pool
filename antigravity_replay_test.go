package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestAntigravityReplayRestoresNativeFunctionCallSignature(t *testing.T) {
	cache := newAntigravityReplayCache(time.Hour, 10240)
	request := replayTestEnvelope("gemini-3.1-flash-lite", "session-1", []any{
		map[string]any{"role": "user", "parts": []any{map[string]any{"text": "read the file"}}},
	})
	scope := antigravityReplayScopeFromBodyForTenant(request, "user\x00origin")
	response := []byte(`{"response":{"candidates":[{"content":{"parts":[{"functionCall":{"id":"call-1","name":"default_api:Read","args":{"file_path":"README.md"}},"thoughtSignature":"native-signature-value"}]}}]}}`)
	if !cache.capture(scope, request, response) {
		t.Fatal("capture returned false")
	}

	next := replayTestEnvelope("gemini-3.1-flash-lite", "session-1", []any{
		map[string]any{"role": "user", "parts": []any{map[string]any{"text": "read the file"}}},
		map[string]any{"role": "model", "parts": []any{map[string]any{"functionCall": map[string]any{"id": "call-1", "name": "default_api:Read", "args": map[string]any{"file_path": "README.md"}}, "thoughtSignature": antigravityFunctionThoughtSignature}}},
		map[string]any{"role": "user", "parts": []any{map[string]any{"functionResponse": map[string]any{"id": "call-1", "name": "default_api:Read", "response": map[string]any{"result": "ok"}}}}},
	})
	updated, changed := cache.apply(scope, next)
	if !changed {
		t.Fatal("apply returned unchanged")
	}
	part := replayTestPart(t, updated, 1, 0)
	if got := part["thoughtSignature"]; got != "native-signature-value" {
		t.Fatalf("thoughtSignature = %#v", got)
	}
	call := part["functionCall"].(map[string]any)
	if call["name"] != "default_api:Read" {
		t.Fatalf("function call was not replayed verbatim: %#v", call)
	}
}

func TestAntigravityReplayInsertsMissingFunctionCallBeforeResult(t *testing.T) {
	cache := newAntigravityReplayCache(time.Hour, 10240)
	request := replayTestEnvelope("gemini-3.1-flash-lite", "session-2", []any{map[string]any{"role": "user", "parts": []any{map[string]any{"text": "run it"}}}})
	scope := antigravityReplayScopeFromBodyForTenant(request, "user\x00origin")
	response := []byte(`{"response":{"candidates":[{"content":{"parts":[{"functionCall":{"id":"call-2","name":"shell","args":{"command":"pwd"}},"thoughtSignature":"native-signature-value"}]}}]}}`)
	cache.capture(scope, request, response)
	next := replayTestEnvelope("gemini-3.1-flash-lite", "session-2", []any{
		map[string]any{"role": "user", "parts": []any{map[string]any{"text": "run it"}}},
		map[string]any{"role": "user", "parts": []any{map[string]any{"functionResponse": map[string]any{"id": "call-2", "name": "shell", "response": map[string]any{"result": "ok"}}}}},
	})
	updated, changed := cache.apply(scope, next)
	if !changed {
		t.Fatal("apply returned unchanged")
	}
	var root map[string]any
	if err := json.Unmarshal(updated, &root); err != nil {
		t.Fatal(err)
	}
	contents := root["request"].(map[string]any)["contents"].([]any)
	if len(contents) != 3 {
		t.Fatalf("contents length = %d, want 3", len(contents))
	}
	inserted := contents[1].(map[string]any)
	if inserted["role"] != "model" {
		t.Fatalf("inserted content = %#v", inserted)
	}
	part := inserted["parts"].([]any)[0].(map[string]any)
	if part["thoughtSignature"] != "native-signature-value" {
		t.Fatalf("inserted part = %#v", part)
	}
}

func TestAntigravityReplayRestoresSignatureForCallWithoutID(t *testing.T) {
	cache := newAntigravityReplayCache(time.Hour, 10240)
	request := replayTestEnvelope("gemini-3.1-flash-lite", "session-no-id", []any{map[string]any{"role": "user", "parts": []any{map[string]any{"text": "search"}}}})
	scope := antigravityReplayScopeFromBodyForTenant(request, "user\x00origin")
	response := []byte(`{"response":{"candidates":[{"content":{"parts":[{"functionCall":{"name":"search","args":{"query":"gemini"}},"thoughtSignature":"native-signature-value"}]}}]}}`)
	cache.capture(scope, request, response)
	next := replayTestEnvelope("gemini-3.1-flash-lite", "session-no-id", []any{
		map[string]any{"role": "user", "parts": []any{map[string]any{"text": "search"}}},
		map[string]any{"role": "model", "parts": []any{map[string]any{"functionCall": map[string]any{"name": "search", "args": map[string]any{"query": "gemini"}}, "thoughtSignature": antigravityFunctionThoughtSignature}}},
		map[string]any{"role": "user", "parts": []any{map[string]any{"functionResponse": map[string]any{"name": "search", "response": map[string]any{"result": "ok"}}}}},
	})
	updated, changed := cache.apply(scope, next)
	if !changed {
		t.Fatal("apply returned unchanged")
	}
	if got := replayTestPart(t, updated, 1, 0)["thoughtSignature"]; got != "native-signature-value" {
		t.Fatalf("thoughtSignature = %#v", got)
	}
}

func TestAntigravityReplayDoesNotReplaceSyntheticSignatureWithUnsignedParallelCall(t *testing.T) {
	cache := newAntigravityReplayCache(time.Hour, 10240)
	request := replayTestEnvelope("gemini-3.5-flash", "session-parallel", []any{
		map[string]any{"role": "user", "parts": []any{map[string]any{"text": "read both"}}},
	})
	scope := antigravityReplayScopeFromBodyForTenant(request, "user\x00origin")
	response := []byte(`{"response":{"candidates":[{"content":{"parts":[{"functionCall":{"id":"call-2","name":"default_api:Read","args":{"file_path":"package.json"}}}]}}]}}`)
	if !cache.capture(scope, request, response) {
		t.Fatal("unsigned function call was not captured")
	}
	next := replayTestEnvelope("gemini-3.5-flash", "session-parallel", []any{
		map[string]any{"role": "user", "parts": []any{map[string]any{"text": "read both"}}},
		map[string]any{"role": "model", "parts": []any{map[string]any{
			"functionCall":     map[string]any{"id": "call-2", "name": "default_api:Read", "args": map[string]any{"file_path": "package.json"}},
			"thoughtSignature": antigravityFunctionThoughtSignature,
		}}},
		map[string]any{"role": "user", "parts": []any{map[string]any{"functionResponse": map[string]any{"id": "call-2", "name": "default_api:Read", "response": map[string]any{"result": "ok"}}}}},
	})
	updated, _ := cache.apply(scope, next)
	part := replayTestPart(t, updated, 1, 0)
	if part["thoughtSignature"] != antigravityFunctionThoughtSignature {
		t.Fatalf("synthetic signature was lost: %#v", part)
	}
}

func TestAntigravityReplayClearsOnlySignatureBadRequests(t *testing.T) {
	cache := newAntigravityReplayCache(time.Hour, 10240)
	request := replayTestEnvelope("gemini-3.1-flash-lite", "session-3", []any{map[string]any{"role": "user", "parts": []any{map[string]any{"text": "go"}}}})
	scope := antigravityReplayScopeFromBodyForTenant(request, "user\x00origin")
	response := []byte(`{"response":{"candidates":[{"content":{"parts":[{"functionCall":{"id":"call-3","name":"tool","args":{}},"thoughtSignature":"native-signature-value"}]}}]}}`)
	if !cache.capture(scope, request, response) {
		t.Fatal("signed function call was not captured")
	}
	next := replayTestEnvelope("gemini-3.1-flash-lite", "session-3", []any{
		map[string]any{"role": "user", "parts": []any{map[string]any{"text": "go"}}},
		map[string]any{"role": "user", "parts": []any{map[string]any{"functionResponse": map[string]any{"id": "call-3", "name": "tool", "response": map[string]any{"result": "ok"}}}}},
	})
	for _, failure := range []struct {
		status int
		body   string
	}{
		{http.StatusInternalServerError, "thoughtSignature invalid"},
		{http.StatusBadRequest, "invalid request"},
	} {
		if cache.clearForInvalidSignature(scope, failure.status, []byte(failure.body)) {
			t.Fatalf("cleared on unrelated error: %+v", failure)
		}
		updated, changed := cache.apply(scope, next)
		if !changed || replayTestPart(t, updated, 1, 0)["thoughtSignature"] != "native-signature-value" {
			t.Fatal("unrelated error discarded signed replay")
		}
	}
	if !cache.clearForInvalidSignature(scope, http.StatusBadRequest, []byte("Function call has invalid thought_signature")) {
		t.Fatal("did not clear signature 400")
	}
	if updated, changed := cache.apply(scope, next); changed || !bytes.Equal(updated, next) {
		t.Fatalf("cleared signature was replayed: %s", updated)
	}
}

func TestAntigravityReplayCacheIsConcurrent(t *testing.T) {
	cache := newAntigravityReplayCache(time.Hour, 10240)
	request := replayTestEnvelope("gemini-3.1-flash-lite", "session-race", []any{map[string]any{"role": "user", "parts": []any{map[string]any{"text": "go"}}}})
	scope := antigravityReplayScopeFromBodyForTenant(request, "user\x00origin")
	response := []byte(`{"response":{"candidates":[{"content":{"parts":[{"functionCall":{"id":"call-race","name":"tool","args":{}},"thoughtSignature":"native-signature-value"}]}}]}}`)
	next := replayTestEnvelope("gemini-3.1-flash-lite", "session-race", []any{
		map[string]any{"role": "user", "parts": []any{map[string]any{"text": "go"}}},
		map[string]any{"role": "user", "parts": []any{map[string]any{"functionResponse": map[string]any{"id": "call-race", "name": "tool", "response": map[string]any{"result": "ok"}}}}},
	})
	const callers = 32
	replayed := make(chan []byte, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !cache.capture(scope, request, response) {
				t.Error("signed function call was not captured")
				return
			}
			updated, changed := cache.apply(scope, next)
			if !changed {
				t.Error("signed function call was not replayed")
				return
			}
			replayed <- updated
		}()
	}
	wg.Wait()
	close(replayed)
	for updated := range replayed {
		part := replayTestPart(t, updated, 1, 0)
		want := map[string]any{"functionCall": map[string]any{"id": "call-race", "name": "tool", "args": map[string]any{}}, "thoughtSignature": "native-signature-value"}
		if !reflect.DeepEqual(part, want) {
			t.Fatalf("replayed part=%#v, want %#v", part, want)
		}
	}
}

func TestAntigravityReplayCacheExpiresSessions(t *testing.T) {
	cache := newAntigravityReplayCache(time.Hour, 10240)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	cache.now = func() time.Time { return now }
	request := replayTestEnvelope("gemini-3.1-flash-lite", "session-expiry", []any{map[string]any{"role": "user", "parts": []any{map[string]any{"text": "go"}}}})
	scope := antigravityReplayScopeFromBodyForTenant(request, "user\x00origin")
	response := []byte(`{"response":{"candidates":[{"content":{"parts":[{"functionCall":{"id":"call-expiry","name":"tool","args":{}},"thoughtSignature":"native-signature-value"}]}}]}}`)
	if !cache.capture(scope, request, response) {
		t.Fatal("signed function call was not captured")
	}
	next := replayTestEnvelope("gemini-3.1-flash-lite", "session-expiry", []any{
		map[string]any{"role": "user", "parts": []any{map[string]any{"text": "go"}}},
		map[string]any{"role": "user", "parts": []any{map[string]any{"functionResponse": map[string]any{"id": "call-expiry", "name": "tool", "response": map[string]any{"result": "ok"}}}}},
	})
	if updated, changed := cache.apply(scope, next); !changed || replayTestPart(t, updated, 1, 0)["thoughtSignature"] != "native-signature-value" {
		t.Fatal("unexpired signed function call was not replayed")
	}
	now = now.Add(time.Hour + time.Nanosecond)
	if updated, changed := cache.apply(scope, next); changed || !bytes.Equal(updated, next) {
		t.Fatalf("expired replay changed the request: %s", updated)
	}
}

func replayTestEnvelope(model, session string, contents []any) []byte {
	body, _ := json.Marshal(map[string]any{"model": model, "request": map[string]any{"sessionId": session, "contents": contents}})
	return body
}

func replayTestPart(t *testing.T, body []byte, contentIndex, partIndex int) map[string]any {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		t.Fatal(err)
	}
	contents := root["request"].(map[string]any)["contents"].([]any)
	return contents[contentIndex].(map[string]any)["parts"].([]any)[partIndex].(map[string]any)
}
