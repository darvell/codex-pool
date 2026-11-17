package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func protocolEvents(t *testing.T, stream string) []map[string]any {
	t.Helper()
	var events []map[string]any
	var framer sseFramer
	data := []byte(stream)
	for len(data) > 0 {
		event, advance, ok := framer.next(data)
		if !ok {
			t.Fatalf("unterminated event: %q", data)
		}
		data = data[advance:]
		_, payload := parseSSEEvent(event)
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal(payload, &obj); err != nil {
			t.Fatal(err)
		}
		events = append(events, obj)
	}
	return events
}

func protocolJSON(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatal(err)
	}
	return obj
}

func TestResponsesToolIdentityPolicies(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"type":"response.output_item.added","item":{"type":"function_call","id":"item-a","call_id":"call-a","name":"old"}}`,
		`data: {"type":"response.output_item.added","item":{"type":"function_call","id":"item-a2","call_id":"call-a","name":"new"}}`,
		`data: {"type":"response.output_item.added","item":{"type":"function_call","id":"item-b","call_id":"call-b","name":"second"}}`,
		`data: {"type":"response.function_call_arguments.delta","item_id":"unknown","delta":"X"}`,
		`data: {"type":"response.function_call_arguments.done","item_id":"item-a2","arguments":"A"}`,
		`data: {"type":"response.output_item.done","item":{"id":"item-a","arguments":"A"}}`,
	}, "\n\n") + "\n\n"
	native := &responsesBufferingWriter{}
	buffered := &responsesToChatCompletionsBufferingWriter{}
	var out bytes.Buffer
	streamed := &responsesToChatCompletionsWriter{w: &out}
	for _, writer := range []io.Writer{native, buffered, streamed} {
		for _, part := range []string{stream[:71], stream[71:]} {
			if _, err := io.WriteString(writer, part); err != nil {
				t.Fatal(err)
			}
		}
	}
	nativeOutput := protocolJSON(t, native.Result())["output"].([]any)
	var nativeCalls []string
	for _, value := range nativeOutput {
		item := value.(map[string]any)
		if item["type"] == "function_call" {
			nativeCalls = append(nativeCalls, item["name"].(string)+":"+item["arguments"].(string))
		}
	}
	if !reflect.DeepEqual(nativeCalls, []string{"new:A", "second:X"}) {
		t.Fatalf("Responses calls = %v", nativeCalls)
	}
	chatOutput := protocolJSON(t, buffered.Result())["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["tool_calls"].([]any)
	var chatCalls []string
	for _, value := range chatOutput {
		fn := value.(map[string]any)["function"].(map[string]any)
		chatCalls = append(chatCalls, fn["name"].(string)+":"+fn["arguments"].(string))
	}
	if !reflect.DeepEqual(chatCalls, []string{"old:A", "new:X", "second:"}) {
		t.Fatalf("Chat calls = %v", chatCalls)
	}
	var indices []int64
	var arguments []string
	for _, event := range protocolEvents(t, out.String()) {
		delta := event["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)
		for _, value := range delta["tool_calls"].([]any) {
			tool := value.(map[string]any)
			indices = append(indices, toInt64(tool["index"]))
			arguments = append(arguments, tool["function"].(map[string]any)["arguments"].(string))
		}
	}
	if !reflect.DeepEqual(indices, []int64{0, 0, 1, 1, 0, 0}) || !reflect.DeepEqual(arguments, []string{"", "", "", "X", "A", "A"}) {
		t.Fatalf("streamed calls: indices=%v arguments=%v", indices, arguments)
	}
}

func TestResponsesUsageProjectionPolicies(t *testing.T) {
	terminal := `data: {"type":"response.completed","response":{"usage":{"input_tokens":7,"output_tokens":5,"total_tokens":99,"input_tokens_details":{"cached_tokens":3},"output_tokens_details":{"reasoning_tokens":2}}}}` + "\n\n"
	var completion, chat bytes.Buffer
	for _, writer := range []io.Writer{&responsesToCompletionsWriter{w: &completion}, &responsesToChatCompletionsWriter{w: &chat}} {
		if _, err := io.WriteString(writer, terminal); err != nil {
			t.Fatal(err)
		}
	}
	completionUsage := protocolEvents(t, completion.String())[0]["usage"].(map[string]any)
	chatUsage := protocolEvents(t, chat.String())[0]["usage"].(map[string]any)
	if !reflect.DeepEqual(completionUsage, map[string]any{
		"prompt_tokens": float64(7), "completion_tokens": float64(5), "total_tokens": float64(99),
		"prompt_tokens_details":     map[string]any{"cached_tokens": float64(3)},
		"completion_tokens_details": map[string]any{"reasoning_tokens": float64(2)},
	}) {
		t.Fatalf("completion usage = %#v", completionUsage)
	}
	if !reflect.DeepEqual(chatUsage, map[string]any{
		"prompt_tokens": float64(7), "completion_tokens": float64(5), "total_tokens": float64(12),
		"prompt_tokens_details": map[string]any{"cached_tokens": float64(3)},
	}) {
		t.Fatalf("chat usage = %#v", chatUsage)
	}
}

func TestClaudeInitialUsagePolicies(t *testing.T) {
	var chat, responses bytes.Buffer
	chatWriter := &sseTranslateWriter{w: &chat, direction: TranslateOAIToClaude}
	responseWriter := &responsesToClaudeWriter{w: &responses}
	if _, err := io.WriteString(chatWriter, `data: {"id":"same","model":"model","choices":[{"delta":{"role":"assistant","content":"hello"}}],"usage":{"prompt_tokens":11}}`+"\n\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(responseWriter, `data: {"type":"response.created","response":{"id":"same","model":"model","usage":{"input_tokens":11}}}`+"\n\n"+`data: {"type":"response.output_text.delta","delta":"hello"}`+"\n\n"); err != nil {
		t.Fatal(err)
	}
	chatEvents := protocolEvents(t, chat.String())
	responseEvents := protocolEvents(t, responses.String())
	chatUsage := chatEvents[0]["message"].(map[string]any)["usage"].(map[string]any)
	responseUsage := responseEvents[0]["message"].(map[string]any)["usage"].(map[string]any)
	if toInt64(chatUsage["input_tokens"]) != 0 || toInt64(responseUsage["input_tokens"]) != 11 {
		t.Fatalf("initial usage: chat=%v responses=%v", chatUsage, responseUsage)
	}
	if !reflect.DeepEqual(chatEvents[1:], responseEvents[1:]) {
		t.Fatalf("block emission differs: chat=%v responses=%v", chatEvents[1:], responseEvents[1:])
	}
}

func TestUsageStreamObservesFailure(t *testing.T) {
	failure := errors.New("client disconnected")
	sink := &streamFailureSink{err: failure}
	translator := &responsesToChatCompletionsWriter{w: sink}
	var observed, committed []string
	writer := newUsageStream(translator, func(data []byte, add func(RequestUsage)) {
		event := protocolJSON(t, data)
		id := event["type"].(string)
		observed = append(observed, id)
		add(RequestUsage{RequestID: id})
	}, func(usage RequestUsage) {
		if sink.calls == 0 {
			t.Fatal("usage committed before forwarding")
		}
		committed = append(committed, usage.RequestID)
	})
	stream := `data: {"type":"response.output_text.delta","delta":"hello"}` + "\n\n" + `data: {"type":"response.completed","response":{"usage":{"input_tokens":7,"output_tokens":3}}}` + "\n\n"
	if _, err := io.WriteString(writer, stream); !errors.Is(err, failure) {
		t.Fatalf("Write = %v", err)
	}
	want := []string{"response.output_text.delta", "response.completed"}
	if !reflect.DeepEqual(observed, want) || !reflect.DeepEqual(committed, want) || sink.calls != 1 {
		t.Fatalf("observed=%v committed=%v writes=%d", observed, committed, sink.calls)
	}
}

func TestUsageStreamSuppressesBeforeWrite(t *testing.T) {
	var out bytes.Buffer
	suppress := &sseInterceptWriter{w: &out, onEvent: func(data []byte) (bool, bool) {
		blocked := protocolJSON(t, data)["type"] == "blocked"
		return blocked, blocked
	}}
	var observed, committed []string
	writer := newUsageStream(suppress, func(data []byte, add func(RequestUsage)) {
		id := protocolJSON(t, data)["type"].(string)
		observed = append(observed, id)
		add(RequestUsage{RequestID: id})
	}, func(usage RequestUsage) {
		committed = append(committed, usage.RequestID)
	})
	visible := "data: {\"type\":\"visible\"}\n\n"
	stream := visible + "data: {\"type\":\"blocked\"}\n\ndata: {\"type\":\"after\"}\n\n"
	if n, err := io.WriteString(writer, stream); n != len(stream) || err != nil {
		t.Fatalf("Write = (%d, %v)", n, err)
	}
	want := []string{"visible", "blocked", "after"}
	if out.String() != visible || !reflect.DeepEqual(observed, want) || !reflect.DeepEqual(committed, want) {
		t.Fatalf("forwarded=%q observed=%v committed=%v", out.String(), observed, committed)
	}
}

type protocolWriteFunc func([]byte) (int, error)

func (f protocolWriteFunc) Write(p []byte) (int, error) { return f(p) }

func TestUsageStreamBoundsAccounting(t *testing.T) {
	const count = 10000
	var out bytes.Buffer
	committed, writes := 0, 0
	sink := protocolWriteFunc(func(p []byte) (int, error) {
		if len(p) > streamUsageChunkBytes {
			t.Fatalf("forwarded chunk = %d bytes", len(p))
		}
		if writes > 0 && committed == 0 {
			t.Fatal("next chunk forwarded before accounting the previous chunk")
		}
		writes++
		return out.Write(p)
	})
	writer := newUsageStream(sink, func(data []byte, add func(RequestUsage)) {
		add(RequestUsage{RequestID: string(data)})
	}, func(usage RequestUsage) {
		if usage.RequestID != `{}` {
			t.Fatalf("observed payload = %q", usage.RequestID)
		}
		committed++
	})
	body := strings.Repeat("data: {}\n\n", count)
	if n, err := io.WriteString(writer, body); n != len(body) || err != nil {
		t.Fatalf("Write = (%d, %v)", n, err)
	}
	if writes < 2 || committed != count || out.String() != body {
		t.Fatalf("writes=%d committed=%d output bytes=%d", writes, committed, out.Len())
	}
}
