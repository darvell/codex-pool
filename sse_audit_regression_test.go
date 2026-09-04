package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestStreamingMixedEndings(t *testing.T) {
	for _, a := range []string{"\n", "\r\n", "\r"} {
		for _, b := range []string{"\n", "\r\n", "\r"} {
			first := "event: response.output_text.delta" + a + `data: {"type":"response.output_text.delta","delta":"FIRST"}` + a + a
			second := "event: response.output_text.delta" + b + `data: {"type":"response.output_text.delta","delta":"SECOND"}` + b + b
			stream := first + second
			for split := 0; split <= len(stream); split++ {
				var out bytes.Buffer
				w := &responsesToChatCompletionsWriter{w: &out}
				for _, p := range []string{stream[:split], stream[split:]} {
					if _, err := io.WriteString(w, p); err != nil {
						t.Fatal(err)
					}
				}
				if !strings.Contains(out.String(), "FIRST") || !strings.Contains(out.String(), "SECOND") {
					t.Fatalf("endings %q/%q split %d: %s", a, b, split, out.String())
				}
				var seen []string
				inspect := &sseInterceptWriter{w: io.Discard, callback: func(p []byte) { seen = append(seen, string(p)) }}
				_, _ = io.WriteString(inspect, stream[:split])
				_, _ = io.WriteString(inspect, stream[split:])
				if len(seen) != 2 {
					t.Fatalf("inspection endings %q/%q split %d: %v", a, b, split, seen)
				}
			}
		}
	}
}

func TestStreamingHostedFilterSplits(t *testing.T) {
	for _, a := range []string{"\n", "\r\n", "\r"} {
		for _, b := range []string{"\n", "\r\n", "\r"} {
			stream := "event: response.output_item.added" + a + `data: {"type":"response.output_item.added","item":{"type":"mcp_call","id":"hidden-item"}}` + a + a + "data: {\"type\":\"response.output_text.delta\",\"delta\":\"visible\"}" + b + b
			for split := 0; split <= len(stream); split++ {
				var out bytes.Buffer
				w := &hostedMCPResponseFilterWriter{w: &out}
				_, err := io.WriteString(w, stream[:split])
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.WriteString(w, stream[split:])
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(out.String(), "hidden-item") || !strings.Contains(out.String(), "visible") {
					t.Fatalf("endings %q/%q split %d: %s", a, b, split, out.String())
				}
			}
		}
	}
}

type streamFailureSink struct {
	err   error
	calls int
}

func (s *streamFailureSink) Write(p []byte) (int, error) {
	s.calls++
	if s.err != nil {
		return 0, s.err
	}
	return len(p) - 1, nil
}

func TestStreamingDownstreamErrors(t *testing.T) {
	response := "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n"
	claude := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\"}}\n\n"
	chat := "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"hello\"}}]}\n\n"
	cases := []struct {
		name, input string
		new         func(io.Writer) io.Writer
	}{
		{"inspection", response, func(w io.Writer) io.Writer { return &sseInterceptWriter{w: w} }},
		{"suppression", response, func(w io.Writer) io.Writer {
			return &sseInterceptWriter{w: w, onEvent: func([]byte) (bool, bool) { return false, false }}
		}},
		{"hosted-filter", response, func(w io.Writer) io.Writer { return &hostedMCPResponseFilterWriter{w: w} }},
		{"responses-chat", response, func(w io.Writer) io.Writer { return &responsesToChatCompletionsWriter{w: w} }},
		{"responses-completions", response, func(w io.Writer) io.Writer { return &responsesToCompletionsWriter{w: w} }},
		{"responses-claude", response, func(w io.Writer) io.Writer { return &responsesToClaudeWriter{w: w} }},
		{"claude-responses", claude, func(w io.Writer) io.Writer { return &claudeToResponsesWriter{w: w} }},
		{"claude-chat", claude, func(w io.Writer) io.Writer { return &sseTranslateWriter{w: w, direction: TranslateClaudeToOAI} }},
		{"chat-claude", chat, func(w io.Writer) io.Writer { return &sseTranslateWriter{w: w, direction: TranslateOAIToClaude} }},
	}
	for _, tc := range cases {
		for _, failure := range []error{errors.New("client disconnected"), nil} {
			t.Run(fmt.Sprint(tc.name, "/", failure), func(t *testing.T) {
				sink := &streamFailureSink{err: failure}
				w := tc.new(sink)
				want := failure
				if want == nil {
					want = io.ErrShortWrite
				}
				_, err := io.WriteString(w, tc.input+tc.input)
				if !errors.Is(err, want) {
					t.Fatalf("got %v want %v", err, want)
				}
				n, err := io.WriteString(w, tc.input)
				if n != 0 || !errors.Is(err, want) || sink.calls != 1 {
					t.Fatalf("sticky failure: n=%d err=%v writes=%d", n, err, sink.calls)
				}
			})
		}
	}
}

func TestStreamingLargeFragmentedEvent(t *testing.T) {
	text := strings.Repeat("x", 1200000)
	event := "data: {\"type\":\"response.output_text.delta\",\"delta\":\"" + text + "\"}\n\n"
	for _, size := range []int{len(event), 32 * 1024} {
		var out bytes.Buffer
		w := &responsesToChatCompletionsWriter{w: &out}
		for pos := 0; pos < len(event); pos += size {
			if _, err := io.WriteString(w, event[pos:min(pos+size, len(event))]); err != nil {
				t.Fatal(err)
			}
		}
		if !strings.Contains(out.String(), text) {
			t.Fatalf("lost large event with chunk size %d", size)
		}
	}
}

func TestStreamingRawFraming(t *testing.T) {
	endings := []string{"\n", "\r\n", "\r"}
	for _, a := range endings {
		for _, b := range endings {
			for _, c := range endings {
				stream := "event: test" + a + "data: first" + b + "data: second" + c + c
				for split := 0; split <= len(stream); split++ {
					var out bytes.Buffer
					var seen []string
					w := &sseInterceptWriter{w: &out, onEvent: func(p []byte) (bool, bool) { seen = append(seen, string(p)); return false, false }}
					_, err := io.WriteString(w, stream[:split])
					if err != nil {
						t.Fatal(err)
					}
					_, err = io.WriteString(w, stream[split:])
					if err != nil {
						t.Fatal(err)
					}
					if out.String() != stream || len(seen) != 1 || seen[0] != "first\nsecond" {
						t.Fatalf("endings %q/%q/%q split %d output=%q data=%q", a, b, c, split, out.String(), seen)
					}
				}
			}
		}
	}
}

func TestStreamingBytewiseFraming(t *testing.T) {
	stream := "data: first\r\n\r\ndata: second\r\rdata: third\n\n"
	var out bytes.Buffer
	var seen []string
	w := &sseInterceptWriter{w: &out, onEvent: func(p []byte) (bool, bool) { seen = append(seen, string(p)); return false, false }}
	for i := range stream {
		if _, err := w.Write([]byte{stream[i]}); err != nil {
			t.Fatal(err)
		}
	}
	if out.String() != stream || strings.Join(seen, ",") != "first,second,third" {
		t.Fatalf("output=%q data=%v", out.String(), seen)
	}
}

func TestStreamingSiblingFraming(t *testing.T) {
	cases := []struct {
		name, data string
		new        func(*bytes.Buffer) io.Writer
	}{
		{"responses-completions", `{"type":"response.output_text.delta","delta":"TOKEN"}`, func(out *bytes.Buffer) io.Writer { return &responsesToCompletionsWriter{w: out} }},
		{"responses-claude", `{"type":"response.output_text.delta","delta":"TOKEN"}`, func(out *bytes.Buffer) io.Writer { return &responsesToClaudeWriter{w: out} }},
		{"claude-responses", `{"type":"content_block_delta","delta":{"type":"text_delta","text":"TOKEN"}}`, func(out *bytes.Buffer) io.Writer { return &claudeToResponsesWriter{w: out} }},
		{"claude-chat", `{"type":"content_block_delta","delta":{"type":"text_delta","text":"TOKEN"}}`, func(out *bytes.Buffer) io.Writer { return &sseTranslateWriter{w: out, direction: TranslateClaudeToOAI} }},
		{"chat-claude", `{"choices":[{"delta":{"role":"assistant","content":"TOKEN"}}]}`, func(out *bytes.Buffer) io.Writer { return &sseTranslateWriter{w: out, direction: TranslateOAIToClaude} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stream := "data: " + strings.ReplaceAll(tc.data, "TOKEN", "FIRST") + "\r\n\r\ndata: " + strings.ReplaceAll(tc.data, "TOKEN", "SECOND") + "\r\r"
			// Claude translators accept the public event name in the SSE field.
			if strings.HasPrefix(tc.name, "claude-") {
				stream = strings.ReplaceAll(stream, "data: ", "event: content_block_delta\rdata: ")
			}
			for split := 0; split <= len(stream); split++ {
				var out bytes.Buffer
				w := tc.new(&out)
				_, err := io.WriteString(w, stream[:split])
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.WriteString(w, stream[split:])
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out.String(), "FIRST") || !strings.Contains(out.String(), "SECOND") {
					t.Fatalf("split %d: %s", split, out.String())
				}
			}
		})
	}
}

func TestStreamingBufferingFraming(t *testing.T) {
	stream := "data: {\"type\":\"response.output_text.delta\",\"delta\":\"FIRST\"}\r\n\r\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"SECOND\"}\r\r"
	for split := 0; split <= len(stream); split++ {
		response := &responsesBufferingWriter{}
		completion := &responsesToCompletionsBufferingWriter{}
		chat := &responsesToChatCompletionsBufferingWriter{}
		claude := &responsesToClaudeBufferingWriter{}
		for _, w := range []io.Writer{response, completion, chat, claude} {
			_, err := io.WriteString(w, stream[:split])
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.WriteString(w, stream[split:])
			if err != nil {
				t.Fatal(err)
			}
		}
		if string(response.contentText) != "FIRSTSECOND" || string(completion.contentText) != "FIRSTSECOND" || string(chat.contentText) != "FIRSTSECOND" || string(claude.contentText) != "FIRSTSECOND" {
			t.Fatalf("buffered content missing at split %d", split)
		}
	}
}

func TestStreamingLargeInspection(t *testing.T) {
	text := strings.Repeat("x", 1200000)
	stream := "data: " + text + "\n\n"
	var seen []string
	w := &sseInterceptWriter{w: io.Discard, callback: func(p []byte) { seen = append(seen, string(p)) }}
	for pos := 0; pos < len(stream); pos += 32 * 1024 {
		if _, err := io.WriteString(w, stream[pos:min(pos+32*1024, len(stream))]); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 1 || seen[0] != text {
		t.Fatal("fragmented inspection event lost")
	}
}

func TestStreamingIncompleteSiblings(t *testing.T) {
	terminal := "data: {\"type\":\"response.incomplete\",\"response\":{\"status\":\"incomplete\",\"incomplete_details\":{\"reason\":\"max_output_tokens\"},\"usage\":{\"input_tokens\":7,\"output_tokens\":3}}}\r\r"
	stream := terminal + terminal + "data: [DONE]\n\n"
	var completionOut, claudeOut bytes.Buffer
	completion := &responsesToCompletionsWriter{w: &completionOut}
	claude := &responsesToClaudeWriter{w: &claudeOut}
	for _, w := range []io.Writer{completion, claude} {
		if _, err := io.WriteString(w, stream); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Count(completionOut.String(), "data: [DONE]") != 1 || !strings.Contains(completionOut.String(), `"finish_reason":"length"`) || !strings.Contains(completionOut.String(), `"prompt_tokens":7`) {
		t.Fatal(completionOut.String())
	}
	if strings.Count(claudeOut.String(), "event: message_stop") != 1 || !strings.Contains(claudeOut.String(), `"stop_reason":"max_tokens"`) || !strings.Contains(claudeOut.String(), `"input_tokens":7`) || !strings.Contains(claudeOut.String(), `"output_tokens":3`) {
		t.Fatal(claudeOut.String())
	}

	response := &responsesBufferingWriter{}
	completionBuffer := &responsesToCompletionsBufferingWriter{}
	chatBuffer := &responsesToChatCompletionsBufferingWriter{}
	claudeBuffer := &responsesToClaudeBufferingWriter{}
	for _, w := range []io.Writer{response, completionBuffer, chatBuffer, claudeBuffer} {
		if _, err := io.WriteString(w, stream); err != nil {
			t.Fatal(err)
		}
	}
	if response.status != "incomplete" || completionBuffer.finishReason != "length" || chatBuffer.finishReason != "length" || claudeBuffer.stopReason != "max_tokens" {
		t.Fatal("incomplete terminal not mapped by buffering writer")
	}
	if response.inputTokens != 7 || response.outputTokens != 3 || completionBuffer.inputTokens != 7 || completionBuffer.outputTokens != 3 || chatBuffer.inputTokens != 7 || chatBuffer.outputTokens != 3 || claudeBuffer.inputTokens != 7 || claudeBuffer.outputTokens != 3 {
		t.Fatal("incomplete usage lost by buffering writer")
	}
}

func TestStreamingIncompleteTerminal(t *testing.T) {
	for _, reason := range []string{"max_output_tokens", "content_filter"} {
		terminal := `data: {"type":"response.incomplete","response":{"status":"incomplete","incomplete_details":{"reason":"` + reason + `"},"usage":{"input_tokens":7,"output_tokens":3}}}` + "\n\n"
		stream := "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n" + terminal + terminal + "data: [DONE]\n\n"
		var out bytes.Buffer
		w := &responsesToChatCompletionsWriter{w: &out}
		if _, err := io.WriteString(w, stream); err != nil {
			t.Fatal(err)
		}
		finish := reason
		if reason == "max_output_tokens" {
			finish = "length"
		}
		if strings.Count(out.String(), "data: [DONE]") != 1 || !strings.Contains(out.String(), `"finish_reason":"`+finish+`"`) || !strings.Contains(out.String(), `"prompt_tokens":7`) || !strings.Contains(out.String(), `"completion_tokens":3`) {
			t.Fatal(out.String())
		}
	}
}
