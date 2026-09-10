package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
)

func TestReadCompactResponse(t *testing.T) {
	tests := []struct {
		name string
		sse  string
		want string
	}{
		{
			name: "done items override empty terminal output and retain opaque fields",
			sse: "data: {\"type\":\"response.created\",\"response\":{\"id\":\"created\"}}\n\n" +
				"data: {\"type\":\"response.output_item.done\",\"output_index\":2,\"item\":{\"type\":\"compaction\",\"encrypted_content\":\"opaque+/=\\nsecret\",\"unknown\":{\"n\":9007199254740993}}}\n\n" +
				"data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"future\",\"first\":true}}\n\n" +
				"data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"future\",\"second\":true}}\n\n" +
				"data: {\"type\":\"response.completed\",\"response\":{\"output\":[],\"usage\":{\"input_tokens\":42},\"error\":null}}\n\n",
			want: `{"object":"response.compact","id":"created","status":"completed","output":[{"type":"future","first":true},{"type":"future","second":true},{"type":"compaction","encrypted_content":"opaque+/=\nsecret","unknown":{"n":9007199254740993}}],"usage":{"input_tokens":42}}`,
		},
		{
			name: "CRLF multiline final undelimited terminal",
			sse:  ": heartbeat\r\n\r\nevent: response.completed\r\ndata: {\"type\":\"response.completed\",\r\ndata: \"response\":{\"id\":\"terminal\",\"output\":[{\"type\":\"compaction\",\"encrypted_content\":\"abc\"}]}}",
			want: `{"object":"response.compact","id":"terminal","status":"completed","output":[{"type":"compaction","encrypted_content":"abc"}]}`,
		},
		{
			name: "terminal id wins and done items override nonempty terminal output",
			sse: "data: {\"type\":\"response.created\",\"response\":{\"id\":\"created\"}}\n\n" +
				"data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"compaction\"}}\n\n" +
				"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"terminal\",\"status\":\"completed\",\"output\":[{\"type\":\"discarded\"}]}}\n\n" +
				"data: [DONE]\n\n",
			want: `{"object":"response.compact","id":"terminal","status":"completed","output":[{"type":"compaction"}]}`,
		},
		{
			name: "empty terminal omits output usage and error",
			sse:  "data: {\"type\":\"response.completed\",\"response\":{\"output\":[],\"usage\":null,\"error\":null}}\n\n",
			want: `{"object":"response.compact","id":null,"status":"completed"}`,
		},
		{
			name: "failed terminal preserves error",
			sse:  "data: {\"type\":\"response.failed\",\"response\":{\"id\":\"failed\",\"status\":\"failed\",\"error\":{\"code\":\"upstream_error\",\"detail\":\"opaque\"}}}\n\n",
			want: `{"object":"response.compact","id":"failed","status":"failed","error":{"code":"upstream_error","detail":"opaque"}}`,
		},
		{
			name: "incomplete terminal preserves usage",
			sse:  "data: {\"type\":\"response.incomplete\",\"response\":{\"status\":\"incomplete\",\"usage\":{\"output_tokens\":7}}}\n\n",
			want: `{"object":"response.compact","id":null,"status":"incomplete","usage":{"output_tokens":7}}`,
		},
		{
			name: "missing and invalid indices use arrival order and nonobjects are ignored",
			sse: "data: {\"type\":\"response.output_item.done\",\"item\":null}\n\n" +
				"data: {\"type\":\"response.output_item.done\",\"output_index\":2,\"item\":{\"id\":\"last\"}}\n\n" +
				"data: {\"type\":\"response.output_item.done\",\"item\":{\"id\":\"first\"}}\n\n" +
				"data: {\"type\":\"response.output_item.done\",\"output_index\":-1,\"item\":{\"id\":\"tied\"}}\n\n" +
				"data: {\"type\":\"response.completed\",\"response\":{}}\n\n",
			want: `{"object":"response.compact","id":null,"status":"completed","output":[{"id":"first"},{"id":"last"},{"id":"tied"}]}`,
		},
		{
			name: "explicit null id and status are retained",
			sse: "data: {\"type\":\"response.created\",\"response\":{\"id\":\"created\"}}\n\n" +
				"data: {\"type\":\"response.completed\",\"response\":{\"id\":null,\"status\":null}}\n\n",
			want: `{"object":"response.compact","id":null,"status":null}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, split := range []bool{false, true} {
				var reader io.Reader = strings.NewReader(tt.sse)
				if split {
					reader = iotest.OneByteReader(reader)
				}
				got, err := readCompactResponse(reader)
				if err != nil {
					t.Fatalf("split=%v: %v", split, err)
				}
				decode := func(data string) any {
					t.Helper()
					decoder := json.NewDecoder(strings.NewReader(data))
					decoder.UseNumber()
					var value any
					if err := decoder.Decode(&value); err != nil {
						t.Fatal(err)
					}
					return value
				}
				if !reflect.DeepEqual(decode(string(got)), decode(tt.want)) {
					t.Fatalf("split=%v: got %s, want %s", split, got, tt.want)
				}
			}
		})
	}
}

func TestReadCompactResponseErrors(t *testing.T) {
	terminal := "data: {\"type\":\"response.completed\",\"response\":{}}\n\n"
	tests := map[string]string{
		"empty":              "",
		"no terminal":        "data: {\"type\":\"response.created\",\"response\":{\"id\":\"created\"}}\n\n",
		"done only":          "data: [DONE]\n\n",
		"malformed JSON":     "data: {broken}\n\n" + terminal,
		"truncated JSON":     "data: {\"type\":",
		"malformed trailing": terminal + "data: {broken}",
		"non SSE JSON":       `{"type":"response.completed","response":{}}`,
		"null event":         "data: null\n\n" + terminal,
		"array event":        "data: []\n\n" + terminal,
		"missing response":   "data: {\"type\":\"response.completed\"}\n\n",
		"null response":      "data: {\"type\":\"response.failed\",\"response\":null}\n\n",
		"nonobject response": "data: {\"type\":\"response.incomplete\",\"response\":[]}\n\n",
		"invalid UTF-8":      "data: {\"unknown\":\"\xff\"}\n\n" + terminal,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if got, err := readCompactResponse(strings.NewReader(input)); err == nil || got != nil {
				t.Fatalf("got %s, error %v; want nil payload and error", got, err)
			}
		})
	}

	t.Run("reader failure after terminal", func(t *testing.T) {
		failure := errors.New("read failed")
		_, err := readCompactResponse(io.MultiReader(strings.NewReader(terminal), iotest.ErrReader(failure)))
		if !errors.Is(err, failure) {
			t.Fatalf("error = %v; want %v", err, failure)
		}
	})
}

func TestReadCompactResponseLimit(t *testing.T) {
	terminal := "\n\ndata: {\"type\":\"response.completed\",\"response\":{}}\n\n"
	input := append([]byte(":"), bytes.Repeat([]byte("x"), compactResponseLimit-len(terminal)-1)...)
	input = append(input, terminal...)
	if _, err := readCompactResponse(bytes.NewReader(input)); err != nil {
		t.Fatalf("exact limit: %v", err)
	}
	reader := bytes.NewReader(append(input, 'x', 'x'))
	if got, err := readCompactResponse(reader); err == nil || got != nil {
		t.Fatalf("over limit: got %s, error %v", got, err)
	}
	if reader.Len() != 1 {
		t.Fatalf("read past limit plus one byte: %d unread", reader.Len())
	}
}
