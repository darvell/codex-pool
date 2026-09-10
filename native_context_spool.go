package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// A JSON escape can use six bytes per token character. The envelope's base64
// encoding uses another 4/3, plus a small allowance for authentication overhead.
const contextSpoolTokenLimit = contextEnvelopeLimit*8 + 1024

type contextSpoolKey struct{}

type jsonStringCapture struct {
	raw      []byte
	limit    int
	overflow bool
}

func (c *jsonStringCapture) Write(p []byte) (int, error) {
	n := min(len(p), c.limit-len(c.raw))
	c.raw = append(c.raw, p[:n]...)
	c.overflow = c.overflow || n < len(p)
	return len(p), nil
}

func (c *jsonStringCapture) hasPrefix(prefix string) bool {
	var value string
	if !c.overflow {
		return json.Unmarshal(c.raw, &value) == nil && strings.HasPrefix(value, prefix)
	}
	// Close the captured prefix at a complete escape boundary. The capture has
	// room for six bytes per prefix character, so trimming cannot hide a match.
	for trim := 0; trim <= 6 && trim < len(c.raw); trim++ {
		encoded := append(append([]byte(nil), c.raw[:len(c.raw)-trim]...), '"')
		if json.Unmarshal(encoded, &value) == nil {
			return strings.HasPrefix(value, prefix)
		}
	}
	return false
}

// prepareSpool never writes the original file. Even a late invalid envelope
// leaves the caller's body intact and all speculative output is removed.
func (s *nativeContext) prepareSpool(scope, clientIP string, spooled *streamedResponsesRequest) error {
	if spooled == nil || spooled.File == nil {
		return errContextInvalid
	}
	out, err := os.CreateTemp("", "codex-pool-context-*.json")
	if err != nil {
		return err
	}
	defer func() { removeLexTemp(out) }()
	writer := bufio.NewWriterSize(out, 64*1024)
	lex := newJSONLex(io.NewSectionReader(spooled.File, 0, spooled.Size))
	rewrite := &contextSpoolRewrite{service: s, scope: scope, clientIP: clientIP, metadata: spooled.contextMetadata}
	if err := lex.contextFields(writer, func(key string) error {
		if key == "input" {
			return lex.contextArray(writer, func() error { return rewrite.item(lex, writer) })
		}
		return lex.copyValue(writer)
	}); err != nil {
		return err
	}
	if _, err := lex.nonspace(); err != io.EOF {
		return errContextInvalid
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if !rewrite.changed {
		_, err := spooled.File.Seek(0, io.SeekStart)
		return err
	}
	size, err := out.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return err
	}
	old := spooled.File
	spooled.File, spooled.Size = out, size
	out = nil
	removeLexTemp(old)
	return nil
}

type contextSpoolRewrite struct {
	service       *nativeContext
	scope         string
	clientIP      string
	metadata      map[string]any
	changed       bool
	expandedBytes int
}

func (r *contextSpoolRewrite) item(lex *jsonLex, out io.Writer) error {
	file, typ, err := lex.spoolValueType()
	if err != nil {
		return err
	}
	defer removeLexTemp(file)
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if typ != "function_call_output" {
		_, err := io.Copy(out, file)
		return err
	}
	item := newJSONLex(file)
	return item.contextFields(out, func(key string) error {
		if key == "output" {
			return item.contextArray(out, func() error { return r.part(item, out) })
		}
		return item.copyValue(out)
	})
}

func (r *contextSpoolRewrite) part(lex *jsonLex, out io.Writer) error {
	file, typ, err := lex.spoolValueType()
	if err != nil {
		return err
	}
	defer removeLexTemp(file)
	own := false
	if typ == "encrypted_content" {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return err
		}
		probe := newJSONLex(file)
		err = probe.contextFields(io.Discard, func(key string) error {
			if key != "encrypted_content" {
				return probe.copyValue(io.Discard)
			}
			b, err := probe.nonspace()
			if err != nil {
				return err
			}
			own = false
			if b != '"' {
				if err := probe.r.UnreadByte(); err != nil {
					return err
				}
				return probe.copyValue(io.Discard)
			}
			capture := &jsonStringCapture{limit: 6*len(contextEnvelopePrefix) + 2}
			if _, err := probe.copyString(capture, 0); err != nil {
				return err
			}
			own = capture.hasPrefix(contextEnvelopePrefix)
			return nil
		})
		if err != nil {
			return err
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if !own {
		_, err := io.Copy(out, file)
		return err
	}

	// Decode only our token, never sibling text, images, or extension fields.
	var token string
	candidate := newJSONLex(file)
	if err := candidate.contextFields(io.Discard, func(key string) error {
		if key == "encrypted_content" {
			return candidate.decodeSmallValue(&token, contextSpoolTokenLimit)
		}
		return candidate.copyValue(io.Discard)
	}); err != nil {
		return err
	}
	obj := make(map[string]any, len(r.metadata)+1)
	for key, value := range r.metadata {
		obj[key] = value
	}
	obj["input"] = []any{map[string]any{"type": "function_call_output", "output": []any{map[string]any{"type": "encrypted_content", "encrypted_content": token}}}}
	changed, err := r.service.expand(r.scope, r.clientIP, obj)
	if err != nil {
		return err
	}
	if !changed {
		return errContextResult
	}
	parts := obj["input"].([]any)[0].(map[string]any)["output"].([]any)
	if len(parts) == 0 {
		return errContextResult
	}
	for i, part := range parts {
		if i > 0 {
			if err := writeByte(out, ','); err != nil {
				return err
			}
		}
		encoded, err := json.Marshal(part)
		if err != nil {
			return err
		}
		// Calls to expand are per token; retain one budget across the whole spool.
		if len(encoded) > contextExpansionLimit-r.expandedBytes {
			return errContextResult
		}
		r.expandedBytes += len(encoded)
		if _, err := out.Write(encoded); err != nil {
			return err
		}
	}
	r.changed = true
	return nil
}

func (l *jsonLex) contextFields(out io.Writer, field func(string) error) error {
	if err := l.expect('{'); err != nil {
		return err
	}
	if err := writeByte(out, '{'); err != nil {
		return err
	}
	first := true
	for {
		b, err := l.nonspace()
		if err != nil {
			return err
		}
		if b == '}' {
			return writeByte(out, '}')
		}
		if !first {
			if b != ',' {
				return fmt.Errorf("invalid context JSON object")
			}
			if err := writeByte(out, ','); err != nil {
				return err
			}
			b, err = l.nonspace()
			if err != nil {
				return err
			}
		}
		if b != '"' {
			return fmt.Errorf("invalid context JSON key")
		}
		capture := &jsonStringCapture{limit: 6*len("encrypted_content") + 2}
		if _, err := l.copyString(io.MultiWriter(out, capture), 0); err != nil {
			return err
		}
		var key string
		if !capture.overflow {
			if err := json.Unmarshal(capture.raw, &key); err != nil {
				return err
			}
		}
		if err := l.expect(':'); err != nil {
			return err
		}
		if err := writeByte(out, ':'); err != nil {
			return err
		}
		if err := field(key); err != nil {
			return err
		}
		first = false
	}
}

func (l *jsonLex) contextArray(out io.Writer, item func() error) error {
	b, err := l.nonspace()
	if err != nil {
		return err
	}
	if b != '[' {
		if err := l.r.UnreadByte(); err != nil {
			return err
		}
		return l.copyValue(out)
	}
	if err := writeByte(out, '['); err != nil {
		return err
	}
	first := true
	for {
		b, err := l.nonspace()
		if err != nil {
			return err
		}
		if b == ']' {
			return writeByte(out, ']')
		}
		if !first {
			if b != ',' {
				return fmt.Errorf("invalid context JSON array")
			}
			if err := writeByte(out, ','); err != nil {
				return err
			}
			if _, err := l.nonspace(); err != nil {
				return err
			}
		}
		if err := l.r.UnreadByte(); err != nil {
			return err
		}
		if err := item(); err != nil {
			return err
		}
		first = false
	}
}
