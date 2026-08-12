package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

var errResponsesSpoolTooLarge = errors.New("Responses request exceeds disk spool limit")

type spoolLimitReader struct {
	r         io.Reader
	remaining int64
}

func (r *spoolLimitReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		var one [1]byte
		n, err := r.r.Read(one[:])
		if n > 0 {
			return 0, errResponsesSpoolTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.r.Read(p)
	r.remaining -= int64(n)
	return n, err
}

type streamedResponsesRequest struct {
	File                    *os.File
	Size                    int64
	Model                   string
	ClientWantsNonStreaming bool
}

func (s *streamedResponsesRequest) Close() {
	if s != nil && s.File != nil {
		n := s.File.Name()
		_ = s.File.Close()
		_ = os.Remove(n)
	}
}

var codexResponsesDroppedFields = map[string]bool{
	"temperature": true, "top_p": true, "presence_penalty": true, "frequency_penalty": true,
	"max_tokens": true, "max_completion_tokens": true, "max_output_tokens": true, "seed": true,
	"logprobs": true, "top_logprobs": true, "metadata": true, "prompt_cache_scope": true,
}

// jsonLex copies JSON lexically. In particular it never turns payload strings
// into Go strings: a multi-gigabyte prompt uses the fixed bufio buffer.
type jsonLex struct{ r *bufio.Reader }

func newJSONLex(r io.Reader) *jsonLex { return &jsonLex{r: bufio.NewReaderSize(r, 64*1024)} }
func (l *jsonLex) nonspace() (byte, error) {
	for {
		b, e := l.r.ReadByte()
		if e != nil {
			return 0, e
		}
		if b != ' ' && b != '\n' && b != '\r' && b != '\t' {
			return b, nil
		}
	}
}
func writeByte(w io.Writer, b byte) error {
	if bw, ok := w.(interface{ WriteByte(byte) error }); ok {
		return bw.WriteByte(b)
	}
	var one [1]byte
	one[0] = b
	_, err := w.Write(one[:])
	return err
}
func (l *jsonLex) expect(want byte) error {
	b, e := l.nonspace()
	if e != nil {
		return e
	}
	if b != want {
		return fmt.Errorf("invalid JSON: expected %q, got %q", want, b)
	}
	return nil
}

func (l *jsonLex) copyString(out io.Writer, captureLimit int) (string, error) {
	if err := writeByte(out, '"'); err != nil {
		return "", err
	}
	var raw []byte
	if captureLimit > 0 {
		raw = append(raw, '"')
	}
	trailingSlashes := 0
	for {
		fragment, readErr := l.r.ReadSlice('"')
		if len(fragment) > 0 {
			content := fragment
			if fragment[len(fragment)-1] == '"' {
				content = fragment[:len(fragment)-1]
			}
			for _, b := range content {
				if b < 0x20 {
					return "", fmt.Errorf("invalid control byte in JSON string")
				}
			}
			if _, err := out.Write(fragment); err != nil {
				return "", err
			}
			if captureLimit > 0 {
				if len(raw)+len(fragment) > captureLimit {
					return "", fmt.Errorf("JSON control string exceeds %d bytes", captureLimit)
				}
				raw = append(raw, fragment...)
			}
			if fragment[len(fragment)-1] == '"' {
				slashes := 0
				for i := len(content) - 1; i >= 0 && content[i] == '\\'; i-- {
					slashes++
				}
				if len(content) == slashes {
					slashes += trailingSlashes
				}
				if slashes%2 == 0 {
					break
				}
				trailingSlashes = 0
				continue
			}
			trailingSlashes = 0
			for i := len(content) - 1; i >= 0 && content[i] == '\\'; i-- {
				trailingSlashes++
			}
		}
		if readErr != nil && readErr != bufio.ErrBufferFull {
			return "", readErr
		}
	}
	if captureLimit <= 0 {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	return value, nil
}
func (l *jsonLex) copyValue(out io.Writer) error {
	b, e := l.nonspace()
	if e != nil {
		return e
	}
	switch b {
	case '"':
		_, e = l.copyString(out, 0)
		return e
	case '{':
		if e = writeByte(out, b); e != nil {
			return e
		}
		first := true
		for {
			n, e := l.nonspace()
			if e != nil {
				return e
			}
			if n == '}' {
				return writeByte(out, n)
			}
			if !first {
				if n != ',' {
					return fmt.Errorf("invalid JSON object")
				}
				if e = writeByte(out, ','); e != nil {
					return e
				}
				n, e = l.nonspace()
				if e != nil {
					return e
				}
			}
			if n != '"' {
				return fmt.Errorf("invalid JSON object key")
			}
			if _, e = l.copyString(out, 0); e != nil {
				return e
			}
			if e = l.expect(':'); e != nil {
				return e
			}
			if _, e = io.WriteString(out, ":"); e != nil {
				return e
			}
			if e = l.copyValue(out); e != nil {
				return e
			}
			first = false
		}
	case '[':
		if e = writeByte(out, b); e != nil {
			return e
		}
		first := true
		for {
			n, e := l.nonspace()
			if e != nil {
				return e
			}
			if n == ']' {
				return writeByte(out, n)
			}
			if !first {
				if n != ',' {
					return fmt.Errorf("invalid JSON array")
				}
				if e = writeByte(out, ','); e != nil {
					return e
				}
				n, e = l.nonspace()
				if e != nil {
					return e
				}
			}
			if e = l.r.UnreadByte(); e != nil {
				return e
			}
			if e = l.copyValue(out); e != nil {
				return e
			}
			first = false
		}
	case '}', ']', ',', ':':
		return fmt.Errorf("invalid JSON value")
	default:
		token := []byte{b}
		for {
			n, readErr := l.r.ReadByte()
			if readErr != nil && readErr != io.EOF {
				return readErr
			}
			if readErr == nil && n != ',' && n != '}' && n != ']' && n != ' ' && n != '\n' && n != '\r' && n != '\t' {
				if len(token) >= 256 {
					return fmt.Errorf("JSON primitive exceeds 256 bytes")
				}
				token = append(token, n)
				continue
			}
			if readErr == nil && (n == ',' || n == '}' || n == ']') {
				if e = l.r.UnreadByte(); e != nil {
					return e
				}
			}
			if !json.Valid(token) {
				return fmt.Errorf("invalid JSON primitive %q", token)
			}
			_, e = out.Write(token)
			return e
		}
	}
}

func (l *jsonLex) readControlString() (string, error) {
	b, e := l.nonspace()
	if e != nil {
		return "", e
	}
	if b != '"' {
		return "", fmt.Errorf("expected JSON string")
	}
	return l.copyString(io.Discard, 64*1024)
}

func streamCodexResponsesRequest(r io.Reader, maxBytes int64, rewriteModel func(string) string) (_ *streamedResponsesRequest, err error) {
	out, e := os.CreateTemp("", "codex-pool-responses-*.json")
	if e != nil {
		return nil, e
	}
	res := &streamedResponsesRequest{File: out, ClientWantsNonStreaming: true}
	bw := bufio.NewWriterSize(out, 64*1024)
	defer func() {
		if err != nil {
			res.Close()
		}
	}()
	if maxBytes <= 0 {
		return nil, errResponsesSpoolTooLarge
	}
	lex := newJSONLex(&spoolLimitReader{r: r, remaining: maxBytes})
	if e = lex.expect('{'); e != nil {
		return nil, e
	}
	if e = writeByte(bw, '{'); e != nil {
		return nil, e
	}
	wrote := false
	seenKeys := make(map[string]bool)
	instructions := false
	store := false
	stream := false
	writeField := func(key string, fn func() error) error {
		if wrote {
			if _, x := io.WriteString(bw, ","); x != nil {
				return x
			}
		}
		kb, _ := json.Marshal(key)
		if _, x := bw.Write(kb); x != nil {
			return x
		}
		if _, x := io.WriteString(bw, ":"); x != nil {
			return x
		}
		if x := fn(); x != nil {
			return x
		}
		wrote = true
		return nil
	}
	first := true
	for {
		b, x := lex.nonspace()
		if x != nil {
			return nil, x
		}
		if b == '}' {
			break
		}
		if !first {
			if b != ',' {
				return nil, fmt.Errorf("invalid top-level JSON object")
			}
			b, x = lex.nonspace()
			if x != nil {
				return nil, x
			}
		}
		if b != '"' {
			return nil, fmt.Errorf("invalid top-level key")
		}
		key, x := lex.copyString(io.Discard, 64*1024)
		if x != nil {
			return nil, x
		}
		if x = lex.expect(':'); x != nil {
			return nil, x
		}
		if seenKeys[key] {
			return nil, fmt.Errorf("duplicate top-level field %q", key)
		}
		seenKeys[key] = true
		first = false
		if codexResponsesDroppedFields[key] {
			if x = lex.copyValue(io.Discard); x != nil {
				return nil, x
			}
			continue
		}
		switch key {
		case "store":
			if x = lex.copyValue(io.Discard); x == nil && !store {
				x = writeField(key, func() error { _, z := io.WriteString(bw, "false"); return z })
				store = true
			}
		case "stream":
			var requested bool
			x = lex.decodeSmallValue(&requested, 64)
			if x == nil {
				res.ClientWantsNonStreaming = !requested
				if !stream {
					x = writeField(key, func() error { _, z := io.WriteString(bw, "true"); return z })
					stream = true
				}
			}
		case "instructions":
			instructions = true
			x = writeField(key, func() error { return lex.copyValue(bw) })
		case "model":
			model, z := lex.readControlString()
			x = z
			if x == nil {
				if rewriteModel != nil {
					model = rewriteModel(model)
				}
				res.Model = model
				x = writeField(key, func() error { v, _ := json.Marshal(model); _, z := bw.Write(v); return z })
			}
		case "tools":
			x = writeField(key, func() error { return lex.copyToolsArray(bw) })
		case "input":
			x = writeField(key, func() error { return lex.copyResponsesInput(bw) })
		case "tool_choice":
			f, keep, z := lex.spoolValueAndCheckMCP()
			x = z
			if x == nil && keep {
				defer removeLexTemp(f)
				x = writeField(key, func() error {
					_, z = f.Seek(0, 0)
					if z != nil {
						return z
					}
					_, z = io.Copy(bw, f)
					return z
				})
			} else if f != nil {
				removeLexTemp(f)
			}
		default:
			x = writeField(key, func() error { return lex.copyValue(bw) })
		}
		if x != nil {
			return nil, x
		}
	}
	if !instructions {
		if e = writeField("instructions", func() error { _, z := io.WriteString(bw, `""`); return z }); e != nil {
			return nil, e
		}
	}
	if !store {
		if e = writeField("store", func() error { _, z := io.WriteString(bw, "false"); return z }); e != nil {
			return nil, e
		}
	}
	if !stream {
		if e = writeField("stream", func() error { _, z := io.WriteString(bw, "true"); return z }); e != nil {
			return nil, e
		}
	}
	if e = writeByte(bw, '}'); e != nil {
		return nil, e
	}
	if trailing, e2 := lex.nonspace(); e2 != io.EOF {
		return nil, fmt.Errorf("trailing JSON data starting with %q", trailing)
	}
	if e = bw.Flush(); e != nil {
		return nil, e
	}
	if res.Size, e = out.Seek(0, io.SeekEnd); e != nil {
		return nil, e
	}
	if _, e = out.Seek(0, 0); e != nil {
		return nil, e
	}
	return res, nil
}

func (l *jsonLex) decodeSmallValue(dst any, limit int64) error {
	f, err := os.CreateTemp("", "codex-pool-control-*.json")
	if err != nil {
		return err
	}
	defer removeLexTemp(f)
	if err = l.copyValue(f); err != nil {
		return err
	}
	if size, _ := f.Seek(0, io.SeekEnd); size > limit {
		return fmt.Errorf("JSON control value exceeds %d bytes", limit)
	}
	if _, err = f.Seek(0, 0); err != nil {
		return err
	}
	return json.NewDecoder(f).Decode(dst)
}

func (l *jsonLex) copyToolsArray(out io.Writer) error {
	b, err := l.nonspace()
	if err != nil {
		return err
	}
	if b != '[' {
		return fmt.Errorf("tools must be an array")
	}
	if err = writeByte(out, '['); err != nil {
		return err
	}
	wrote, first := false, true
	for {
		b, err = l.nonspace()
		if err != nil {
			return err
		}
		if b == ']' {
			return writeByte(out, ']')
		}
		if !first {
			if b != ',' {
				return fmt.Errorf("invalid tools array")
			}
			b, err = l.nonspace()
			if err != nil {
				return err
			}
		}
		if err = l.r.UnreadByte(); err != nil {
			return err
		}
		f, _, err := l.spoolValueAndCheckMCP()
		if err != nil {
			return err
		}
		size, _ := f.Seek(0, io.SeekEnd)
		if size > largeReplayBodyThreshold {
			removeLexTemp(f)
			return fmt.Errorf("individual tool definition exceeds %d bytes", largeReplayBodyThreshold)
		}
		if _, err = f.Seek(0, 0); err != nil {
			removeLexTemp(f)
			return err
		}
		var tool map[string]any
		if err = json.NewDecoder(f).Decode(&tool); err != nil {
			removeLexTemp(f)
			return err
		}
		removeLexTemp(f)
		if typ, _ := tool["type"].(string); strings.TrimSpace(typ) == hostedMCPToolType {
			first = false
			continue
		}
		if params, _ := tool["parameters"].(map[string]any); params != nil {
			tool["parameters"] = prepareCodexJSONSchema(params)
		}
		if fn, _ := tool["function"].(map[string]any); fn != nil {
			if params, _ := fn["parameters"].(map[string]any); params != nil {
				fn["parameters"] = prepareCodexJSONSchema(params)
			}
		}
		encoded, err := json.Marshal(tool)
		if err != nil {
			return err
		}
		if wrote {
			if _, err = io.WriteString(out, ","); err != nil {
				return err
			}
		}
		if _, err = out.Write(encoded); err != nil {
			return err
		}
		wrote, first = true, false
	}
}

func (l *jsonLex) copyResponsesInput(out io.Writer) error {
	b, e := l.nonspace()
	if e != nil {
		return e
	}
	if b == '"' {
		if _, e = io.WriteString(out, `[{"type":"message","role":"user","content":[{"type":"input_text","text":`); e != nil {
			return e
		}
		if _, e = l.copyString(out, 0); e != nil {
			return e
		}
		_, e = io.WriteString(out, `}]}]`)
		return e
	}
	if b != '[' {
		if e = l.r.UnreadByte(); e != nil {
			return e
		}
		return l.copyValue(out)
	}
	if e = writeByte(out, '['); e != nil {
		return e
	}
	return l.copyFilteredArrayAfterOpen(out)
}
func (l *jsonLex) copyFilteredArray(out io.Writer) error {
	b, e := l.nonspace()
	if e != nil {
		return e
	}
	if b != '[' {
		if e = l.r.UnreadByte(); e != nil {
			return e
		}
		return l.copyValue(out)
	}
	if e = writeByte(out, '['); e != nil {
		return e
	}
	return l.copyFilteredArrayAfterOpen(out)
}
func (l *jsonLex) copyFilteredArrayAfterOpen(out io.Writer) error {
	wrote := false
	first := true
	for {
		b, e := l.nonspace()
		if e != nil {
			return e
		}
		if b == ']' {
			return writeByte(out, ']')
		}
		if !first {
			if b != ',' {
				return fmt.Errorf("invalid filtered array")
			}
			b, e = l.nonspace()
			if e != nil {
				return e
			}
		}
		if e = l.r.UnreadByte(); e != nil {
			return e
		}
		f, keep, e := l.spoolValueAndCheckMCP()
		if e != nil {
			return e
		}
		if keep {
			if wrote {
				if _, e = io.WriteString(out, ","); e != nil {
					removeLexTemp(f)
					return e
				}
			}
			if _, e = f.Seek(0, 0); e != nil {
				removeLexTemp(f)
				return e
			}
			_, e = io.Copy(out, f)
			removeLexTemp(f)
			if e != nil {
				return e
			}
			wrote = true
		} else {
			removeLexTemp(f)
		}
		first = false
	}
}
func (l *jsonLex) spoolValueAndCheckMCP() (*os.File, bool, error) {
	f, e := os.CreateTemp("", "codex-pool-value-*.json")
	if e != nil {
		return nil, false, e
	}
	fw := bufio.NewWriterSize(f, 64*1024)
	if e = l.copyValue(fw); e != nil {
		removeLexTemp(f)
		return nil, false, e
	}
	if e = fw.Flush(); e != nil {
		removeLexTemp(f)
		return nil, false, e
	}
	if _, e = f.Seek(0, 0); e != nil {
		removeLexTemp(f)
		return nil, false, e
	}
	typ, e := scanDirectType(f)
	if e != nil {
		removeLexTemp(f)
		return nil, false, e
	}
	typ = strings.TrimSpace(typ)
	return f, typ != hostedMCPToolType && !isHostedMCPItemType(typ), nil
}
func scanDirectType(r io.Reader) (string, error) {
	l := newJSONLex(r)
	b, e := l.nonspace()
	if e != nil {
		return "", e
	}
	if b == '"' {
		return l.copyString(io.Discard, 64*1024)
	}
	if b != '{' {
		return "", nil
	}
	first := true
	typ := ""
	for {
		b, e = l.nonspace()
		if e != nil {
			return "", e
		}
		if b == '}' {
			return typ, nil
		}
		if !first {
			if b != ',' {
				return "", fmt.Errorf("invalid object")
			}
			b, e = l.nonspace()
			if e != nil {
				return "", e
			}
		}
		if b != '"' {
			return "", fmt.Errorf("invalid key")
		}
		key, e := l.copyString(io.Discard, 64*1024)
		if e != nil {
			return "", e
		}
		if e = l.expect(':'); e != nil {
			return "", e
		}
		if key == "type" {
			if typ != "" {
				return "", fmt.Errorf("duplicate type field")
			}
			typ, e = l.readControlString()
			if e != nil {
				return "", e
			}
			first = false
			continue
		}
		if e = l.copyValue(io.Discard); e != nil {
			return "", e
		}
		first = false
	}
}
func removeLexTemp(f *os.File) {
	if f != nil {
		n := f.Name()
		_ = f.Close()
		_ = os.Remove(n)
	}
}
