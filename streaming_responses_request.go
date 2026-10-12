package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/klauspost/compress/zstd"
)

var (
	errResponsesSpoolTooLarge       = errors.New("decoded Responses request exceeds disk spool limit")
	errResponsesWireTooLarge        = errors.New("Responses request exceeds wire byte limit")
	errResponsesOutputTooLarge      = errors.New("transformed Responses request exceeds disk spool limit")
	errResponsesUnsupportedEncoding = errors.New("unsupported Responses request content encoding")
)

const (
	maxResponsesJSONDepth       = 256
	maxResponsesTopLevelFields  = 1024
	maxResponsesZstdWindowBytes = 64 << 20
	responsesTransformOverhead  = 1 << 20
)

func responsesOutputLimit(maxDecoded int64) int64 {
	limit := maxDecoded + responsesTransformOverhead
	if limit < maxDecoded {
		return maxDecoded
	}
	return limit
}

type spoolLimitReader struct {
	r         io.Reader
	remaining int64
	limitErr  error
}

func (r *spoolLimitReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		var one [1]byte
		n, err := r.r.Read(one[:])
		if n > 0 {
			if r.limitErr != nil {
				return 0, r.limitErr
			}
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

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.r.Read(p)
	if err == nil {
		if contextErr := r.ctx.Err(); contextErr != nil {
			return n, contextErr
		}
	}
	return n, err
}

type responsesDecodedReader struct {
	io.Reader
	close func() error
}

func (r *responsesDecodedReader) Close() error {
	if r == nil || r.close == nil {
		return nil
	}
	return r.close()
}

func decodeResponsesRequest(ctx context.Context, src io.Reader, encoding string, maxWire, maxDecoded int64) (*responsesDecodedReader, error) {
	if maxWire <= 0 {
		return nil, errResponsesWireTooLarge
	}
	wire := &spoolLimitReader{r: &contextReader{ctx: ctx, r: src}, remaining: maxWire, limitErr: errResponsesWireTooLarge}
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return &responsesDecodedReader{Reader: wire}, nil
	case "gzip":
		zr, err := gzip.NewReader(wire)
		if err != nil {
			return nil, fmt.Errorf("decode gzip Responses request: %w", err)
		}
		return &responsesDecodedReader{Reader: zr, close: zr.Close}, nil
	case "zstd":
		zr, err := zstd.NewReader(wire,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxMemory(maxResponsesZstdWindowBytes),
			zstd.WithDecoderMaxWindow(maxResponsesZstdWindowBytes),
		)
		if err != nil {
			return nil, fmt.Errorf("decode zstd Responses request: %w", err)
		}
		return &responsesDecodedReader{Reader: zr, close: func() error { zr.Close(); return nil }}, nil
	default:
		return nil, fmt.Errorf("%w: %q", errResponsesUnsupportedEncoding, encoding)
	}
}

type streamedResponsesRequest struct {
	File                    *os.File
	Size                    int64
	OriginalFile            *os.File
	OriginalSize            int64
	Model                   string
	ClientWantsNonStreaming bool
	contextMetadata         map[string]any
}

func closeAndRemoveTemp(f *os.File) {
	if f != nil {
		n := f.Name()
		_ = f.Close()
		_ = os.Remove(n)
	}
}

func (s *streamedResponsesRequest) Close() {
	if s != nil {
		closeAndRemoveTemp(s.File)
		closeAndRemoveTemp(s.OriginalFile)
		s.File = nil
		s.OriginalFile = nil
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

type responsesStreamOptions struct {
	ctx          context.Context
	rewriteModel func(string) string
	passthrough  bool
	effortLimit  string
}

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
	escaped, unicodeDigits := false, 0
	for {
		fragment, readErr := l.r.ReadSlice('"')
		closed := false
		for i, b := range fragment {
			if b == '"' && i == len(fragment)-1 && !escaped && unicodeDigits == 0 {
				closed = true
				continue
			}
			if unicodeDigits > 0 {
				if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
					return "", fmt.Errorf("invalid unicode escape in JSON string")
				}
				unicodeDigits--
				continue
			}
			if escaped {
				escaped = false
				switch b {
				case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				case 'u':
					unicodeDigits = 4
				default:
					return "", fmt.Errorf("invalid escape in JSON string")
				}
				continue
			}
			if b == '\\' {
				escaped = true
			} else if b < 0x20 {
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
		if closed {
			break
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
func (l *jsonLex) copyValue(out io.Writer) error { return l.copyValueDepth(out, 0) }
func (l *jsonLex) copyValueDepth(out io.Writer, depth int) error {
	if depth > maxResponsesJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxResponsesJSONDepth)
	}
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
			if e = l.copyValueDepth(out, depth+1); e != nil {
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
			if e = l.copyValueDepth(out, depth+1); e != nil {
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

type spoolLimitWriter struct {
	w         io.Writer
	remaining int64
}

func (w *spoolLimitWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errResponsesOutputTooLarge
	}
	n, err := w.w.Write(p)
	w.remaining -= int64(n)
	return n, err
}

func streamCodexResponsesRequest(r io.Reader, maxBytes int64, rewriteModel func(string) string) (*streamedResponsesRequest, error) {
	return streamResponsesRequest(r, maxBytes, responsesStreamOptions{rewriteModel: rewriteModel})
}

func streamResponsesRequest(r io.Reader, maxBytes int64, opts responsesStreamOptions) (_ *streamedResponsesRequest, err error) {
	out, e := os.CreateTemp("", "codex-pool-responses-*.json")
	if e != nil {
		return nil, e
	}
	res := &streamedResponsesRequest{File: out, ClientWantsNonStreaming: true}
	outputLimit := responsesOutputLimit(maxBytes)
	bw := bufio.NewWriterSize(&spoolLimitWriter{w: out, remaining: outputLimit}, 64*1024)
	defer func() {
		if err != nil {
			res.Close()
		}
	}()
	if maxBytes <= 0 {
		return nil, errResponsesSpoolTooLarge
	}
	if opts.ctx != nil {
		r = &contextReader{ctx: opts.ctx, r: r}
	}
	lex := newJSONLex(&spoolLimitReader{r: r, remaining: maxBytes, limitErr: errResponsesSpoolTooLarge})
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
	var reasoningRaw, serviceTierRaw json.RawMessage
	var suffixEffort, suffixTier string
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
		if len(seenKeys) >= maxResponsesTopLevelFields {
			return nil, fmt.Errorf("Responses request exceeds %d top-level fields", maxResponsesTopLevelFields)
		}
		seenKeys[key] = true
		first = false
		if !opts.passthrough && codexResponsesDroppedFields[key] {
			if x = lex.copyValue(io.Discard); x != nil {
				return nil, x
			}
			continue
		}
		switch key {
		case "store":
			if opts.passthrough {
				store = true
				x = writeField(key, func() error { return lex.copyValue(bw) })
			} else if x = lex.copyValue(io.Discard); x == nil && !store {
				x = writeField(key, func() error { _, z := io.WriteString(bw, "false"); return z })
				store = true
			}
		case "stream":
			var requested bool
			var raw json.RawMessage
			x = lex.decodeSmallValue(&raw, 64)
			if x == nil {
				x = json.Unmarshal(raw, &requested)
			}
			if x == nil {
				res.ClientWantsNonStreaming = !requested
				stream = true
				if opts.passthrough {
					x = writeField(key, func() error { _, z := bw.Write(raw); return z })
				} else {
					x = writeField(key, func() error { _, z := io.WriteString(bw, "true"); return z })
				}
			}
		case "instructions":
			instructions = true
			x = writeField(key, func() error { return lex.copyValue(bw) })
		case "model":
			model, z := lex.readControlString()
			x = z
			if x == nil {
				if opts.rewriteModel != nil {
					model = opts.rewriteModel(model)
				}
				if !opts.passthrough && isOpenAIModel(model) {
					base, budget, hasBudget := parseThinkingSuffix(model)
					model, suffixEffort, suffixTier = stripCodexModelSuffixes(base)
					if hasBudget {
						// Match injectThinkingBudget without decoding the prompt. Keep
						// native-context metadata and apply the admission effort cap below.
						suffixEffort = "medium"
						if budget >= 10000 {
							suffixEffort = "high"
						} else if budget <= 2000 {
							suffixEffort = "low"
						}
					}
				}
				res.Model = model
				x = writeField(key, func() error { v, _ := json.Marshal(model); _, z := bw.Write(v); return z })
			}
		case "client_metadata":
			var raw json.RawMessage
			x = lex.decodeSmallValue(&raw, contextRequestLimit)
			if x == nil {
				var value any
				x = decodeResponsesControl(raw, &value)
				if x == nil {
					if res.contextMetadata == nil {
						res.contextMetadata = make(map[string]any)
					}
					res.contextMetadata[key] = value
					x = writeField(key, func() error { _, z := bw.Write(raw); return z })
				}
			}
		case "reasoning":
			if opts.passthrough {
				x = writeField(key, func() error { return lex.copyValue(bw) })
			} else {
				x = lex.decodeSmallValue(&reasoningRaw, contextRequestLimit)
			}
		case "service_tier":
			if opts.passthrough {
				x = writeField(key, func() error { return lex.copyValue(bw) })
			} else {
				x = lex.decodeSmallValue(&serviceTierRaw, 64*1024)
			}
		case "text":
			if opts.passthrough {
				x = writeField(key, func() error { return lex.copyValue(bw) })
			} else {
				var raw json.RawMessage
				x = lex.decodeSmallValue(&raw, largeReplayBodyThreshold)
				if x == nil {
					var value any
					x = decodeResponsesControl(raw, &value)
					if text, _ := value.(map[string]any); text != nil {
						if format, _ := text["format"].(map[string]any); format != nil {
							if schema, _ := format["schema"].(map[string]any); schema != nil {
								format["schema"] = prepareCodexJSONSchema(schema)
							}
						}
					}
					if x == nil {
						var encoded []byte
						encoded, x = json.Marshal(value)
						if x == nil {
							x = writeField(key, func() error { _, z := bw.Write(encoded); return z })
						}
					}
				}
			}
		case "tools":
			x = writeField(key, func() error { return lex.copyToolsArray(bw, !opts.passthrough) })
		case "input":
			if opts.passthrough {
				x = writeField(key, func() error { return lex.copyFilteredArray(bw) })
			} else {
				x = writeField(key, func() error { return lex.copyResponsesInput(bw) })
			}
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
	if !opts.passthrough {
		if len(reasoningRaw) > 0 || suffixEffort != "" {
			var reasoningValue any
			if len(reasoningRaw) > 0 {
				if e = decodeResponsesControl(reasoningRaw, &reasoningValue); e != nil {
					return nil, e
				}
			}
			reasoning, _ := reasoningValue.(map[string]any)
			if suffixEffort != "" {
				if reasoning == nil {
					reasoning = make(map[string]any)
				}
				if _, ok := reasoning["summary"]; !ok {
					reasoning["summary"] = "auto"
				}
				reasoning["effort"] = suffixEffort
				reasoningValue = reasoning
			}
			if reasoning != nil && opts.effortLimit != "" {
				current, _ := reasoning["effort"].(string)
				ceiling, ceilingOK := codexEffortRank[strings.ToLower(strings.TrimSpace(opts.effortLimit))]
				rank, rankOK := codexEffortRank[strings.ToLower(strings.TrimSpace(current))]
				if ceilingOK && rankOK && rank > ceiling {
					reasoning["effort"] = strings.ToLower(strings.TrimSpace(opts.effortLimit))
				}
				reasoningValue = reasoning
			}
			encoded, marshalErr := json.Marshal(reasoningValue)
			if marshalErr != nil {
				return nil, marshalErr
			}
			if e = writeField("reasoning", func() error { _, z := bw.Write(encoded); return z }); e != nil {
				return nil, e
			}
			if res.contextMetadata == nil {
				res.contextMetadata = make(map[string]any)
			}
			res.contextMetadata["reasoning"] = reasoningValue
		}
		if suffixTier != "" {
			serviceTierRaw, _ = json.Marshal(suffixTier)
		}
		if len(serviceTierRaw) > 0 {
			if e = writeField("service_tier", func() error { _, z := bw.Write(serviceTierRaw); return z }); e != nil {
				return nil, e
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
	}
	if e = writeByte(bw, '}'); e != nil {
		return nil, e
	}
	if trailing, e2 := lex.nonspace(); e2 != io.EOF {
		if e2 != nil {
			return nil, e2
		}
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

func decodeResponsesControl(raw json.RawMessage, dst any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	return decoder.Decode(dst)
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

func (l *jsonLex) copyToolsArray(out io.Writer, prepareSchema bool) error {
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
		decoder := json.NewDecoder(f)
		decoder.UseNumber()
		if err = decoder.Decode(&tool); err != nil {
			removeLexTemp(f)
			return err
		}
		if typ, _ := tool["type"].(string); strings.TrimSpace(typ) == hostedMCPToolType {
			removeLexTemp(f)
			first = false
			continue
		}
		if wrote {
			if _, err = io.WriteString(out, ","); err != nil {
				removeLexTemp(f)
				return err
			}
		}
		if !prepareSchema {
			if _, err = f.Seek(0, io.SeekStart); err != nil {
				removeLexTemp(f)
				return err
			}
			_, err = io.Copy(out, f)
			removeLexTemp(f)
			if err != nil {
				return err
			}
			wrote, first = true, false
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
		removeLexTemp(f)
		if err != nil {
			return err
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
	f, typ, err := l.spoolValueType()
	typ = strings.TrimSpace(typ)
	return f, typ != hostedMCPToolType && !isHostedMCPItemType(typ), err
}

func (l *jsonLex) spoolValueType() (*os.File, string, error) {
	f, e := os.CreateTemp("", "codex-pool-value-*.json")
	if e != nil {
		return nil, "", e
	}
	fw := bufio.NewWriterSize(f, 64*1024)
	if e = l.copyValue(fw); e != nil {
		removeLexTemp(f)
		return nil, "", e
	}
	if e = fw.Flush(); e != nil {
		removeLexTemp(f)
		return nil, "", e
	}
	if _, e = f.Seek(0, 0); e != nil {
		removeLexTemp(f)
		return nil, "", e
	}
	typ, e := scanDirectType(f)
	if e != nil {
		removeLexTemp(f)
		return nil, "", e
	}
	return f, typ, nil
}
func scanDirectType(r io.Reader) (string, error) {
	l := newJSONLex(r)
	b, e := l.nonspace()
	if e != nil {
		return "", e
	}
	if b == '"' {
		// Scalar input text is unbounded; only short tool-choice names need capture.
		capture := &jsonStringCapture{limit: 64 * 1024}
		if _, e = l.copyString(capture, 0); e != nil {
			return "", e
		}
		if capture.overflow {
			return "", nil
		}
		var value string
		e = json.Unmarshal(capture.raw, &value)
		return value, e
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
