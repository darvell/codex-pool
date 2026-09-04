package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"unicode"
)

// Keep disk offsets, not decoded values. Even tool schemas, keys and effort
// strings can occupy the entire request; only known field names are captured.
type grokJSONSpan struct {
	start int64
	end   int64
}

type grokSpoolCursor struct {
	lex *jsonLex
	r   *io.SectionReader
}

func newGrokSpoolCursor(f *os.File, size int64) *grokSpoolCursor {
	r := io.NewSectionReader(f, 0, size)
	return &grokSpoolCursor{lex: newJSONLex(r), r: r}
}

func (c *grokSpoolCursor) reset(start int64) error {
	if _, err := c.r.Seek(start, io.SeekStart); err != nil {
		return err
	}
	c.lex.r.Reset(c.r)
	return nil
}

func (c *grokSpoolCursor) pos() int64 {
	offset, _ := c.r.Seek(0, io.SeekCurrent)
	return offset - int64(c.lex.r.Buffered())
}

// Six bytes per ASCII character covers every JSON escape spelling of the
// recognized keys and image_generation. Longer keys remain opaque, not errors.
type grokNameCapture struct {
	data [6*len("external_web_access") + 2]byte
	n    int
	full bool
}

func (b *grokNameCapture) Write(p []byte) (int, error) {
	n := copy(b.data[b.n:], p)
	b.n += n
	b.full = b.full || n < len(p)
	return len(p), nil
}

func (c *grokSpoolCursor) name() (string, error) {
	var capture grokNameCapture
	var check grokJSONCheck
	if _, err := c.lex.copyString(io.MultiWriter(&capture, &check), 0); err != nil {
		return "", err
	}
	if err := check.finish(); err != nil {
		return "", err
	}
	if capture.full {
		return "", nil
	}
	var name string
	err := json.Unmarshal(capture.data[:capture.n], &name)
	return name, err
}

func (c *grokSpoolCursor) fields(visit func(string, grokJSONSpan) error) error {
	if err := c.lex.expect('{'); err != nil {
		return err
	}
	first := true
	for {
		b, err := c.lex.nonspace()
		if err != nil {
			return err
		}
		if b == '}' {
			return nil
		}
		if !first {
			if b != ',' {
				return fmt.Errorf("invalid Grok JSON object")
			}
			b, err = c.lex.nonspace()
			if err != nil {
				return err
			}
		}
		if b != '"' {
			return fmt.Errorf("invalid Grok JSON key")
		}
		key, err := c.name()
		if err != nil {
			return err
		}
		if err := c.lex.expect(':'); err != nil {
			return err
		}
		span := grokJSONSpan{start: c.pos()}
		var check grokJSONCheck
		if err := c.lex.copyValue(&check); err != nil {
			return err
		}
		if err := check.finish(); err != nil {
			return err
		}
		span.end = c.pos()
		if err := visit(key, span); err != nil {
			return err
		}
		first = false
	}
}

type grokSpoolRewrite struct {
	file       *os.File
	cursor     *grokSpoolCursor
	probe      *grokSpoolCursor
	model      string
	tools      grokJSONSpan
	format     grokJSONSpan
	effort     grokJSONSpan
	hasText    bool
	hasReason  bool
	emptyTools bool
}

func (g *grokSpoolRewrite) plan() error {
	if err := g.probe.fields(func(key string, span grokJSONSpan) error {
		switch key {
		case "tools":
			g.tools = span
		case "response_format":
			g.format = span
		case "reasoningEffort":
			g.effort = span
		case "text":
			g.hasText = true
		case "reasoning":
			g.hasReason = true
		}
		return nil
	}); err != nil {
		return err
	}
	if g.tools.end == 0 {
		return nil
	}
	if err := g.cursor.reset(g.tools.start); err != nil {
		return err
	}
	b, err := g.cursor.lex.nonspace()
	if err != nil {
		return err
	}
	if b != '[' {
		return nil
	}
	kept, err := g.array(io.Discard, grokTools)
	g.emptyTools = kept == 0
	return err
}

type grokSpoolContext uint8

const (
	grokNested grokSpoolContext = iota
	grokRoot
	grokTools
)

func (g *grokSpoolRewrite) imageTool() (bool, error) {
	if err := g.probe.reset(g.cursor.pos()); err != nil {
		return false, err
	}
	b, err := g.probe.lex.nonspace()
	if err != nil || b != '{' {
		return false, err
	}
	if err := g.probe.lex.r.UnreadByte(); err != nil {
		return false, err
	}
	var typ grokJSONSpan
	if err := g.probe.fields(func(key string, span grokJSONSpan) error {
		if key == "type" {
			typ = span
		}
		return nil
	}); err != nil || typ.end == 0 {
		return false, err
	}
	if err := g.probe.reset(typ.start); err != nil {
		return false, err
	}
	b, err = g.probe.lex.nonspace()
	if err != nil || b != '"' {
		return false, err
	}
	name, err := g.probe.name()
	return name == "image_generation", err
}

func (g *grokSpoolRewrite) copySpan(out io.Writer, span grokJSONSpan) error {
	_, err := io.Copy(out, io.NewSectionReader(g.file, span.start, span.end-span.start))
	return err
}

func (g *grokSpoolRewrite) value(out io.Writer, context grokSpoolContext) error {
	b, err := g.cursor.lex.nonspace()
	if err != nil {
		return err
	}
	switch b {
	case '{':
		return g.object(out, context)
	case '[':
		_, err = g.array(out, context)
		return err
	default:
		if err := g.cursor.lex.r.UnreadByte(); err != nil {
			return err
		}
		return g.cursor.lex.copyValue(out)
	}
}

func (g *grokSpoolRewrite) array(out io.Writer, context grokSpoolContext) (int, error) {
	if err := writeByte(out, '['); err != nil {
		return 0, err
	}
	kept := 0
	first := true
	for {
		b, err := g.cursor.lex.nonspace()
		if err != nil {
			return kept, err
		}
		if b == ']' {
			return kept, writeByte(out, ']')
		}
		if !first {
			if b != ',' {
				return kept, fmt.Errorf("invalid Grok JSON array")
			}
		} else if err := g.cursor.lex.r.UnreadByte(); err != nil {
			return kept, err
		}
		first = false
		if context == grokTools {
			drop, err := g.imageTool()
			if err != nil {
				return kept, err
			}
			if drop {
				if err := g.cursor.lex.copyValue(io.Discard); err != nil {
					return kept, err
				}
				continue
			}
		}
		if kept > 0 {
			if err := writeByte(out, ','); err != nil {
				return kept, err
			}
		}
		if err := g.value(out, grokNested); err != nil {
			return kept, err
		}
		kept++
	}
}

func (g *grokSpoolRewrite) drop(key string, context grokSpoolContext) bool {
	if key == "external_web_access" {
		return true
	}
	if context != grokRoot {
		return false
	}
	switch key {
	case "model", "metadata", "response_format", "reasoningEffort", "tools":
		return true
	case "reasoning":
		return !grokModelSupportsReasoningEffort(g.model)
	case "tool_choice", "parallel_tool_calls":
		return g.emptyTools
	}
	return false
}

func (g *grokSpoolRewrite) object(out io.Writer, context grokSpoolContext) error {
	if err := writeByte(out, '{'); err != nil {
		return err
	}
	first, wrote := true, false
	for {
		b, err := g.cursor.lex.nonspace()
		if err != nil {
			return err
		}
		if b == '}' {
			break
		}
		if !first {
			if b != ',' {
				return fmt.Errorf("invalid Grok JSON object")
			}
			b, err = g.cursor.lex.nonspace()
			if err != nil {
				return err
			}
		}
		if b != '"' {
			return fmt.Errorf("invalid Grok JSON key")
		}
		keySpan := grokJSONSpan{start: g.cursor.pos() - 1}
		key, err := g.cursor.name()
		if err != nil {
			return err
		}
		keySpan.end = g.cursor.pos()
		if err := g.cursor.lex.expect(':'); err != nil {
			return err
		}
		first = false
		if g.drop(key, context) {
			if err := g.cursor.lex.copyValue(io.Discard); err != nil {
				return err
			}
			continue
		}
		if wrote {
			if err := writeByte(out, ','); err != nil {
				return err
			}
		}
		if err := g.copySpan(out, keySpan); err != nil {
			return err
		}
		if err := writeByte(out, ':'); err != nil {
			return err
		}
		if err := g.value(out, grokNested); err != nil {
			return err
		}
		wrote = true
	}
	if context == grokRoot {
		if err := g.appendFields(out, wrote); err != nil {
			return err
		}
	}
	return writeByte(out, '}')
}

func (g *grokSpoolRewrite) appendFields(out io.Writer, wrote bool) error {
	// Only the root calls this after consuming its closing brace, so the main
	// cursor can now replay retained fields without disturbing a parent value.
	field := func(name string) error {
		if wrote {
			if err := writeByte(out, ','); err != nil {
				return err
			}
		}
		wrote = true
		_, err := io.WriteString(out, `"`+name+`":`)
		return err
	}
	if err := field("model"); err != nil {
		return err
	}
	model, err := json.Marshal(g.model)
	if err != nil {
		return err
	}
	if _, err := out.Write(model); err != nil {
		return err
	}
	if g.tools.end != 0 && !g.emptyTools {
		if err := field("tools"); err != nil {
			return err
		}
		if err := g.cursor.reset(g.tools.start); err != nil {
			return err
		}
		if err := g.value(out, grokTools); err != nil {
			return err
		}
	}
	if g.format.end != 0 && !g.hasText {
		if err := field("text"); err != nil {
			return err
		}
		if _, err := io.WriteString(out, `{"format":`); err != nil {
			return err
		}
		if err := g.cursor.reset(g.format.start); err != nil {
			return err
		}
		if err := g.value(out, grokNested); err != nil {
			return err
		}
		if err := writeByte(out, '}'); err != nil {
			return err
		}
	}
	if g.effort.end == 0 || g.hasReason || !grokModelSupportsReasoningEffort(g.model) {
		return nil
	}
	trimmed, err := g.trimEffort()
	if err != nil || trimmed.end == 0 {
		return err
	}
	if err := field("reasoning"); err != nil {
		return err
	}
	if _, err := io.WriteString(out, `{"effort":"`); err != nil {
		return err
	}
	if err := g.copySpan(out, trimmed); err != nil {
		return err
	}
	_, err = io.WriteString(out, `"}`)
	return err
}

// Find TrimSpace boundaries in the encoded string. Unicode escapes are decoded
// one rune at a time; the retained substring is copied directly from the spool.
func (g *grokSpoolRewrite) trimEffort() (grokJSONSpan, error) {
	var span grokJSONSpan
	c := g.probe
	if err := c.reset(g.effort.start); err != nil {
		return span, err
	}
	b, err := c.lex.nonspace()
	if err != nil || b != '"' {
		return span, err
	}
	for {
		start := c.pos()
		r, _, err := c.lex.r.ReadRune()
		if err != nil {
			return span, err
		}
		if r == '"' {
			return span, nil
		}
		if r == '\\' {
			b, err := c.lex.r.ReadByte()
			if err != nil {
				return span, err
			}
			switch b {
			case 'u':
				var hex [4]byte
				if _, err := io.ReadFull(c.lex.r, hex[:]); err != nil {
					return span, err
				}
				n, err := strconv.ParseUint(string(hex[:]), 16, 16)
				if err != nil {
					return span, err
				}
				r = rune(n)
			case 't':
				r = '\t'
			case 'n':
				r = '\n'
			case 'r':
				r = '\r'
			case 'f':
				r = '\f'
			case 'b':
				r = '\b'
			default:
				r = rune(b)
			}
		}
		if !unicode.IsSpace(r) {
			if span.end == 0 {
				span.start = start
			}
			span.end = c.pos()
		}
	}
}

func rewriteGrokSpool(s *streamedResponsesRequest) error {
	g := grokSpoolRewrite{
		file: s.File, model: grokCanonicalModel(s.Model),
		cursor: newGrokSpoolCursor(s.File, s.Size),
		probe:  newGrokSpoolCursor(s.File, s.Size),
	}
	if err := g.plan(); err != nil {
		if errors.Is(err, errGrokOpaqueJSON) {
			_, err = s.File.Seek(0, io.SeekStart)
		}
		return err
	}
	out, err := os.CreateTemp("", "codex-pool-grok-*.json")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			removeLexTemp(out)
		}
	}()
	writer := bufio.NewWriterSize(out, 64*1024)
	if err := g.cursor.reset(0); err != nil {
		return err
	}
	if err := g.value(writer, grokRoot); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	size, err := out.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return err
	}
	// Publish only a complete, rewound replacement. Failed rewrites leave the
	// original file and its replay metadata intact.
	s.Close()
	s.File, s.Size = out, size
	committed = true
	return nil
}
