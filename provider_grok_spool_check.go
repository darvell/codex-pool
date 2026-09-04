package main

import (
	"errors"
	"strconv"
)

var errGrokOpaqueJSON = errors.New("Grok JSON cannot be decoded by the buffered sanitizer")

// encoding/json's scanner rejects nesting beyond this depth. Each checked
// field value already sits inside the request's root object.
const grokJSONMaxDepth = 10000

// jsonLex checks structure and primitive syntax, but deliberately copies string
// escapes verbatim. Preserve the old sanitizer's no-op for invalid escapes and
// numbers that encoding/json cannot represent as float64, without decoding a
// payload string. Primitive storage matches jsonLex's existing 256-byte bound.
type grokJSONCheck struct {
	quoted  bool
	escape  bool
	hex     int
	invalid bool
	depth   int
	number  [256]byte
	n       int
}

func (c *grokJSONCheck) Write(p []byte) (int, error) {
	for _, b := range p {
		if c.quoted {
			switch {
			case c.hex > 0:
				if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F') {
					c.invalid = true
				}
				c.hex--
			case c.escape:
				c.escape = false
				switch b {
				case 'u':
					c.hex = 4
				case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				default:
					c.invalid = true
				}
			case b == '\\':
				c.escape = true
			case b == '"':
				c.quoted = false
			case b < 0x20:
				c.invalid = true
			}
			continue
		}
		if b == '"' {
			c.flushNumber()
			c.quoted = true
			continue
		}
		if b >= '0' && b <= '9' || b == '-' || b == '+' || b == '.' || b == 'e' || b == 'E' {
			// The e in true/false is not a number start.
			if c.n == 0 && !(b >= '0' && b <= '9' || b == '-') {
				continue
			}
			if c.n == len(c.number) {
				c.invalid = true
				continue
			}
			c.number[c.n] = b
			c.n++
			continue
		}
		c.flushNumber()
		switch b {
		case '{', '[':
			c.depth++
			if c.depth >= grokJSONMaxDepth {
				c.invalid = true
			}
		case '}', ']':
			c.depth--
		}
	}
	return len(p), nil
}

func (c *grokJSONCheck) flushNumber() {
	if c.n == 0 {
		return
	}
	if _, err := strconv.ParseFloat(string(c.number[:c.n]), 64); err != nil {
		c.invalid = true
	}
	c.n = 0
}

func (c *grokJSONCheck) finish() error {
	c.flushNumber()
	if c.invalid || c.quoted || c.escape || c.hex != 0 {
		return errGrokOpaqueJSON
	}
	return nil
}
