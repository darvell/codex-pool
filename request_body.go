package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
)

func readBodyPrefix(body io.Reader, limit int64) ([]byte, error) {
	var buf bytes.Buffer
	_, err := io.CopyN(&buf, body, limit)
	if err == io.EOF {
		err = nil
	}
	return buf.Bytes(), err
}

type prefixReadCloser struct {
	r io.Reader
	c io.Closer
}

func (p *prefixReadCloser) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

func (p *prefixReadCloser) Close() error {
	return p.c.Close()
}

func replaceJSONStringToken(prefix []byte, start, end int, value string) ([]byte, int, error) {
	if start < 0 || end < start || end > len(prefix) {
		return nil, 0, fmt.Errorf("invalid JSON string bounds")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, 0, err
	}
	out := make([]byte, 0, len(prefix)-(end-start)+len(encoded))
	out = append(out, prefix[:start]...)
	out = append(out, encoded...)
	out = append(out, prefix[end:]...)
	return out, len(encoded) - (end - start), nil
}

func findTopLevelJSONStringField(blob []byte, field string) (value string, valueStart int, valueEnd int, ok bool) {
	i := skipJSONWhitespace(blob, 0)
	if i >= len(blob) || blob[i] != '{' {
		return "", 0, 0, false
	}
	i++
	for {
		i = skipJSONWhitespace(blob, i)
		if i >= len(blob) {
			return "", 0, 0, false
		}
		if blob[i] == '}' {
			return "", 0, 0, false
		}
		if blob[i] == ',' {
			i++
			continue
		}
		key, _, _, next, ok := readJSONStringToken(blob, i)
		if !ok {
			return "", 0, 0, false
		}
		i = skipJSONWhitespace(blob, next)
		if i >= len(blob) || blob[i] != ':' {
			return "", 0, 0, false
		}
		i = skipJSONWhitespace(blob, i+1)
		if key == field {
			value, valueStart, valueEnd, _, ok = readJSONStringToken(blob, i)
			return value, valueStart, valueEnd, ok
		}
		next, ok = skipJSONValue(blob, i)
		if !ok {
			return "", 0, 0, false
		}
		i = next
	}
}

func skipJSONWhitespace(blob []byte, i int) int {
	for i < len(blob) {
		switch blob[i] {
		case ' ', '\n', '\r', '\t':
			i++
		default:
			return i
		}
	}
	return i
}

func readJSONStringToken(blob []byte, i int) (value string, start int, end int, next int, ok bool) {
	if i >= len(blob) || blob[i] != '"' {
		return "", 0, 0, 0, false
	}
	start = i
	escaped := false
	for i++; i < len(blob); i++ {
		if escaped {
			escaped = false
			continue
		}
		switch blob[i] {
		case '\\':
			escaped = true
		case '"':
			end = i + 1
			if err := json.Unmarshal(blob[start:end], &value); err != nil {
				return "", 0, 0, 0, false
			}
			return value, start, end, end, true
		}
	}
	return "", 0, 0, 0, false
}

func skipJSONValue(blob []byte, i int) (int, bool) {
	i = skipJSONWhitespace(blob, i)
	if i >= len(blob) {
		return 0, false
	}
	if blob[i] == '"' {
		_, _, _, next, ok := readJSONStringToken(blob, i)
		return next, ok
	}
	if blob[i] != '{' && blob[i] != '[' {
		for i < len(blob) {
			switch blob[i] {
			case ',', '}', ']':
				return i, true
			case ' ', '\n', '\r', '\t':
				return skipJSONWhitespace(blob, i), true
			default:
				i++
			}
		}
		return 0, false
	}

	stack := []byte{blob[i]}
	escaped := false
	inString := false
	for i++; i < len(blob); i++ {
		c := blob[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch c {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			stack = append(stack, c)
		case '}', ']':
			if len(stack) == 0 {
				return 0, false
			}
			open := stack[len(stack)-1]
			if (open == '{' && c != '}') || (open == '[' && c != ']') {
				return 0, false
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return i + 1, true
			}
		}
	}
	return 0, false
}

func rewriteModelInBody(body []byte, newModel string) []byte {
	if len(body) == 0 {
		return nil
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil
	}
	if _, ok := obj["model"]; !ok {
		return nil
	}
	obj["model"] = newModel
	rewritten, err := json.Marshal(obj)
	if err != nil {
		return nil
	}
	return rewritten
}

func extractConversationIDFromSSE(sample []byte) string {
	for _, line := range bytes.Split(sample, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			line = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		}
		if len(line) == 0 || bytes.Equal(line, []byte("[DONE]")) {
			continue
		}
		if id := extractConversationIDFromJSON(line); id != "" {
			return id
		}
	}
	return ""
}

func bodyForInspection(r *http.Request, body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	enc := ""
	if r != nil {
		enc = strings.ToLower(r.Header.Get("Content-Encoding"))
	}
	looksGzip := len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b
	if strings.Contains(enc, "gzip") || looksGzip {
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body
		}
		defer gr.Close()
		decoded, err := io.ReadAll(io.LimitReader(gr, 512*1024))
		if err != nil || len(decoded) == 0 {
			return body
		}
		return decoded
	}
	return body
}

func (h *proxyHandler) responsesWireLimit() int64 {
	if h != nil && h.cfg != nil && h.cfg.maxWireBodyBytes > 0 {
		return h.cfg.maxWireBodyBytes
	}
	if h != nil && h.cfg != nil {
		return h.cfg.maxSpoolBodyBytes
	}
	return 0
}

func validateResponsesSpoolSize(spooled *streamedResponsesRequest, maxDecoded int64) error {
	if spooled == nil || spooled.File == nil {
		return errors.New("Responses replay spool unavailable")
	}
	info, err := spooled.File.Stat()
	if err != nil {
		return err
	}
	spooled.Size = info.Size()
	if spooled.Size > responsesOutputLimit(maxDecoded) {
		return fmt.Errorf("%w (%d > %d)", errResponsesOutputTooLarge, spooled.Size, responsesOutputLimit(maxDecoded))
	}
	return nil
}

var errResponsesBodyTimeout = errors.New("Responses request body upload timed out")

func responsesSpoolError(w http.ResponseWriter, prefix string, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, errResponsesUnsupportedEncoding):
		status = http.StatusUnsupportedMediaType
	case errors.Is(err, errResponsesWireTooLarge), errors.Is(err, errResponsesSpoolTooLarge), errors.Is(err, errResponsesOutputTooLarge):
		status = http.StatusRequestEntityTooLarge
	case errors.Is(err, errResponsesBodyTimeout):
		status = http.StatusRequestTimeout
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return
	}
	http.Error(w, prefix+err.Error(), status)
}

func (h *proxyHandler) spoolHTTPResponsesRequest(w http.ResponseWriter, r *http.Request, opts responsesStreamOptions) (_ *streamedResponsesRequest, err error) {
	wireLimit := h.responsesWireLimit()
	if r.ContentLength > wireLimit && wireLimit > 0 {
		return nil, fmt.Errorf("%w (%d > %d)", errResponsesWireTooLarge, r.ContentLength, wireLimit)
	}
	uploadCtx := r.Context()
	cancelUpload := func() {}
	if h.cfg.responsesBodyTimeout > 0 {
		uploadCtx, cancelUpload = context.WithTimeout(r.Context(), h.cfg.responsesBodyTimeout)
	}
	controller := http.NewResponseController(w)
	if deadline, ok := uploadCtx.Deadline(); ok && w != nil {
		_ = controller.SetReadDeadline(deadline)
	}
	originalBody := r.Body
	closed := make(chan struct{})
	stopClose := context.AfterFunc(uploadCtx, func() {
		defer close(closed)
		// net/http request Body.Close can wait behind an in-progress socket read.
		// Expire the connection read first so cancellation releases admission now,
		// rather than waiting for the independent upload deadline.
		if w != nil {
			_ = controller.SetReadDeadline(time.Now())
		}
		_ = originalBody.Close()
	})
	finishUpload := sync.OnceFunc(func() {
		if !stopClose() {
			<-closed
		}
		cancelUpload()
		if w != nil {
			_ = controller.SetReadDeadline(time.Time{})
		}
	})
	defer finishUpload()

	decoded, err := decodeResponsesRequest(uploadCtx, r.Body, r.Header.Get("Content-Encoding"), wireLimit)
	if err != nil {
		if errors.Is(uploadCtx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w after %s", errResponsesBodyTimeout, h.cfg.responsesBodyTimeout)
		}
		if contextErr := r.Context().Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, err
	}
	defer decoded.Close()

	raw, err := os.CreateTemp("", "codex-pool-responses-decoded-*.json")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			closeAndRemoveTemp(raw)
		}
	}()
	limited := &spoolLimitReader{r: decoded, remaining: h.cfg.maxSpoolBodyBytes, limitErr: errResponsesSpoolTooLarge}
	if _, err = io.Copy(raw, limited); err != nil {
		if errors.Is(err, zstd.ErrWindowSizeExceeded) || errors.Is(err, zstd.ErrDecoderSizeExceeded) {
			return nil, fmt.Errorf("%w: zstd resource window exceeds %d bytes", errResponsesSpoolTooLarge, maxResponsesZstdWindowBytes)
		}
		if errors.Is(uploadCtx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w after %s", errResponsesBodyTimeout, h.cfg.responsesBodyTimeout)
		}
		if contextErr := r.Context().Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, err
	}
	finishUpload()
	originalSize, err := raw.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	// Small bodies must enter the established buffered pipeline before any
	// disk-only control limits or Codex-specific parsing/routing. Compression
	// must not reject buffered provider routes or valid small BYOK requests.
	if originalSize <= h.cfg.maxInMemoryBodyBytes {
		return &streamedResponsesRequest{OriginalFile: raw, OriginalSize: originalSize}, nil
	}
	opts.ctx = r.Context()
	if _, err = raw.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	spooled, err := streamResponsesRequest(raw, h.cfg.maxSpoolBodyBytes, opts)
	if err != nil {
		return nil, err
	}
	spooled.OriginalFile = raw
	if spooled.OriginalSize, err = raw.Seek(0, io.SeekEnd); err != nil {
		spooled.Close()
		return nil, err
	}
	if _, err = raw.Seek(0, io.SeekStart); err != nil {
		spooled.Close()
		return nil, err
	}
	return spooled, nil
}

// decodeRequestBody makes compressed JSON routable and rewritable. We must not
// forward encoded bytes after a model-based provider override: the selected
// provider needs the rewritten JSON, not the original Codex wire payload.
func decodeRequestBody(contentEncoding string, body []byte, maxBytes int64) ([]byte, bool, error) {
	encoding := strings.ToLower(strings.TrimSpace(contentEncoding))
	if len(body) == 0 || encoding == "" || encoding == "identity" {
		return body, false, nil
	}
	if maxBytes <= 0 {
		maxBytes = 16 << 20
	}

	var reader io.ReadCloser
	switch encoding {
	case "gzip":
		gzipReader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false, fmt.Errorf("decode gzip request body: %w", err)
		}
		reader = gzipReader
	case "zstd":
		zstdReader, err := zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false, fmt.Errorf("decode zstd request body: %w", err)
		}
		reader = zstdReader.IOReadCloser()
	default:
		return body, false, nil
	}
	defer reader.Close()

	decoded, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("decode %s request body: %w", encoding, err)
	}
	if int64(len(decoded)) > maxBytes {
		return nil, false, fmt.Errorf("decoded request body exceeds %d byte limit", maxBytes)
	}
	return decoded, true, nil
}
