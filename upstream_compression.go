package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/klauspost/compress/zstd"
)

const (
	minUpstreamCompressBytes = 1024
	maxUpstreamCompressBytes = 8 << 20
	maxOpenAICompressRatio   = 100
)

type upstreamTransport struct {
	base     http.RoundTripper
	maxBody  int64
	disabled bool
}

func newUpstreamTransport(base http.RoundTripper, maxBody int64) http.RoundTripper {
	if maxBody <= 0 || maxBody > maxUpstreamCompressBytes {
		maxBody = maxUpstreamCompressBytes
	}
	return &upstreamTransport{base: base, maxBody: maxBody, disabled: getenv("PROXY_UPSTREAM_COMPRESSION", "1") == "0"}
}

func (t *upstreamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// WebSocket compression is negotiated by the WebSocket implementation.
	if req.Header.Get("Upgrade") != "" {
		return t.base.RoundTrip(req)
	}

	out := req.Clone(req.Context())
	if t.disabled {
		out.Header.Set("Accept-Encoding", "identity")
		return t.base.RoundTrip(out)
	}

	// Let net/http request gzip and remove its encoding/length headers after
	// decoding. Forwarding a client's header disables that automatic decoding.
	out.Header.Del("Accept-Encoding")
	encoding := upstreamBodyEncoding(out)
	if encoding == "" || out.Body == nil || out.GetBody == nil || out.ContentLength < minUpstreamCompressBytes || out.ContentLength > t.maxBody {
		return t.base.RoundTrip(out)
	}

	compressed, err := compressUpstreamBody(out, encoding, t.maxBody)
	if err != nil {
		out.Body.Close()
		return nil, err
	}
	if compressed == nil {
		return t.base.RoundTrip(out)
	}

	out.Body.Close()
	out.Body = io.NopCloser(bytes.NewReader(compressed))
	out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(compressed)), nil }
	out.ContentLength = int64(len(compressed))
	out.TransferEncoding = nil
	out.Header.Del("Content-Length")
	out.Header.Set("Content-Encoding", encoding)

	resp, err := t.base.RoundTrip(out)
	if err != nil || resp.StatusCode != http.StatusUnsupportedMediaType {
		return resp, err
	}

	// A 415 rejects the representation before inference. Reopen the original
	// JSON once; transport errors and other statuses keep existing retry rules.
	resp.Body.Close()
	retry := req.Clone(req.Context())
	retry.Header.Del("Accept-Encoding")
	retry.Body, err = req.GetBody()
	if err != nil {
		return nil, err
	}
	return t.base.RoundTrip(retry)
}

func upstreamBodyEncoding(req *http.Request) string {
	if req.Method != http.MethodPost || req.URL.Scheme != "https" {
		return ""
	}
	if encoding := req.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return ""
	}

	switch req.URL.Hostname() {
	case "api.anthropic.com":
		if req.URL.Path == "/v1/messages" || req.URL.Path == "/v1/messages/count_tokens" {
			return "gzip"
		}
	case "api.openai.com":
		if req.URL.Path == "/v1/responses" {
			return "zstd"
		}
	}
	return ""
}

func compressUpstreamBody(req *http.Request, encoding string, maxBody int64) ([]byte, error) {
	replay, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	defer replay.Close()

	body, err := io.ReadAll(io.LimitReader(&contextReader{ctx: req.Context(), r: replay}, maxBody+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != req.ContentLength {
		return nil, fmt.Errorf("upstream compression: replay length differs from content length")
	}

	var compressed []byte
	switch encoding {
	case "gzip":
		var buffer bytes.Buffer
		writer, err := gzip.NewWriterLevel(&buffer, gzip.BestSpeed)
		if err != nil {
			return nil, err
		}
		if _, err := writer.Write(body); err != nil {
			writer.Close()
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		compressed = buffer.Bytes()
	case "zstd":
		writer, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithWindowSize(1<<20))
		if err != nil {
			return nil, err
		}
		compressed = writer.EncodeAll(body, nil)
		writer.Close()
	}
	if len(compressed) >= len(body) || (encoding == "zstd" && len(body) > len(compressed)*maxOpenAICompressRatio) {
		return nil, nil
	}
	return compressed, nil
}
