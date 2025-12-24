package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strings"
)

func randomID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

func safeText(b []byte) string {
	s := string(b)
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}

// getClientIP extracts the client IP from the request, checking common proxy headers.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For first (may contain multiple IPs)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Check CF-Connecting-IP (Cloudflare)
	if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
		return cfip
	}
	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func respondJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

// readBodyForReplay reads the full body into memory so we can retry requests across accounts.
// It also returns a bounded sample for logging.
func readBodyForReplay(body io.ReadCloser, wantSample bool, sampleLimit int64) (full []byte, sample []byte, err error) {
	if body == nil {
		return nil, nil, nil
	}
	defer body.Close()
	full, err = io.ReadAll(body)
	if err != nil {
		return nil, nil, err
	}
	if wantSample && sampleLimit > 0 {
		if int64(len(full)) > sampleLimit {
			sample = full[:sampleLimit]
		} else {
			sample = full
		}
	}
	return full, sample, nil
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vv := range h {
		cpy := make([]string, len(vv))
		copy(cpy, vv)
		out[k] = cpy
	}
	return out
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		dst.Del(k)
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// removeHopByHopHeaders strips headers that must not be forwarded by proxies.
func removeHopByHopHeaders(h http.Header) {
	// Strip any headers listed in the Connection header first.
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(textproto.CanonicalMIMEHeaderKey(f))
			}
		}
	}

	// Standard hop-by-hop headers.
	for _, k := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		h.Del(k)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
