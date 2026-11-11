package main

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUpstreamGzipBunFetch(t *testing.T) {
	bun, err := exec.LookPath("bun")
	if err != nil {
		t.Skip("Bun is not installed")
	}
	t.Setenv("POOL_JWT_SECRET", "bun-compression-secret")
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", http2), func(t *testing.T) {
			finish := make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(finish) }) }
			defer release()
			_, transport := compressionHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				if r.Header.Get("Accept-Encoding") != "gzip" {
					t.Errorf("upstream accept encoding = %q", r.Header.Get("Accept-Encoding"))
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Content-Encoding", "gzip")
				zw := gzip.NewWriter(gzipFragments{w})
				io.WriteString(zw, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"BUN_FIRST_TOKEN\"}\n\n")
				zw.Flush()
				w.(http.Flusher).Flush()
				select {
				case <-finish:
				case <-r.Context().Done():
					return
				}
				io.WriteString(zw, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_bun\",\"status\":\"completed\"}}\n\n")
				zw.Close()
			}), http2)
			h := preflightHandler(newUpstreamTransport(transport, 1<<20))
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/finish" {
					release()
					w.WriteHeader(http.StatusNoContent)
					return
				}
				h.ServeHTTP(w, r)
			}))
			defer proxy.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			script := `
const [base, token] = process.argv.slice(1);
const response = await fetch(base + "/v1/responses", {
  method: "POST",
  headers: {authorization: "Bearer " + token, "content-type": "application/json"},
  body: JSON.stringify({model: "gpt-5.6", stream: true, input: "hello"}),
});
if (!response.ok) throw new Error("HTTP " + response.status + ": " + await response.text());
if (response.headers.get("content-encoding")) throw new Error("Compressed headers leaked to Bun");
const reader = response.body.getReader();
const decoder = new TextDecoder();
let text = "", first = false;
while (true) {
  const {value, done} = await reader.read();
  if (done) break;
  text += decoder.decode(value, {stream: true});
  if (!first && text.includes("BUN_FIRST_TOKEN")) {
    first = true;
    await fetch(base + "/finish");
  }
}
if (!first || !text.includes("response.completed")) throw new Error("Incomplete SSE: " + text);
console.log("BUN_INCREMENTAL_GZIP_OK " + Bun.version);
`
			cmd := exec.CommandContext(ctx, bun, "-e", script, proxy.URL, generateClaudePoolToken("bun-compression-secret", "bun-user"))
			output, err := cmd.CombinedOutput()
			release()
			if err != nil || !strings.Contains(string(output), "BUN_INCREMENTAL_GZIP_OK") {
				t.Fatalf("Bun streaming failed: %v\n%s", err, output)
			}
			t.Log(strings.TrimSpace(string(output)))
		})
	}
}
