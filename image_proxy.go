package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

func (h *proxyHandler) handleImagesGenerationFanout(w http.ResponseWriter, r *http.Request, body []byte, n int, reqID string) bool {
	if n <= 1 {
		return false
	}
	if n > 10 {
		http.Error(w, "n must be between 1 and 10", http.StatusBadRequest)
		return true
	}
	endpoint := h.imageFanoutEndpoint(r)
	oneBody := setImagesGenerationCount(body, 1)
	ctx := r.Context()
	client := &http.Client{Timeout: clientOrDefaultTimeout(r, h.cfg.requestTimeout, h.cfg.streamTimeout, oneBody)}
	type imageFanoutResult struct {
		index   int
		body    []byte
		status  int
		header  http.Header
		err     error
		created int64
		data    []any
	}
	results := make([]imageFanoutResult, n)
	parallelism := h.pool.countByType(AccountTypeCodex)
	if parallelism < 1 {
		parallelism = 1
	}
	if parallelism > n {
		parallelism = n
	}
	sem := make(chan struct{}, parallelism)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			const maxSlotAttempts = 3
			for slotAttempt := 1; slotAttempt <= maxSlotAttempts; slotAttempt++ {
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(oneBody))
				if err != nil {
					results[i].err = err
					return
				}
				req.Header = cloneHeader(r.Header)
				removeHopByHopHeaders(req.Header)
				removeConflictingProxyHeaders(req.Header)
				req.Header.Del("Accept-Encoding")
				req.Header.Del("Content-Length")
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Codex-Pool-Image-Fanout", "1")
				req.Header.Set("X-Codex-Pool-Image-Fanout-Index", strconv.Itoa(i))
				req.Header.Set("X-Codex-Pool-Image-Fanout-Attempt", strconv.Itoa(slotAttempt))
				resp, err := client.Do(req)
				if err != nil {
					results[i].err = err
				} else {
					respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 80*1024*1024))
					_ = resp.Body.Close()
					results[i].index = i
					results[i].status = resp.StatusCode
					results[i].header = resp.Header.Clone()
					results[i].body = respBody
					switch {
					case readErr != nil:
						results[i].err = readErr
					case resp.StatusCode < 200 || resp.StatusCode >= 300:
						results[i].err = fmt.Errorf("image fanout request %d failed: %s: %s", i+1, resp.Status, safeText(respBody))
					default:
						var data []any
						data, results[i].created, err = appendImagesGenerationData(nil, respBody)
						results[i].err = err
						results[i].data = data
					}
				}
				if results[i].err == nil {
					return
				}
				if results[i].status >= 400 && results[i].status < 500 {
					return
				}
				if slotAttempt < maxSlotAttempts {
					select {
					case <-ctx.Done():
						results[i].err = ctx.Err()
						return
					case <-time.After(time.Duration(slotAttempt) * 250 * time.Millisecond):
					}
				}
			}
		}()
	}
	wg.Wait()
	mergedData := []any{}
	created := time.Now().Unix()
	for _, result := range results {
		if result.err != nil {
			if h.cfg.debug.Load() {
				log.Printf("[%s] image fanout failed: %v", reqID, result.err)
			}
			http.Error(w, result.err.Error(), http.StatusBadGateway)
			return true
		}
		if result.created > 0 && (created == 0 || result.created < created) {
			created = result.created
		}
		mergedData = append(mergedData, result.data...)
	}
	out, err := json.Marshal(map[string]any{"created": created, "data": mergedData})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(out)
	return true
}

func (h *proxyHandler) imageFanoutEndpoint(r *http.Request) string {
	if h != nil && h.cfg != nil {
		if _, port, err := net.SplitHostPort(h.cfg.listenAddr); err == nil && port != "" {
			return "http://127.0.0.1:" + port + "/v1/images/generations"
		}
	}
	baseURL := h.getEffectivePublicURL(r)
	return strings.TrimRight(baseURL, "/") + "/v1/images/generations"
}
