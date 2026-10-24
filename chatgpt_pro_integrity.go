package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

//go:embed chatgpt_pro_integrity.js
var chatGPTIntegrityJS string

var chatGPTBrowserSlot = make(chan struct{}, 1)

type chatGPTIntegrity struct {
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
	key    string
}

func newChatGPTIntegrity(ctx context.Context) (*chatGPTIntegrity, error) {
	select {
	case chatGPTBrowserSlot <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	options := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	if executable := os.Getenv("CHATGPT_BROWSER_PATH"); executable != "" {
		options = append(options, chromedp.ExecPath(executable))
	}
	allocator, stopAllocator := chromedp.NewExecAllocator(ctx, options...)
	browser, stopBrowser := chromedp.NewContext(allocator)
	i := &chatGPTIntegrity{ctx: browser}
	i.cancel = func() { stopBrowser(); stopAllocator(); <-chatGPTBrowserSlot }
	// The first Run owns the browser lifetime; cancelling a startup child kills it.
	startup := time.AfterFunc(30*time.Second, stopBrowser)
	defer startup.Stop()
	// Loopback provides Web Crypto without contacting a provider. Block all
	// subsequent network requests before evaluating any challenge code.
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html><html><head></head><body></body></html>"))
	}))
	defer page.Close()
	if err := chromedp.Run(browser, chromedp.Navigate(page.URL), network.Enable(), network.SetBlockedURLs([]string{"*"}), chromedp.Evaluate(chatGPTIntegrityJS, nil)); err != nil {
		i.close()
		return nil, errors.New("ChatGPT integrity browser unavailable")
	}
	return i, nil
}

func (i *chatGPTIntegrity) close() {
	i.once.Do(i.cancel)
}

func (i *chatGPTIntegrity) prepare() (string, error) {
	if err := chromedp.Run(i.ctx, chromedp.Evaluate("poolIntegrity.prepare()", &i.key)); err != nil {
		return "", errors.New("ChatGPT integrity preparation failed")
	}
	return i.key, nil
}

func (i *chatGPTIntegrity) complete(requirements map[string]any) (map[string]string, error) {
	args, err := json.Marshal([]any{requirements, i.key})
	if err != nil {
		return nil, err
	}
	var result struct {
		Proof     string `json:"proof"`
		Turnstile string `json:"turnstile"`
	}
	expression := "poolIntegrity.complete(..." + string(args) + ")"
	if err := chromedp.Run(i.ctx, chromedp.Evaluate(expression, &result, func(p *runtime.EvaluateParams) *runtime.EvaluateParams { return p.WithAwaitPromise(true) })); err != nil {
		return nil, errors.New("ChatGPT integrity challenge failed")
	}
	return map[string]string{"proofofwork": result.Proof, "turnstile": result.Turnstile}, nil
}
