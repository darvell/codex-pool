package main

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
)

var errInvalidRedirectFrame = errors.New("invalid response.create frame")

type modelRedirects struct {
	mu      sync.RWMutex
	origins map[string]string
}

func newModelRedirects(origins map[string]string) *modelRedirects {
	redirects := &modelRedirects{}
	redirects.reload(origins)
	return redirects
}

func (r *modelRedirects) reload(origins map[string]string) {
	next := make(map[string]string, len(origins))
	for origin, model := range origins {
		origin = strings.TrimSpace(origin)
		model = strings.TrimSpace(model)
		if origin != "" && model != "" {
			next[origin] = model
		}
	}
	r.mu.Lock()
	r.origins = next
	r.mu.Unlock()
}

func (r *modelRedirects) modelFor(origin string) string {
	if r == nil {
		return ""
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.origins[origin]
}

func redirectWSModel(data []byte, model string) ([]byte, error) {
	if model == "" || !isCodexResponseCreate(data) {
		return data, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	value, err := json.Marshal(model)
	if err != nil {
		return nil, err
	}
	if _, ok := obj["model"]; ok {
		obj["model"] = value
	}
	if raw, ok := obj["response"]; ok {
		var response map[string]json.RawMessage
		if err := json.Unmarshal(raw, &response); err != nil || response == nil {
			return nil, errInvalidRedirectFrame
		}
		response["model"] = value
		obj["response"], err = json.Marshal(response)
		if err != nil {
			return nil, err
		}
	} else {
		obj["model"] = value
	}
	return json.Marshal(obj)
}
