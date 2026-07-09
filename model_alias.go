package main

import (
	"log"
	"strings"
	"sync"
)

// defaultModelAliases are always registered unless overridden by config.toml
// [model_aliases]. Keys are matched case-insensitively at resolve time.
var defaultModelAliases = map[string]string{
	// GPT-5.6 series short name → Sol (default variant).
	"gpt-5.6": "gpt-5.6-sol",
}

// modelAliases manages model name aliases. Thread-safe for hot-reload.
type modelAliases struct {
	mu      sync.RWMutex
	aliases map[string]string // short name -> full upstream model name
}

func mergeModelAliases(cfg map[string]string) map[string]string {
	out := make(map[string]string, len(defaultModelAliases)+len(cfg))
	for k, v := range defaultModelAliases {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	for k, v := range cfg {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			continue
		}
		// Config overrides built-ins.
		out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return out
}

func newModelAliases(cfg map[string]string) *modelAliases {
	return &modelAliases{aliases: mergeModelAliases(cfg)}
}

// resolve returns the upstream model name for a given alias, or the
// original name if no alias is defined. The second return value indicates
// whether an alias was applied.
func (m *modelAliases) resolve(model string) (string, bool) {
	if m == nil || model == "" {
		return model, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if target, ok := m.aliases[strings.ToLower(model)]; ok {
		return target, true
	}
	return model, false
}

// reload replaces the alias map (used by hot-reload). Always re-applies
// built-in defaults, then overlays cfg (which may be nil).
func (m *modelAliases) reload(cfg map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.aliases = mergeModelAliases(cfg)
}

// applyModelAlias resolves the model alias and rewrites the body if needed.
// Uses the existing rewriteModelInBody from main.go.
func applyModelAlias(aliases *modelAliases, model string, body []byte, debug bool, reqID string) (string, []byte) {
	resolved, aliased := aliases.resolve(model)
	if !aliased {
		return model, body
	}
	if rewritten := rewriteModelInBody(body, resolved); rewritten != nil {
		if debug {
			log.Printf("[%s] model alias: %s -> %s", reqID, model, resolved)
		}
		return resolved, rewritten
	}
	// Body rewrite failed, but still use the resolved name for routing.
	if debug {
		log.Printf("[%s] model alias: %s -> %s (body rewrite failed, routing only)", reqID, model, resolved)
	}
	return resolved, body
}
