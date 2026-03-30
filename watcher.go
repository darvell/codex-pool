package main

import (
	"log"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// poolWatcher watches the pool directory and config file for changes,
// triggering automatic reloads without requiring a server restart.
type poolWatcher struct {
	watcher    *fsnotify.Watcher
	poolDir    string
	configPath string
	handler    *proxyHandler

	mu           sync.Mutex
	debouncePool *time.Timer
	debounceCfg  *time.Timer
}

const watcherDebounce = 500 * time.Millisecond

func newPoolWatcher(poolDir, configPath string, handler *proxyHandler) (*poolWatcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	pw := &poolWatcher{
		watcher:    w,
		poolDir:    poolDir,
		configPath: configPath,
		handler:    handler,
	}

	// Watch pool directory for credential file changes.
	if poolDir != "" {
		if err := w.Add(poolDir); err != nil {
			w.Close()
			return nil, err
		}
		log.Printf("watching pool directory: %s", poolDir)
	}

	// Watch config file for setting changes.
	if configPath != "" {
		if err := w.Add(configPath); err != nil {
			// Non-fatal — config may not exist yet.
			log.Printf("warning: cannot watch config file %s: %v", configPath, err)
		} else {
			log.Printf("watching config file: %s", configPath)
		}
	}

	go pw.loop()
	return pw, nil
}

func (pw *poolWatcher) loop() {
	for {
		select {
		case event, ok := <-pw.watcher.Events:
			if !ok {
				return
			}
			// Ignore chmod-only events.
			if event.Op == fsnotify.Chmod {
				continue
			}
			pw.handleEvent(event)

		case err, ok := <-pw.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("watcher error: %v", err)
		}
	}
}

func (pw *poolWatcher) handleEvent(event fsnotify.Event) {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	// Is this the config file?
	if pw.configPath != "" && event.Name == pw.configPath {
		if pw.debounceCfg != nil {
			pw.debounceCfg.Stop()
		}
		pw.debounceCfg = time.AfterFunc(watcherDebounce, pw.reloadConfig)
		return
	}

	// Otherwise it's a pool directory change.
	if pw.debouncePool != nil {
		pw.debouncePool.Stop()
	}
	pw.debouncePool = time.AfterFunc(watcherDebounce, pw.reloadPool)
}

func (pw *poolWatcher) reloadPool() {
	log.Printf("pool directory changed, reloading accounts")
	pw.handler.reloadAccounts()
	counts := map[AccountType]int{}
	pw.handler.pool.mu.RLock()
	for _, a := range pw.handler.pool.accounts {
		counts[a.Type]++
	}
	pw.handler.pool.mu.RUnlock()
	log.Printf("hot-reload complete: codex=%d claude=%d gemini=%d kimi=%d minimax=%d zai=%d",
		counts[AccountTypeCodex], counts[AccountTypeClaude], counts[AccountTypeGemini],
		counts[AccountTypeKimi], counts[AccountTypeMinimax], counts[AccountTypeZAI])
}

func (pw *poolWatcher) reloadConfig() {
	log.Printf("config file changed, reloading non-sensitive settings")
	cfg, err := loadConfigFile(pw.configPath)
	if err != nil {
		log.Printf("config reload failed: %v", err)
		return
	}
	if cfg == nil {
		return
	}

	// Only reload safe, non-sensitive fields.
	newDebug := getConfigBool("DEBUG", cfg.Debug, false)
	pw.handler.cfg.debug.Store(newDebug)
	pw.handler.cfg.tierThreshold = getConfigFloat64("TIER_THRESHOLD", cfg.TierThreshold, 0.15)
	pw.handler.pool.mu.Lock()
	pw.handler.pool.debug = newDebug
	pw.handler.pool.mu.Unlock()

	// Reload model aliases.
	if pw.handler.aliases != nil && cfg.ModelAliases != nil {
		pw.handler.aliases.reload(cfg.ModelAliases)
		log.Printf("reloaded %d model aliases", len(cfg.ModelAliases))
	}

	log.Printf("config hot-reload complete (debug=%v, tier_threshold=%.2f)",
		newDebug, pw.handler.cfg.tierThreshold)
}

func (pw *poolWatcher) close() {
	pw.watcher.Close()
}
