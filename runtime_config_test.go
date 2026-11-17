package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigCredentialSources(t *testing.T) {
	t.Setenv("POOL_JWT_SECRET", "")
	t.Setenv("POOL_USERS_PATH", "")
	t.Setenv("PUBLIC_URL", "")
	cfg := &config{file: &ConfigFile{PoolUsers: PoolUsersConfig{JWTSecret: "file-secret", StoragePath: "file-users.json"}, PublicURL: "https://file.example.test/"}}
	if cfg.poolJWTSecret() != "file-secret" || cfg.poolUsersPath() != "file-users.json" || cfg.publicURL() != "https://file.example.test" {
		t.Fatal("loaded configuration was not used")
	}
	t.Setenv("POOL_JWT_SECRET", "environment-secret")
	t.Setenv("POOL_USERS_PATH", "environment-users.json")
	t.Setenv("PUBLIC_URL", "https://environment.example.test/")
	if cfg.poolJWTSecret() != "environment-secret" || cfg.poolUsersPath() != "environment-users.json" || cfg.publicURL() != "https://environment.example.test" {
		t.Fatal("environment did not override loaded configuration")
	}
	var defaults *config
	if defaults.poolJWTSecret() != "environment-secret" || defaults.publicURL() != "https://environment.example.test" {
		t.Fatal("environment defaults require a startup side effect")
	}
}

func TestConfigReloadPoolSettings(t *testing.T) {
	t.Setenv("DEBUG", "")
	t.Setenv("TIER_THRESHOLD", "")
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("debug = true\ntier_threshold = 0.37\n"), 0600); err != nil {
		t.Fatal(err)
	}
	highScore := &Account{ID: "high-score", Type: AccountTypeClaude, PlanType: "max", Usage: UsageSnapshot{SecondaryUsedPercent: 0.4}}
	belowThreshold := &Account{ID: "below-threshold", Type: AccountTypeClaude, PlanType: "max", Usage: UsageSnapshot{SecondaryUsedPercent: 0.3}, Penalty: 0.5, LastPenalty: time.Now()}
	pool := newPoolState([]*Account{highScore, belowThreshold}, false)
	if selected := pool.candidate("", nil, AccountTypeClaude, "", ""); selected != highScore {
		t.Fatalf("initial selection = %v, want high-score", selected)
	}
	h := &proxyHandler{cfg: &config{tierThreshold: 0.5}, pool: pool}
	watcher := &poolWatcher{configPath: path, handler: h}
	watcher.reloadConfig()
	if !h.cfg.debug.Load() {
		t.Fatal("debug setting was not reloaded")
	}
	if selected := pool.candidate("", nil, AccountTypeClaude, "", ""); selected != belowThreshold {
		t.Fatalf("selection after threshold reload = %v, want below-threshold", selected)
	}
}
