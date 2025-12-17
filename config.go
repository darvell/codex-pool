package main

import (
	"os"

	"github.com/BurntSushi/toml"
)

// ConfigFile represents the config.toml structure.
type ConfigFile struct {
	ListenAddr     string `toml:"listen_addr"`
	PoolDir        string `toml:"pool_dir"`
	DBPath         string `toml:"db_path"`
	MaxAttempts    int    `toml:"max_attempts"`
	DisableRefresh bool   `toml:"disable_refresh"`
	Debug          bool   `toml:"debug"`
	PublicURL      string `toml:"public_url"`

	PoolUsers PoolUsersConfig `toml:"pool_users"`
}

// PoolUsersConfig is the [pool_users] section.
type PoolUsersConfig struct {
	AdminPassword string `toml:"admin_password"`
	JWTSecret     string `toml:"jwt_secret"`
	StoragePath   string `toml:"storage_path"`
}

// loadConfigFile loads config.toml if it exists.
// Returns nil if the file doesn't exist.
func loadConfigFile(path string) (*ConfigFile, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}

	var cfg ConfigFile
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// getConfigString returns the config value with priority: env var > config file > default.
func getConfigString(envKey string, configValue string, defaultValue string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	if configValue != "" {
		return configValue
	}
	return defaultValue
}

// getConfigInt returns the config value with priority: env var > config file > default.
func getConfigInt(envKey string, configValue int, defaultValue int) int {
	if v := os.Getenv(envKey); v != "" {
		if n, err := parseInt64(v); err == nil && n > 0 {
			return int(n)
		}
	}
	if configValue > 0 {
		return configValue
	}
	return defaultValue
}

// getConfigBool returns the config value with priority: env var > config file > default.
func getConfigBool(envKey string, configValue bool, defaultValue bool) bool {
	if v := os.Getenv(envKey); v != "" {
		return v == "1" || v == "true"
	}
	if configValue {
		return true
	}
	return defaultValue
}
