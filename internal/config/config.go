package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the application configuration for vaultwatch.
type Config struct {
	Vault   VaultConfig   `yaml:"vault"`
	Alerts  AlertsConfig  `yaml:"alerts"`
	Monitor MonitorConfig `yaml:"monitor"`
}

// VaultConfig contains Vault connection settings.
type VaultConfig struct {
	Address   string `yaml:"address"`
	Token     string `yaml:"token"`
	Namespace string `yaml:"namespace"`
}

// AlertsConfig defines alerting thresholds and channels.
type AlertsConfig struct {
	// WarnBefore is the duration before expiry to start warning.
	WarnBefore time.Duration `yaml:"warn_before"`
	SlackWebhook string       `yaml:"slack_webhook"`
	Email        string       `yaml:"email"`
}

// MonitorConfig controls polling behaviour.
type MonitorConfig struct {
	Interval time.Duration `yaml:"interval"`
	Paths    []string      `yaml:"paths"`
}

// Load reads and parses a YAML config file from the given path.
// Environment variables VAULT_ADDR and VAULT_TOKEN override file values.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Allow environment variable overrides.
	if addr := os.Getenv("VAULT_ADDR"); addr != "" {
		cfg.Vault.Address = addr
	}
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		cfg.Vault.Token = token
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Vault.Address == "" {
		return fmt.Errorf("vault.address is required")
	}
	if c.Vault.Token == "" {
		return fmt.Errorf("vault.token is required (or set VAULT_TOKEN)")
	}
	if c.Monitor.Interval <= 0 {
		c.Monitor.Interval = 5 * time.Minute
	}
	if c.Alerts.WarnBefore <= 0 {
		c.Alerts.WarnBefore = 24 * time.Hour
	}
	return nil
}
