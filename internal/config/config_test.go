package config

import (
	"os"
	"testing"
	"time"
)

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "vaultwatch-*.yaml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

func TestLoad_ValidConfig(t *testing.T) {
	path := writeTempConfig(t, `
vault:
  address: "http://127.0.0.1:8200"
  token: "root"
  namespace: "admin"
monitor:
  interval: 10m
  paths:
    - secret/myapp
alerts:
  warn_before: 48h
  slack_webhook: "https://hooks.slack.com/xxx"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Vault.Address != "http://127.0.0.1:8200" {
		t.Errorf("expected vault address, got %q", cfg.Vault.Address)
	}
	if cfg.Monitor.Interval != 10*time.Minute {
		t.Errorf("expected 10m interval, got %v", cfg.Monitor.Interval)
	}
	if cfg.Alerts.WarnBefore != 48*time.Hour {
		t.Errorf("expected 48h warn_before, got %v", cfg.Alerts.WarnBefore)
	}
}

func TestLoad_DefaultsApplied(t *testing.T) {
	path := writeTempConfig(t, `
vault:
  address: "http://127.0.0.1:8200"
  token: "root"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Monitor.Interval != 5*time.Minute {
		t.Errorf("expected default 5m interval, got %v", cfg.Monitor.Interval)
	}
	if cfg.Alerts.WarnBefore != 24*time.Hour {
		t.Errorf("expected default 24h warn_before, got %v", cfg.Alerts.WarnBefore)
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	path := writeTempConfig(t, `
vault:
  address: "http://original:8200"
  token: "original-token"
`)

	t.Setenv("VAULT_ADDR", "http://override:8200")
	t.Setenv("VAULT_TOKEN", "override-token")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Vault.Address != "http://override:8200" {
		t.Errorf("expected overridden address, got %q", cfg.Vault.Address)
	}
	if cfg.Vault.Token != "override-token" {
		t.Errorf("expected overridden token, got %q", cfg.Vault.Token)
	}
}

func TestLoad_MissingAddress(t *testing.T) {
	path := writeTempConfig(t, `
vault:
  token: "root"
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing vault.address")
	}
}
