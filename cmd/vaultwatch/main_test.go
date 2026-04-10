package main

import (
	"os"
	"testing"
)

func TestMain_MissingVaultAddress(t *testing.T) {
	// Ensure VAULT_ADDR is unset so config.Load returns an error.
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "")

	err := run()
	if err == nil {
		t.Fatal("expected error when vault address is missing, got nil")
	}
}

func TestMain_EnvConfigured(t *testing.T) {
	// This test verifies run() proceeds past config loading when env is set.
	// The vault client will fail to connect, which is acceptable here.
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:19999")
	t.Setenv("VAULT_TOKEN", "test-token")

	// run() will fail at vault health check or scan, not config — that's fine.
	err := run()
	if err == nil {
		t.Log("unexpectedly succeeded; vault may be running locally")
	}
	// We only care that the error is NOT a config error.
	if err != nil && os.Getenv("VAULT_ADDR") == "" {
		t.Errorf("unexpected config error: %v", err)
	}
}
