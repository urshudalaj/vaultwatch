//go:build integration
// +build integration

// Package vault provides integration tests for the token watcher.
// Run with: go test -tags=integration ./internal/vault/...
package vault_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
)

// TestTokenWatcher_Integration tests the token watcher against a real Vault instance.
// Requires VAULT_ADDR and VAULT_TOKEN environment variables to be set.
func TestTokenWatcher_Integration(t *testing.T) {
	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		t.Skip("VAULT_ADDR and VAULT_TOKEN must be set for integration tests")
	}

	cfg := api.DefaultConfig()
	cfg.Address = addr

	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create vault client: %v", err)
	}
	client.SetToken(token)

	watcher := NewTokenWatcher(client)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	info, err := watcher.LookupSelf(ctx)
	if err != nil {
		t.Fatalf("LookupSelf failed: %v", err)
	}

	if info.TokenID == "" {
		t.Error("expected non-empty TokenID")
	}

	t.Logf("token accessor: %s", info.Accessor)
	t.Logf("token policies: %v", info.Policies)
	t.Logf("token ttl: %s", info.TTL)
	t.Logf("token expires at: %s", info.ExpireTime.Format(time.RFC3339))

	if info.Renewable {
		t.Log("token is renewable, attempting renewal...")
		if err := watcher.RenewSelf(ctx, 3600); err != nil {
			t.Errorf("RenewSelf failed: %v", err)
		} else {
			t.Log("token renewal succeeded")
		}
	} else {
		t.Log("token is not renewable, skipping renewal test")
	}
}

// TestTokenWatcher_Integration_InvalidToken verifies behaviour with a bad token.
func TestTokenWatcher_Integration_InvalidToken(t *testing.T) {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		t.Skip("VAULT_ADDR must be set for integration tests")
	}

	cfg := api.DefaultConfig()
	cfg.Address = addr

	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create vault client: %v", err)
	}
	client.SetToken("invalid-token-xyz")

	watcher := NewTokenWatcher(client)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = watcher.LookupSelf(ctx)
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
	t.Logf("received expected error: %v", err)
}
