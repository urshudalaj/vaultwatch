package vault

import (
	"context"
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Client wraps the Vault API client with helper methods for VaultWatch.
type Client struct {
	api *vaultapi.Client
}

// SecretInfo holds metadata about a Vault secret or lease.
type SecretInfo struct {
	Path      string
	LeaseTTL  time.Duration
	LeaseID   string
	Renewable bool
	ExpiresAt time.Time
}

// NewClient creates a new Vault client using the provided address and token.
func NewClient(address, token string) (*Client, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = address

	api, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault api client: %w", err)
	}

	api.SetToken(token)

	return &Client{api: api}, nil
}

// IsHealthy checks whether the Vault server is reachable and unsealed.
func (c *Client) IsHealthy(ctx context.Context) error {
	health, err := c.api.Sys().HealthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("vault health check failed: %w", err)
	}
	if health.Sealed {
		return fmt.Errorf("vault is sealed")
	}
	return nil
}

// ReadSecret reads a KV secret at the given path and returns its SecretInfo.
func (c *Client) ReadSecret(ctx context.Context, path string) (*SecretInfo, error) {
	secret, err := c.api.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("reading secret at %q: %w", path, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("secret not found at path %q", path)
	}

	ttl := time.Duration(secret.LeaseDuration) * time.Second

	return &SecretInfo{
		Path:      path,
		LeaseTTL:  ttl,
		LeaseID:   secret.LeaseID,
		Renewable: secret.Renewable,
		ExpiresAt: time.Now().Add(ttl),
	}, nil
}
