package vault

import (
	"context"
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// TokenInfo holds metadata about the current Vault token.
type TokenInfo struct {
	Accessor   string
	ExpireTime time.Time
	TTL        time.Duration
	Renewable  bool
	Policies   []string
}

// TokenWatcher inspects the current Vault token and reports its status.
type TokenWatcher struct {
	client *vaultapi.Client
}

// NewTokenWatcher creates a TokenWatcher using the provided Vault API client.
func NewTokenWatcher(client *vaultapi.Client) *TokenWatcher {
	return &TokenWatcher{client: client}
}

// LookupSelf queries Vault for the current token's metadata.
func (tw *TokenWatcher) LookupSelf(ctx context.Context) (*TokenInfo, error) {
	secret, err := tw.client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("token lookup failed: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("empty token data returned from vault")
	}

	info := &TokenInfo{}

	if v, ok := secret.Data["accessor"].(string); ok {
		info.Accessor = v
	}
	if v, ok := secret.Data["renewable"].(bool); ok {
		info.Renewable = v
	}
	if ttlRaw, ok := secret.Data["ttl"]; ok {
		if ttlFloat, ok := ttlRaw.(float64); ok {
			info.TTL = time.Duration(ttlFloat) * time.Second
			info.ExpireTime = time.Now().Add(info.TTL)
		}
	}
	if policies, ok := secret.Data["policies"].([]interface{}); ok {
		for _, p := range policies {
			if ps, ok := p.(string); ok {
				info.Policies = append(info.Policies, ps)
			}
		}
	}

	return info, nil
}

// RenewSelf attempts to renew the current token with the given increment.
func (tw *TokenWatcher) RenewSelf(ctx context.Context, increment int) error {
	_, err := tw.client.Auth().Token().RenewSelfWithContext(ctx, increment)
	if err != nil {
		return fmt.Errorf("token renewal failed: %w", err)
	}
	return nil
}
