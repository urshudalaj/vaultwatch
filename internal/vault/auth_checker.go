package vault

import (
	"context"
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// AuthInfo holds metadata about the current Vault authentication token.
type AuthInfo struct {
	TokenID    string
	Policies   []string
	ExpireTime time.Time
	Renewable  bool
}

// AuthChecker verifies that the Vault client is authenticated and retrieves
// token metadata useful for pre-flight checks.
type AuthChecker struct {
	client *vaultapi.Client
}

// NewAuthChecker returns an AuthChecker backed by the provided Vault API client.
func NewAuthChecker(client *vaultapi.Client) *AuthChecker {
	return &AuthChecker{client: client}
}

// Check performs a token self-lookup and returns an AuthInfo struct.
// It returns an error if the lookup fails or the token has already expired.
func (a *AuthChecker) Check(ctx context.Context) (*AuthInfo, error) {
	secret, err := a.client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth check: lookup self: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("auth check: empty response from Vault")
	}

	id, _ := secret.Data["id"].(string)
	renewable, _ := secret.Data["renewable"].(bool)

	var policies []string
	if raw, ok := secret.Data["policies"].([]interface{}); ok {
		for _, p := range raw {
			if s, ok := p.(string); ok {
				policies = append(policies, s)
			}
		}
	}

	var expireTime time.Time
	if expStr, ok := secret.Data["expire_time"].(string); ok && expStr != "" {
		if t, err := time.Parse(time.RFC3339, expStr); err == nil {
			expireTime = t
		}
	}

	if !expireTime.IsZero() && time.Now().After(expireTime) {
		return nil, fmt.Errorf("auth check: token has already expired at %s", expireTime.Format(time.RFC3339))
	}

	return &AuthInfo{
		TokenID:    id,
		Policies:   policies,
		ExpireTime: expireTime,
		Renewable:  renewable,
	}, nil
}
