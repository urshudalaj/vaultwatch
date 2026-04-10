package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
)

// SecretScanner scans Vault paths for secrets and their lease information.
type SecretScanner struct {
	client *api.Client
}

// NewSecretScanner creates a new SecretScanner using the provided Vault client.
func NewSecretScanner(client *api.Client) *SecretScanner {
	return &SecretScanner{client: client}
}

// ScanPath lists all secret keys under the given path.
func (s *SecretScanner) ScanPath(ctx context.Context, path string) ([]string, error) {
	path = strings.TrimSuffix(path, "/") + "/"
	secret, err := s.client.Logical().ListWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("listing path %q: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}
	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected keys format at path %q", path)
	}
	result := make([]string, 0, len(keys))
	for _, k := range keys {
		if ks, ok := k.(string); ok {
			result = append(result, strings.TrimSuffix(path, "/")+"/"+strings.TrimSuffix(ks, "/"))
		}
	}
	return result, nil
}

// ReadLeaseInfo reads a secret at the given path and returns its lease ID and duration.
func (s *SecretScanner) ReadLeaseInfo(ctx context.Context, path string) (leaseID string, leaseDuration int, renewable bool, err error) {
	secret, err := s.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return "", 0, false, fmt.Errorf("reading secret at %q: %w", path, err)
	}
	if secret == nil {
		return "", 0, false, fmt.Errorf("no secret found at %q", path)
	}
	return secret.LeaseID, secret.LeaseDuration, secret.Renewable, nil
}
