package vault

import (
	"context"
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"
)

// PolicyInfo holds metadata about a Vault policy.
type PolicyInfo struct {
	Name  string
	Rules string
}

// PolicyChecker retrieves policy information from Vault.
type PolicyChecker struct {
	client *vaultapi.Client
}

// NewPolicyChecker creates a PolicyChecker using the provided Vault API client.
func NewPolicyChecker(client *vaultapi.Client) *PolicyChecker {
	return &PolicyChecker{client: client}
}

// GetPolicy fetches the rules for the named ACL policy.
func (p *PolicyChecker) GetPolicy(ctx context.Context, name string) (*PolicyInfo, error) {
	if name == "" {
		return nil, fmt.Errorf("policy name must not be empty")
	}

	secret, err := p.client.Logical().ReadWithContext(ctx, "sys/policy/"+name)
	if err != nil {
		return nil, fmt.Errorf("reading policy %q: %w", name, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("policy %q not found", name)
	}

	rules, _ := secret.Data["rules"].(string)
	return &PolicyInfo{
		Name:  name,
		Rules: rules,
	}, nil
}

// ListPolicies returns the names of all ACL policies in Vault.
func (p *PolicyChecker) ListPolicies(ctx context.Context) ([]string, error) {
	secret, err := p.client.Logical().ListWithContext(ctx, "sys/policy")
	if err != nil {
		return nil, fmt.Errorf("listing policies: %w", err)
	}
	if secret == nil {
		return nil, fmt.Errorf("no policies returned from vault")
	}

	keys, _ := secret.Data["keys"].([]interface{})
	names := make([]string, 0, len(keys))
	for _, k := range keys {
		if s, ok := k.(string); ok {
			names = append(names, s)
		}
	}
	return names, nil
}
