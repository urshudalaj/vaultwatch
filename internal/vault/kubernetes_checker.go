package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// KubernetesRole holds configuration details for a Kubernetes auth role.
type KubernetesRole struct {
	BoundServiceAccountNames      []string `json:"bound_service_account_names"`
	BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces"`
	TTL                           string   `json:"ttl"`
	MaxTTL                        string   `json:"max_ttl"`
	TokenPolicies                 []string `json:"token_policies"`
}

// KubernetesChecker reads Kubernetes auth roles from Vault.
type KubernetesChecker struct {
	client *Client
}

// NewKubernetesChecker creates a new KubernetesChecker.
func NewKubernetesChecker(client *Client) *KubernetesChecker {
	return &KubernetesChecker{client: client}
}

// GetRole fetches the Kubernetes auth role from the given mount and role name.
func (k *KubernetesChecker) GetRole(mount, role string) (*KubernetesRole, error) {
	if mount == "" || role == "" {
		return nil, fmt.Errorf("kubernetes checker: mount and role must not be empty")
	}

	path := fmt.Sprintf("/v1/auth/%s/role/%s", mount, role)
	req, err := http.NewRequest(http.MethodGet, k.client.Address+path, nil)
	if err != nil {
		return nil, fmt.Errorf("kubernetes checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", k.client.Token)

	resp, err := k.client.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kubernetes checker: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kubernetes checker: unexpected status %d for role %s/%s", resp.StatusCode, mount, role)
	}

	var envelope struct {
		Data KubernetesRole `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("kubernetes checker: decode response: %w", err)
	}

	return &envelope.Data, nil
}
