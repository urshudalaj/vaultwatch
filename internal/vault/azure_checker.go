package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// AzureRoleInfo holds configuration details for a Vault Azure secrets role.
type AzureRoleInfo struct {
	ApplicationObjectID string   `json:"application_object_id"`
	AzureRoles          []string `json:"azure_roles"`
	TTL                 string   `json:"ttl"`
	MaxTTL              string   `json:"max_ttl"`
}

// AzureChecker retrieves Azure secrets engine role configuration from Vault.
type AzureChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewAzureChecker returns a new AzureChecker using the provided HTTP client.
func NewAzureChecker(client *http.Client, baseURL, token string) *AzureChecker {
	return &AzureChecker{client: client, base: baseURL, token: token}
}

// GetAzureRole fetches the role configuration for the given mount and role name.
func (a *AzureChecker) GetAzureRole(mount, role string) (*AzureRoleInfo, error) {
	if mount == "" || role == "" {
		return nil, fmt.Errorf("azure: mount and role must not be empty")
	}
	url := fmt.Sprintf("%s/v1/%s/roles/%s", a.base, mount, role)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", a.token)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure: unexpected status %d for role %s/%s", resp.StatusCode, mount, role)
	}

	var envelope struct {
		Data AzureRoleInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("azure: decode response: %w", err)
	}
	return &envelope.Data, nil
}
