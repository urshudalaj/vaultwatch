package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// AWSRoleInfo holds configuration details for an AWS secrets engine role.
type AWSRoleInfo struct {
	Mount          string
	Role           string
	CredentialType string `json:"credential_type"`
	DefaultTTL     int    `json:"default_ttl"`
	MaxTTL         int    `json:"max_ttl"`
}

// AWSChecker retrieves AWS secrets engine role configuration from Vault.
type AWSChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewAWSChecker creates a new AWSChecker using the provided Vault client.
func NewAWSChecker(c *Client) *AWSChecker {
	return &AWSChecker{
		client: c.HTTP,
		base:   c.Address,
		token:  c.Token,
	}
}

// GetRole fetches the AWS role configuration at the given mount and role name.
func (a *AWSChecker) GetRole(mount, role string) (*AWSRoleInfo, error) {
	if mount == "" || role == "" {
		return nil, fmt.Errorf("aws checker: mount and role must not be empty")
	}

	url := fmt.Sprintf("%s/v1/%s/roles/%s", a.base, mount, role)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("aws checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", a.token)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aws checker: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aws checker: unexpected status %d", resp.StatusCode)
	}

	var envelope struct {
		Data AWSRoleInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("aws checker: decode: %w", err)
	}

	info := envelope.Data
	info.Mount = mount
	info.Role = role
	return &info, nil
}
