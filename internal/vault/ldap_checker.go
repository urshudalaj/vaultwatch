package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// LDAPRole holds configuration details for a Vault LDAP secrets engine role.
type LDAPRole struct {
	RoleName        string `json:"role_name"`
	CreationLDIF    string `json:"creation_ldif"`
	DeletionLDIF    string `json:"deletion_ldif"`
	DefaultTTL      string `json:"default_ttl"`
	MaxTTL          string `json:"max_ttl"`
}

// LDAPChecker checks LDAP secrets engine roles in Vault.
type LDAPChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewLDAPChecker creates a new LDAPChecker.
func NewLDAPChecker(baseURL, token string, client *http.Client) *LDAPChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &LDAPChecker{
		client:  client,
		baseURL: baseURL,
		token:   token,
	}
}

// GetRole retrieves the LDAP role configuration from the given mount and role name.
func (c *LDAPChecker) GetRole(mount, role string) (*LDAPRole, error) {
	if mount == "" || role == "" {
		return nil, fmt.Errorf("ldap checker: mount and role must not be empty")
	}

	url := fmt.Sprintf("%s/v1/%s/role/%s", c.baseURL, mount, role)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("ldap checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ldap checker: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ldap checker: unexpected status %d", resp.StatusCode)
	}

	var wrapper struct {
		Data LDAPRole `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("ldap checker: decode response: %w", err)
	}
	return &wrapper.Data, nil
}
