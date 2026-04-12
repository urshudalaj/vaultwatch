package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// DatabaseRole holds metadata about a Vault database role.
type DatabaseRole struct {
	Mount          string
	Role           string
	DefaultTTL     int `json:"default_ttl"`
	MaxTTL         int `json:"max_ttl"`
	CreationStmts  []string `json:"creation_statements"`
}

// DatabaseChecker reads database secret engine roles from Vault.
type DatabaseChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewDatabaseChecker constructs a DatabaseChecker using the provided Vault client.
func NewDatabaseChecker(base, token string, client *http.Client) *DatabaseChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &DatabaseChecker{client: client, base: base, token: token}
}

// GetRole fetches the configuration for a named database role.
func (d *DatabaseChecker) GetRole(mount, role string) (*DatabaseRole, error) {
	if mount == "" || role == "" {
		return nil, fmt.Errorf("database checker: mount and role must not be empty")
	}
	url := fmt.Sprintf("%s/v1/%s/roles/%s", d.base, mount, role)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("database checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", d.token)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("database checker: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("database checker: unexpected status %d for role %s/%s", resp.StatusCode, mount, role)
	}

	var wrapper struct {
		Data DatabaseRole `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("database checker: decode response: %w", err)
	}
	wrapper.Data.Mount = mount
	wrapper.Data.Role = role
	return &wrapper.Data, nil
}
