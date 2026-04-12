package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// SSHRoleInfo holds information about a Vault SSH secret engine role.
type SSHRoleInfo struct {
	Mount    string
	Role     string
	KeyType  string `json:"key_type"`
	TTL      string `json:"ttl"`
	MaxTTL   string `json:"max_ttl"`
	AllowedUsers string `json:"allowed_users"`
}

// SSHChecker checks SSH secret engine roles in Vault.
type SSHChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewSSHChecker creates a new SSHChecker.
func NewSSHChecker(base, token string, client *http.Client) *SSHChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &SSHChecker{client: client, base: base, token: token}
}

// GetRole returns the SSH role configuration for the given mount and role name.
func (s *SSHChecker) GetRole(mount, role string) (*SSHRoleInfo, error) {
	if mount == "" || role == "" {
		return nil, fmt.Errorf("ssh checker: mount and role must not be empty")
	}
	url := fmt.Sprintf("%s/v1/%s/roles/%s", s.base, mount, role)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("ssh checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ssh checker: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ssh checker: unexpected status %d for role %s/%s", resp.StatusCode, mount, role)
	}

	var wrapper struct {
		Data SSHRoleInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("ssh checker: decode: %w", err)
	}
	wrapper.Data.Mount = mount
	wrapper.Data.Role = role
	return &wrapper.Data, nil
}
