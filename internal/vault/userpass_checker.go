package vault

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// UserpassRole holds configuration for a userpass auth role.
type UserpassRole struct {
	TokenTTL    string `json:"token_ttl"`
	TokenMaxTTL string `json:"token_max_ttl"`
	TokenPolicies []string `json:"token_policies"`
}

// UserpassChecker retrieves userpass auth role information from Vault.
type UserpassChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewUserpassChecker creates a new UserpassChecker.
func NewUserpassChecker(base, token string, client *http.Client) *UserpassChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &UserpassChecker{client: client, base: base, token: token}
}

// GetUserpassRole fetches the configuration for a userpass role at the given mount.
func (u *UserpassChecker) GetUserpassRole(mount, username string) (*UserpassRole, error) {
	if mount == "" || username == "" {
		return nil, fmt.Errorf("userpass: mount and username must not be empty")
	}
	url := fmt.Sprintf("%s/v1/auth/%s/users/%s", u.base, mount, username)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("userpass: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", u.token)

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userpass: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userpass: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("userpass: read body: %w", err)
	}

	var envelope struct {
		Data UserpassRole `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("userpass: decode response: %w", err)
	}
	return &envelope.Data, nil
}
