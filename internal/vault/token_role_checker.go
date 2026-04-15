package vault

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// TokenRoleInfo holds configuration details for a Vault token role.
type TokenRoleInfo struct {
	Name            string `json:"name"`
	TokenTTL        int    `json:"token_ttl"`
	TokenMaxTTL     int    `json:"token_max_ttl"`
	TokenExplicitMaxTTL int `json:"token_explicit_max_ttl"`
	Orphan          bool   `json:"orphan"`
	Renewable       bool   `json:"renewable"`
}

// TokenRoleChecker retrieves token role configuration from Vault.
type TokenRoleChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewTokenRoleChecker creates a new TokenRoleChecker.
func NewTokenRoleChecker(client *http.Client, baseURL, token string) *TokenRoleChecker {
	return &TokenRoleChecker{
		client: client,
		base:   baseURL,
		token:  token,
	}
}

// GetTokenRole fetches the token role configuration for the given role name.
func (c *TokenRoleChecker) GetTokenRole(roleName string) (*TokenRoleInfo, error) {
	if roleName == "" {
		return nil, fmt.Errorf("token role name must not be empty")
	}

	url := fmt.Sprintf("%s/v1/auth/token/roles/%s", c.base, roleName)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for role %q", resp.StatusCode, roleName)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var wrapper struct {
		Data TokenRoleInfo `json:"data"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	wrapper.Data.Name = roleName
	return &wrapper.Data, nil
}
