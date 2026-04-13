package vault

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// OIDCRole holds configuration details for a Vault OIDC role.
type OIDCRole struct {
	RoleName    string
	BoundAudiences []string `json:"bound_audiences"`
	TTL         string   `json:"ttl"`
	MaxTTL      string   `json:"max_ttl"`
	UserClaim   string   `json:"user_claim"`
}

// OIDCChecker fetches OIDC role configuration from Vault.
type OIDCChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewOIDCChecker creates a new OIDCChecker.
func NewOIDCChecker(base, token string, client *http.Client) *OIDCChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &OIDCChecker{client: client, base: base, token: token}
}

// GetOIDCRole retrieves the OIDC role from the given mount and role name.
func (c *OIDCChecker) GetOIDCRole(mount, role string) (*OIDCRole, error) {
	if mount == "" || role == "" {
		return nil, fmt.Errorf("oidc_checker: mount and role must not be empty")
	}
	url := fmt.Sprintf("%s/v1/auth/%s/role/%s", c.base, mount, role)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc_checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc_checker: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc_checker: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oidc_checker: read body: %w", err)
	}
	var envelope struct {
		Data OIDCRole `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("oidc_checker: decode: %w", err)
	}
	envelope.Data.RoleName = role
	return &envelope.Data, nil
}
