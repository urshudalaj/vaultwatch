package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// OktaRole holds configuration details for an Okta auth role.
type OktaRole struct {
	Mount    string
	Name     string
	Policies []string `json:"policies"`
	TTL      string   `json:"ttl"`
	MaxTTL   string   `json:"max_ttl"`
}

// OktaChecker fetches Okta auth role details from Vault.
type OktaChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewOktaChecker creates a new OktaChecker.
func NewOktaChecker(base, token string, client *http.Client) *OktaChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &OktaChecker{client: client, base: base, token: token}
}

// GetOktaRole retrieves the Okta role configuration for the given mount and role name.
func (o *OktaChecker) GetOktaRole(mount, role string) (*OktaRole, error) {
	if mount == "" || role == "" {
		return nil, fmt.Errorf("okta_checker: mount and role must not be empty")
	}
	url := fmt.Sprintf("%s/v1/auth/%s/groups/%s", o.base, mount, role)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("okta_checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", o.token)

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("okta_checker: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("okta_checker: unexpected status %d", resp.StatusCode)
	}

	var wrapper struct {
		Data OktaRole `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("okta_checker: decode response: %w", err)
	}
	wrapper.Data.Mount = mount
	wrapper.Data.Name = role
	return &wrapper.Data, nil
}
