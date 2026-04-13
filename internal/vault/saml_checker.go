package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// SAMLRole holds configuration details for a SAML auth role.
type SAMLRole struct {
	BoundSubjects    []string `json:"bound_subjects"`
	BoundAttributes  map[string]string `json:"bound_attributes"`
	TTL              string   `json:"ttl"`
	MaxTTL           string   `json:"max_ttl"`
	TokenPolicies    []string `json:"token_policies"`
}

// SAMLChecker reads SAML auth role configuration from Vault.
type SAMLChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewSAMLChecker creates a new SAMLChecker.
func NewSAMLChecker(base, token string, client *http.Client) *SAMLChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &SAMLChecker{client: client, base: base, token: token}
}

// GetSAMLRole fetches the SAML role config from the given mount and role name.
func (s *SAMLChecker) GetSAMLRole(mount, role string) (*SAMLRole, error) {
	if mount == "" || role == "" {
		return nil, fmt.Errorf("saml_checker: mount and role must not be empty")
	}
	url := fmt.Sprintf("%s/v1/auth/%s/role/%s", s.base, mount, role)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("saml_checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("saml_checker: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("saml_checker: unexpected status %d", resp.StatusCode)
	}

	var wrapper struct {
		Data SAMLRole `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("saml_checker: decode response: %w", err)
	}
	return &wrapper.Data, nil
}
