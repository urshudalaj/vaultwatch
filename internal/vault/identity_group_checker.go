package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// IdentityGroupInfo holds metadata about a Vault identity group.
type IdentityGroupInfo struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Policies []string `json:"policies"`
	Disabled bool     `json:"disabled"`
}

// IdentityGroupChecker retrieves identity group information from Vault.
type IdentityGroupChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewIdentityGroupChecker creates a new IdentityGroupChecker.
func NewIdentityGroupChecker(base, token string, client *http.Client) *IdentityGroupChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &IdentityGroupChecker{client: client, base: base, token: token}
}

// GetIdentityGroup fetches metadata for the identity group with the given ID.
func (c *IdentityGroupChecker) GetIdentityGroup(id string) (*IdentityGroupInfo, error) {
	if id == "" {
		return nil, fmt.Errorf("identity group id must not be empty")
	}

	url := fmt.Sprintf("%s/v1/identity/group/id/%s", c.base, id)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for identity group %s", resp.StatusCode, id)
	}

	var envelope struct {
		Data IdentityGroupInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &envelope.Data, nil
}

// ListIdentityGroups returns all identity group IDs registered in Vault.
func (c *IdentityGroupChecker) ListIdentityGroups() ([]string, error) {
	url := fmt.Sprintf("%s/v1/identity/group/id", c.base)
	req, err := http.NewRequest("LIST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d listing identity groups", resp.StatusCode)
	}

	var envelope struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return envelope.Data.Keys, nil
}
