package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// PolicyCountInfo holds the total number of ACL policies in Vault.
type PolicyCountInfo struct {
	Count int
	Names []string
}

// PolicyCountChecker retrieves the count of ACL policies from Vault.
type PolicyCountChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewPolicyCountChecker creates a new PolicyCountChecker.
func NewPolicyCountChecker(baseURL, token string, client *http.Client) *PolicyCountChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &PolicyCountChecker{client: client, baseURL: baseURL, token: token}
}

// CountPolicies lists all ACL policies and returns count information.
func (c *PolicyCountChecker) CountPolicies() (*PolicyCountInfo, error) {
	url := fmt.Sprintf("%s/v1/sys/policies/acl?list=true", c.baseURL)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("policy count: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("policy count: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("policy count: unexpected status %d", resp.StatusCode)
	}

	var payload struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("policy count: decode response: %w", err)
	}

	return &PolicyCountInfo{
		Count: len(payload.Data.Keys),
		Names: payload.Data.Keys,
	}, nil
}
