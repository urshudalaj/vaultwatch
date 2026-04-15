package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// LeaseCountInfo holds information about current lease counts from Vault.
type LeaseCountInfo struct {
	LeaseCount    int            `json:"lease_count"`
	CountPerMount map[string]int `json:"counts"`
}

// LeaseCountChecker retrieves lease count information from Vault.
type LeaseCountChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewLeaseCountChecker creates a new LeaseCountChecker.
func NewLeaseCountChecker(baseURL, token string, client *http.Client) *LeaseCountChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &LeaseCountChecker{client: client, baseURL: baseURL, token: token}
}

// GetLeaseCount retrieves the current lease count from Vault.
func (c *LeaseCountChecker) GetLeaseCount() (*LeaseCountInfo, error) {
	url := fmt.Sprintf("%s/v1/sys/leases/count", c.baseURL)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("lease count checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lease count checker: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lease count checker: unexpected status %d", resp.StatusCode)
	}

	var wrapper struct {
		Data LeaseCountInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("lease count checker: decode response: %w", err)
	}
	return &wrapper.Data, nil
}
