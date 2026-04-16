package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// HAStatus holds high-availability status information from Vault.
type HAStatus struct {
	Enabled     bool   `json:"ha_enabled"`
	Leader      string `json:"leader_address"`
	LeaderCluster string `json:"leader_cluster_address"`
	PerfStandby bool   `json:"performance_standby"`
}

// HAChecker checks the HA status of a Vault cluster.
type HAChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewHAChecker creates a new HAChecker.
func NewHAChecker(base, token string, client *http.Client) *HAChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &HAChecker{client: client, base: base, token: token}
}

// CheckHA returns the HA status of the Vault cluster.
func (c *HAChecker) CheckHA() (*HAStatus, error) {
	url := fmt.Sprintf("%s/v1/sys/leader", c.base)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("ha_checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ha_checker: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ha_checker: unexpected status %d", resp.StatusCode)
	}

	var status HAStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("ha_checker: decode response: %w", err)
	}
	return &status, nil
}
