package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// MaintenanceInfo holds information about Vault maintenance mode status.
type MaintenanceInfo struct {
	Enabled     bool   `json:"enabled"`
	Message     string `json:"message"`
	RequestCount int64  `json:"request_count"`
}

// MaintenanceChecker checks whether Vault is in maintenance mode.
type MaintenanceChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewMaintenanceChecker returns a new MaintenanceChecker.
func NewMaintenanceChecker(base, token string, client *http.Client) *MaintenanceChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &MaintenanceChecker{client: client, base: base, token: token}
}

// CheckMaintenance queries the Vault sys/maintenance endpoint.
func (c *MaintenanceChecker) CheckMaintenance() (*MaintenanceInfo, error) {
	url := fmt.Sprintf("%s/v1/sys/maintenance", c.base)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("maintenance checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("maintenance checker: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("maintenance checker: unexpected status %d", resp.StatusCode)
	}

	var wrapper struct {
		Data MaintenanceInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("maintenance checker: decode response: %w", err)
	}
	return &wrapper.Data, nil
}
