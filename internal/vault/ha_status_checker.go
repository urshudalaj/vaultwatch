package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// HAStatusInfo holds high-availability status details.
type HAStatusInfo struct {
	ClusterName string `json:"cluster_name"`
	ClusterID   string `json:"cluster_id"`
	LeaderAddr  string `json:"leader_address"`
	IsLeader    bool   `json:"is_self"`
	HAEnabled   bool   `json:"ha_enabled"`
}

// HAStatusChecker checks Vault HA status.
type HAStatusChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewHAStatusChecker returns a new HAStatusChecker.
func NewHAStatusChecker(base, token string, client *http.Client) *HAStatusChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &HAStatusChecker{client: client, base: base, token: token}
}

// CheckHAStatus queries /v1/sys/leader for HA status.
func (c *HAStatusChecker) CheckHAStatus() (*HAStatusInfo, error) {
	url := fmt.Sprintf("%s/v1/sys/leader", c.base)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("ha status: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ha status: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ha status: unexpected status %d", resp.StatusCode)
	}

	var out struct {
		HAEnabled   bool   `json:"ha_enabled"`
		IsSelf      bool   `json:"is_self"`
		LeaderAddr  string `json:"leader_address"`
		ClusterName string `json:"cluster_name"`
		ClusterID   string `json:"cluster_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("ha status: decode: %w", err)
	}

	return &HAStatusInfo{
		ClusterName: out.ClusterName,
		ClusterID:   out.ClusterID,
		LeaderAddr:  out.LeaderAddr,
		IsLeader:    out.IsSelf,
		HAEnabled:   out.HAEnabled,
	}, nil
}
