package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// SysInfo holds high-level system information returned by Vault.
type SysInfo struct {
	ClusterName string `json:"cluster_name"`
	ClusterID   string `json:"cluster_id"`
	Version     string `json:"version"`
	BuildDate   string `json:"build_date"`
}

// SysChecker retrieves general system information from Vault.
type SysChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewSysChecker creates a SysChecker using the provided HTTP client, base URL, and token.
func NewSysChecker(client *http.Client, baseURL, token string) *SysChecker {
	return &SysChecker{client: client, base: baseURL, token: token}
}

// GetSysInfo fetches cluster and version information from /v1/sys/seal-status
// and /v1/sys/health, combining them into a SysInfo struct.
func (s *SysChecker) GetSysInfo() (*SysInfo, error) {
	req, err := http.NewRequest(http.MethodGet, s.base+"/v1/sys/health", nil)
	if err != nil {
		return nil, fmt.Errorf("sys checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sys checker: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusTooManyRequests {
		return nil, fmt.Errorf("sys checker: unexpected status %d", resp.StatusCode)
	}

	var payload struct {
		ClusterName string `json:"cluster_name"`
		ClusterID   string `json:"cluster_id"`
		Version     string `json:"version"`
		BuildDate   string `json:"build_date"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("sys checker: decode response: %w", err)
	}

	return &SysInfo{
		ClusterName: payload.ClusterName,
		ClusterID:   payload.ClusterID,
		Version:     payload.Version,
		BuildDate:   payload.BuildDate,
	}, nil
}
