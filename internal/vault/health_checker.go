package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// HealthStatus holds the result of a Vault health check.
type HealthStatus struct {
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	Standby     bool   `json:"standby"`
	Version     string `json:"version"`
	ClusterName string `json:"cluster_name"`
}

// HealthChecker queries the Vault health endpoint.
type HealthChecker struct {
	client *http.Client
	baseURL string
}

// NewHealthChecker creates a HealthChecker using the given API client base URL.
func NewHealthChecker(baseURL string, client *http.Client) *HealthChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &HealthChecker{client: client, baseURL: baseURL}
}

// Check performs a GET against /v1/sys/health and returns the parsed status.
// Vault returns non-200 codes for sealed/standby states, so we accept 200, 429,
// 472, and 473 as valid responses.
func (h *HealthChecker) Check(ctx context.Context) (*HealthStatus, error) {
	url := h.baseURL + "/v1/sys/health?standbyok=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("health_checker: build request: %w", err)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("health_checker: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("health_checker: unexpected status %d", resp.StatusCode)
	}

	var status HealthStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("health_checker: decode response: %w", err)
	}
	return &status, nil
}
