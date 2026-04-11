package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// SealStatus holds the current seal state of a Vault instance.
type SealStatus struct {
	Sealed      bool   `json:"sealed"`
	Initialized bool   `json:"initialized"`
	ClusterName string `json:"cluster_name"`
	Version     string `json:"version"`
}

// SealChecker queries the Vault seal status endpoint.
type SealChecker struct {
	client *http.Client
	baseURL string
}

// NewSealChecker creates a new SealChecker using the provided HTTP client and base URL.
func NewSealChecker(client *http.Client, baseURL string) *SealChecker {
	return &SealChecker{
		client:  client,
		baseURL: baseURL,
	}
}

// CheckSeal queries /v1/sys/seal-status and returns the current SealStatus.
func (s *SealChecker) CheckSeal(ctx context.Context) (*SealStatus, error) {
	url := s.baseURL + "/v1/sys/seal-status"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("seal_checker: building request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("seal_checker: executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("seal_checker: unexpected status %d", resp.StatusCode)
	}

	var status SealStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("seal_checker: decoding response: %w", err)
	}

	return &status, nil
}
