package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// ReplicationStatus holds the DR and performance replication state.
type ReplicationStatus struct {
	DRMode          string `json:"dr_mode"`
	PerformanceMode string `json:"performance_mode"`
	DRState         string `json:"dr_state"`
	PerformanceState string `json:"performance_state"`
}

// ReplicationChecker queries the Vault replication status endpoint.
type ReplicationChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewReplicationChecker creates a new ReplicationChecker.
func NewReplicationChecker(baseURL, token string, client *http.Client) *ReplicationChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &ReplicationChecker{client: client, baseURL: baseURL, token: token}
}

// CheckReplication returns the current replication status from Vault.
func (r *ReplicationChecker) CheckReplication(ctx context.Context) (*ReplicationStatus, error) {
	url := r.baseURL + "/v1/sys/replication/status"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("replication checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", r.token)

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("replication checker: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("replication checker: unexpected status %d", resp.StatusCode)
	}

	var payload struct {
		Data struct {
			DR struct {
				Mode  string `json:"mode"`
				State string `json:"state"`
			} `json:"dr"`
			Performance struct {
				Mode  string `json:"mode"`
				State string `json:"state"`
			} `json:"performance"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("replication checker: decode response: %w", err)
	}

	return &ReplicationStatus{
		DRMode:           payload.Data.DR.Mode,
		DRState:          payload.Data.DR.State,
		PerformanceMode:  payload.Data.Performance.Mode,
		PerformanceState: payload.Data.Performance.State,
	}, nil
}
