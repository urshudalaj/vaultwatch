package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// RaftStatus holds the parsed response from the Vault raft autopilot state endpoint.
type RaftStatus struct {
	Healthy          bool              `json:"healthy"`
	OptimisticFailureTolerance int    `json:"optimistic_failure_tolerance"`
	Servers          map[string]RaftServer `json:"servers"`
}

// RaftServer represents a single server entry in the raft cluster.
type RaftServer struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Status  string `json:"status"`
	Leader  bool   `json:"leader"`
	Voter   bool   `json:"voter"`
	Healthy bool   `json:"healthy"`
}

// RaftChecker queries Vault's raft autopilot state.
type RaftChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewRaftChecker creates a new RaftChecker.
func NewRaftChecker(baseURL, token string, client *http.Client) *RaftChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &RaftChecker{client: client, baseURL: baseURL, token: token}
}

// CheckRaft returns the current raft autopilot status from Vault.
func (r *RaftChecker) CheckRaft(ctx context.Context) (*RaftStatus, error) {
	url := fmt.Sprintf("%s/v1/sys/storage/raft/autopilot/state", r.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("raft checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", r.token)

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("raft checker: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("raft checker: unexpected status %d", resp.StatusCode)
	}

	var status RaftStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("raft checker: decode response: %w", err)
	}
	return &status, nil
}
