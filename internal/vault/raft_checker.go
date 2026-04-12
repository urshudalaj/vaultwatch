package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// RaftStatus holds the Raft cluster status returned by Vault.
type RaftStatus struct {
	LeaderID        string `json:"leader_id"`
	AppliedIndex    uint64 `json:"applied_index"`
	CommitIndex     uint64 `json:"commit_index"`
	FSMPending      uint64 `json:"fsm_pending"`
	LastContact     string `json:"last_contact"`
	NumPeers        int    `json:"num_peers"`
	ProtocolVersion int    `json:"protocol_version"`
}

// RaftChecker queries the Vault Raft storage backend status.
type RaftChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewRaftChecker returns a new RaftChecker.
func NewRaftChecker(baseURL, token string, client *http.Client) *RaftChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &RaftChecker{client: client, baseURL: baseURL, token: token}
}

// CheckRaft fetches the Raft status from Vault.
func (r *RaftChecker) CheckRaft() (*RaftStatus, error) {
	url := fmt.Sprintf("%s/v1/sys/storage/raft/status", r.baseURL)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("raft checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", r.token)

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("raft checker: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("raft checker: unexpected status %d", resp.StatusCode)
	}

	var payload struct {
		Data RaftStatus `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("raft checker: decode response: %w", err)
	}
	return &payload.Data, nil
}
