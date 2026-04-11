package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SnapshotInfo holds metadata about the latest Vault raft snapshot.
type SnapshotInfo struct {
	Index     uint64    `json:"index"`
	Term      uint64    `json:"term"`
	Timestamp time.Time `json:"timestamp"`
}

// SnapshotChecker queries the Vault raft storage snapshot status.
type SnapshotChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewSnapshotChecker returns a SnapshotChecker using the provided HTTP client.
func NewSnapshotChecker(base, token string, client *http.Client) *SnapshotChecker {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &SnapshotChecker{client: client, base: base, token: token}
}

// CheckSnapshot retrieves the raft configuration to infer snapshot availability.
func (s *SnapshotChecker) CheckSnapshot(ctx context.Context) (*SnapshotInfo, error) {
	url := fmt.Sprintf("%s/v1/sys/storage/raft/configuration", s.base)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("snapshot: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("snapshot: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("snapshot: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Data struct {
			Config struct {
				Index uint64 `json:"commit_index"`
				Term  uint64 `json:"term"`
			} `json:"config"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("snapshot: decode response: %w", err)
	}

	return &SnapshotInfo{
		Index:     body.Data.Config.Index,
		Term:      body.Data.Config.Term,
		Timestamp: time.Now().UTC(),
	}, nil
}
