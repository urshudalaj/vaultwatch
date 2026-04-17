package vault

import (
	"context"
	"fmt"
	"net/http"
)

// StepDownInfo holds information about the active node step-down status.
type StepDownInfo struct {
	ClusterID   string `json:"cluster_id"`
	ClusterName string `json:"cluster_name"`
	LeaderAddr  string `json:"leader_address"`
	IsSelf      bool   `json:"is_self"`
}

// StepDownChecker checks whether the active Vault node considers itself leader.
type StepDownChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewStepDownChecker creates a new StepDownChecker.
func NewStepDownChecker(base, token string, client *http.Client) *StepDownChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &StepDownChecker{client: client, base: base, token: token}
}

// CheckLeaderSelf returns the leader status for the current node.
func (c *StepDownChecker) CheckLeaderSelf(ctx context.Context) (*StepDownInfo, error) {
	url := fmt.Sprintf("%s/v1/sys/leader", c.base)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("step_down_checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("step_down_checker: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("step_down_checker: unexpected status %d", resp.StatusCode)
	}

	var wrapper struct {
		ClusterID   string `json:"cluster_id"`
		ClusterName string `json:"cluster_name"`
		LeaderAddr  string `json:"leader_address"`
		IsSelf      bool   `json:"is_self"`
	}
	if err := decodeJSON(resp.Body, &wrapper); err != nil {
		return nil, fmt.Errorf("step_down_checker: decode: %w", err)
	}
	return &StepDownInfo{
		ClusterID:   wrapper.ClusterID,
		ClusterName: wrapper.ClusterName,
		LeaderAddr:  wrapper.LeaderAddr,
		IsSelf:      wrapper.IsSelf,
	}, nil
}
