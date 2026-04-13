package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// SentinelPolicy represents a single Vault Sentinel policy entry.
type SentinelPolicy struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// SentinelChecker queries Vault for Endpoint Governing Policies (EGPs) and
// Role Governing Policies (RGPs) via the Sentinel integration.
type SentinelChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewSentinelChecker returns a SentinelChecker backed by the given HTTP client.
func NewSentinelChecker(client *http.Client, baseURL, token string) *SentinelChecker {
	return &SentinelChecker{client: client, base: baseURL, token: token}
}

// ListEGPs returns the names of all Endpoint Governing Policies.
func (s *SentinelChecker) ListEGPs(ctx context.Context) ([]string, error) {
	return s.listPolicies(ctx, "egp")
}

// ListRGPs returns the names of all Role Governing Policies.
func (s *SentinelChecker) ListRGPs(ctx context.Context) ([]string, error) {
	return s.listPolicies(ctx, "rgp")
}

func (s *SentinelChecker) listPolicies(ctx context.Context, kind string) ([]string, error) {
	url := fmt.Sprintf("%s/v1/sys/policies/%s?list=true", s.base, kind)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sentinel status %d fors policies", resp.StatusCode, kind struct {
		Data struct []string `json:"keys
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("sentinel: decode error: %w", err)
	}
	return body.Data.Keys, nil
}
