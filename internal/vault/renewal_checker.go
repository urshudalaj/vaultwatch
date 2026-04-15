package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// RenewalInfo holds information about a lease's renewal eligibility.
type RenewalInfo struct {
	LeaseID   string
	Renewable bool
	TTL       int
	MaxTTL    int
}

// RenewalChecker checks whether a lease is renewable and retrieves its TTL info.
type RenewalChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewRenewalChecker creates a new RenewalChecker.
func NewRenewalChecker(baseURL, token string, client *http.Client) *RenewalChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &RenewalChecker{client: client, baseURL: baseURL, token: token}
}

// CheckRenewal queries Vault for lease renewal info by leaseID.
func (r *RenewalChecker) CheckRenewal(leaseID string) (*RenewalInfo, error) {
	if leaseID == "" {
		return nil, fmt.Errorf("lease ID must not be empty")
	}

	body, err := jsonMarshal(map[string]string{"lease_id": leaseID})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := newJSONRequest("PUT", r.baseURL+"/v1/sys/leases/lookup", body, r.token)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var out struct {
		Data struct {
			ID        string `json:"id"`
			Renewable bool   `json:"renewable"`
			TTL       int    `json:"ttl"`
			MaxTTL    int    `json:"max_ttl"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &RenewalInfo{
		LeaseID:   out.Data.ID,
		Renewable: out.Data.Renewable,
		TTL:       out.Data.TTL,
		MaxTTL:    out.Data.MaxTTL,
	}, nil
}
