package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// LeaseInfo holds metadata about a Vault lease.
type LeaseInfo struct {
	LeaseID       string
	Renewable     bool
	LeaseDuration time.Duration
	ExpireTime    time.Time
}

// LeaseChecker looks up lease metadata from Vault.
type LeaseChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewLeaseChecker constructs a LeaseChecker using the given HTTP client, Vault address, and token.
func NewLeaseChecker(client *http.Client, baseURL, token string) *LeaseChecker {
	return &LeaseChecker{
		client:  client,
		baseURL: baseURL,
		token:   token,
	}
}

// LookupLease fetches metadata for the given leaseID from Vault's sys/leases/lookup endpoint.
func (lc *LeaseChecker) LookupLease(leaseID string) (*LeaseInfo, error) {
	if leaseID == "" {
		return nil, fmt.Errorf("leaseID must not be empty")
	}

	url := fmt.Sprintf("%s/v1/sys/leases/lookup", lc.baseURL)
	body := fmt.Sprintf(`{"lease_id":%q}`, leaseID)

	req, err := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-Vault-Token", lc.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := lc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for lease lookup", resp.StatusCode)
	}

	var result struct {
		Data struct {
			ID            string `json:"id"`
			Renewable     bool   `json:"renewable"`
			TTL           int    `json:"ttl"`
			ExpireTime    string `json:"expire_time"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	info := &LeaseInfo{
		LeaseID:       result.Data.ID,
		Renewable:     result.Data.Renewable,
		LeaseDuration: time.Duration(result.Data.TTL) * time.Second,
	}

	if result.Data.ExpireTime != "" {
		t, err := time.Parse(time.RFC3339, result.Data.ExpireTime)
		if err == nil {
			info.ExpireTime = t
		}
	}

	return info, nil
}
