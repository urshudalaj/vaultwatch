package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SecretLeaseInfo holds metadata about a secret's lease expiry.
type SecretLeaseInfo struct {
	LeaseID        string
	Renewable      bool
	LeaseDuration  time.Duration
	ExpireTime     time.Time
}

// SecretLeaseChecker queries Vault for lease metadata on a given secret path.
type SecretLeaseChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewSecretLeaseChecker constructs a SecretLeaseChecker using the provided API client.
func NewSecretLeaseChecker(client *http.Client, baseURL, token string) *SecretLeaseChecker {
	return &SecretLeaseChecker{
		client:  client,
		baseURL: baseURL,
		token:   token,
	}
}

// CheckLease retrieves lease information for the given leaseID.
func (c *SecretLeaseChecker) CheckLease(leaseID string) (*SecretLeaseInfo, error) {
	if leaseID == "" {
		return nil, fmt.Errorf("lease ID must not be empty")
	}

	req, err := http.NewRequest(http.MethodPut, c.baseURL+"/v1/sys/leases/lookup", nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	body := fmt.Sprintf(`{"lease_id":%q}`, leaseID)
	req.Body = http.NoBody
	req2, _ := http.NewRequest(http.MethodPut, c.baseURL+"/v1/sys/leases/lookup", nil)
	req2.Header.Set("X-Vault-Token", c.token)
	req2.Header.Set("Content-Type", "application/json")
	req2.Body = newStringBody(body)

	resp, err := c.client.Do(req2)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for lease %s", resp.StatusCode, leaseID)
	}

	var out struct {
		Data struct {
			ID            string `json:"id"`
			Renewable     bool   `json:"renewable"`
			LeaseDuration int    `json:"ttl"`
			ExpireTime    string `json:"expire_time"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	info := &SecretLeaseInfo{
		LeaseID:       out.Data.ID,
		Renewable:     out.Data.Renewable,
		LeaseDuration: time.Duration(out.Data.LeaseDuration) * time.Second,
	}
	if out.Data.ExpireTime != "" {
		t, err := time.Parse(time.RFC3339, out.Data.ExpireTime)
		if err == nil {
			info.ExpireTime = t
		}
	}
	return info, nil
}
