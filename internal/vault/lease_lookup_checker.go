package vault

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// LeaseLookupInfo holds metadata about a Vault lease returned by sys/leases/lookup.
type LeaseLookupInfo struct {
	LeaseID        string    `json:"id"`
	IssueTime      time.Time `json:"issue_time"`
	ExpireTime     time.Time `json:"expire_time"`
	LastRenewalTime time.Time `json:"last_renewal"`
	Renewable      bool      `json:"renewable"`
	TTL            int       `json:"ttl"`
}

// LeaseLookupChecker queries Vault for detailed lease information.
type LeaseLookupChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewLeaseLookupChecker creates a new LeaseLookupChecker.
func NewLeaseLookupChecker(base, token string, client *http.Client) *LeaseLookupChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &LeaseLookupChecker{client: client, base: base, token: token}
}

// LookupLease fetches metadata for the given leaseID from Vault.
func (c *LeaseLookupChecker) LookupLease(leaseID string) (*LeaseLookupInfo, error) {
	if leaseID == "" {
		return nil, fmt.Errorf("lease ID must not be empty")
	}

	url := fmt.Sprintf("%s/v1/sys/leases/lookup", c.base)
	body := fmt.Sprintf(`{"lease_id":%q}`, leaseID)

	req, err := http.NewRequest(http.MethodPut, url, mustStringReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for lease lookup", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var envelope struct {
		Data LeaseLookupInfo `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &envelope.Data, nil
}
