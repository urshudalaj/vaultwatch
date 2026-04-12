package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// QuotaInfo holds rate-limit quota details for a Vault path.
type QuotaInfo struct {
	Name        string  `json:"name"`
	Path        string  `json:"path"`
	Type        string  `json:"type"`
	MaxRequests float64 `json:"rate"`
	Interval    float64 `json:"interval"`
}

// QuotaListResponse is the Vault API response for listing quotas.
type QuotaListResponse struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
}

// QuotaChecker queries Vault for configured rate-limit quotas.
type QuotaChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewQuotaChecker creates a QuotaChecker using the provided Vault client.
func NewQuotaChecker(base, token string, client *http.Client) *QuotaChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &QuotaChecker{client: client, base: base, token: token}
}

// ListQuotas returns the names of all rate-limit quotas defined in Vault.
func (q *QuotaChecker) ListQuotas(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		q.base+"/v1/sys/quotas/rate-limit", nil)
	if err != nil {
		return nil, fmt.Errorf("quota list request: %w", err)
	}
	req.Header.Set("X-Vault-Token", q.token)
	q.addListHeader(req)

	resp, err := q.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("quota list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("quota list: unexpected status %d", resp.StatusCode)
	}

	var out QuotaListResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("quota list decode: %w", err)
	}
	return out.Data.Keys, nil
}

// GetQuota returns the details for a named rate-limit quota.
func (q *QuotaChecker) GetQuota(ctx context.Context, name string) (*QuotaInfo, error) {
	if name == "" {
		return nil, fmt.Errorf("quota name must not be empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		q.base+"/v1/sys/quotas/rate-limit/"+name, nil)
	if err != nil {
		return nil, fmt.Errorf("quota get request: %w", err)
	}
	req.Header.Set("X-Vault-Token", q.token)

	resp, err := q.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("quota get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("quota get: unexpected status %d", resp.StatusCode)
	}

	var wrapper struct {
		Data QuotaInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("quota get decode: %w", err)
	}
	return &wrapper.Data, nil
}

func (q *QuotaChecker) addListHeader(r *http.Request) {
	r.Header.Set("X-Vault-Request", "true")
}
