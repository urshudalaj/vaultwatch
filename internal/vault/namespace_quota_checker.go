package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// NamespaceQuotaInfo holds rate-limit quota details for a namespace.
type NamespaceQuotaInfo struct {
	Name      string  `json:"name"`
	Namespace string  `json:"namespace"`
	Type      string  `json:"type"`
	Rate      float64 `json:"rate"`
	Interval  float64 `json:"interval"`
}

// NamespaceQuotaChecker retrieves quota information scoped to a namespace.
type NamespaceQuotaChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewNamespaceQuotaChecker creates a new NamespaceQuotaChecker.
func NewNamespaceQuotaChecker(baseURL, token string, client *http.Client) *NamespaceQuotaChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &NamespaceQuotaChecker{client: client, baseURL: baseURL, token: token}
}

// GetNamespaceQuota fetches quota details for the given quota name within a namespace.
func (c *NamespaceQuotaChecker) GetNamespaceQuota(namespace, name string) (*NamespaceQuotaInfo, error) {
	if namespace == "" || name == "" {
		return nil, fmt.Errorf("namespace and name must not be empty")
	}
	url := fmt.Sprintf("%s/v1/%s/sys/quotas/rate-limit/%s", c.baseURL, namespace, name)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for namespace quota %s/%s", resp.StatusCode, namespace, name)
	}
	var wrapper struct {
		Data NamespaceQuotaInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &wrapper.Data, nil
}
