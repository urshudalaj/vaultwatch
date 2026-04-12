package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// CAInfo holds information about a PKI CA certificate.
type CAInfo struct {
	Mount      string
	Expiration time.Time
	Issuer     string
}

// CAChecker reads PKI CA certificate expiry information from Vault.
type CAChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewCAChecker creates a new CAChecker.
func NewCAChecker(baseURL, token string, client *http.Client) *CAChecker {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &CAChecker{client: client, baseURL: baseURL, token: token}
}

// CheckCA fetches CA certificate info for the given PKI mount.
func (c *CAChecker) CheckCA(mount string) (*CAInfo, error) {
	if mount == "" {
		return nil, fmt.Errorf("mount must not be empty")
	}

	url := fmt.Sprintf("%s/v1/%s/cert/ca", c.baseURL, mount)
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
		return nil, fmt.Errorf("unexpected status %d for mount %s", resp.StatusCode, mount)
	}

	var body struct {
		Data struct {
			Expiration int64  `json:"expiration"`
			IssuingCA  string `json:"issuing_ca"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &CAInfo{
		Mount:      mount,
		Expiration: time.Unix(body.Data.Expiration, 0),
		Issuer:     body.Data.IssuingCA,
	}, nil
}
