package vault

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// PKICertInfo holds metadata about a PKI certificate role.
type PKICertInfo struct {
	Mount   string
	Role    string
	MaxTTL  string
	TTL     string
	AllowedDomains []string
}

// PKIChecker reads PKI secret engine role configuration from Vault.
type PKIChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewPKIChecker creates a new PKIChecker using the provided Vault client.
func NewPKIChecker(baseURL, token string, client *http.Client) *PKIChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &PKIChecker{client: client, baseURL: baseURL, token: token}
}

// GetRole fetches the PKI role configuration for the given mount and role name.
func (p *PKIChecker) GetRole(mount, role string) (*PKICertInfo, error) {
	if mount == "" || role == "" {
		return nil, fmt.Errorf("pki: mount and role must not be empty")
	}
	url := fmt.Sprintf("%s/v1/%s/roles/%s", p.baseURL, mount, role)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("pki: create request: %w", err)
	}
	req.Header.Set("X-Vault-Token", p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pki: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pki: unexpected status %d for role %s/%s", resp.StatusCode, mount, role)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("pki: read body: %w", err)
	}

	var result struct {
		Data struct {
			MaxTTL         string   `json:"max_ttl"`
			TTL            string   `json:"ttl"`
			AllowedDomains []string `json:"allowed_domains"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("pki: decode response: %w", err)
	}

	return &PKICertInfo{
		Mount:          mount,
		Role:           role,
		MaxTTL:         result.Data.MaxTTL,
		TTL:            result.Data.TTL,
		AllowedDomains: result.Data.AllowedDomains,
	}, nil
}
