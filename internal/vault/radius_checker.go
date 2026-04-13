package vault

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// RADIUSRole holds configuration for a RADIUS auth role.
type RADIUSRole struct {
	Policies []string `json:"policies"`
	TTL      string   `json:"ttl"`
	MaxTTL   string   `json:"max_ttl"`
}

// RADIUSChecker retrieves RADIUS auth role info from Vault.
type RADIUSChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewRADIUSChecker creates a new RADIUSChecker.
func NewRADIUSChecker(base, token string, client *http.Client) *RADIUSChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &RADIUSChecker{client: client, base: base, token: token}
}

// GetRADIUSRole fetches a RADIUS role from the given mount and role name.
func (r *RADIUSChecker) GetRADIUSRole(mount, role string) (*RADIUSRole, error) {
	if mount == "" || role == "" {
		return nil, fmt.Errorf("radius: mount and role must not be empty")
	}
	url := fmt.Sprintf("%s/v1/auth/%s/users/%s", r.base, mount, role)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("radius: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", r.token)

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("radius: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("radius: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("radius: read body: %w", err)
	}

	var envelope struct {
		Data RADIUSRole `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("radius: decode response: %w", err)
	}
	return &envelope.Data, nil
}
