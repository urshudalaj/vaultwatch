package vault

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// RGPPolicy represents a Role Governing Policy in Vault.
type RGPPolicy struct {
	Name             string `json:"name"`
	Policy           string `json:"policy"`
	EnforcementLevel string `json:"enforcement_level"`
}

// RGPChecker retrieves RGP policies from Vault.
type RGPChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewRGPChecker creates a new RGPChecker.
func NewRGPChecker(base, token string, client *http.Client) *RGPChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &RGPChecker{client: client, base: base, token: token}
}

// GetRGP retrieves a single RGP policy by name.
func (r *RGPChecker) GetRGP(name string) (*RGPPolicy, error) {
	if name == "" {
		return nil, fmt.Errorf("rgp name must not be empty")
	}
	url := fmt.Sprintf("%s/v1/sys/policies/rgp/%s", r.base, name)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", r.token)

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for Rq", resp.StatusCode, name, err := io.ReadAll( struct {
		Data RGPPolicy `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return &result.Data, nil
}
