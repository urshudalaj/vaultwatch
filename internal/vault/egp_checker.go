package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// EGPPolicy represents an Endpoint Governing Policy in Vault.
type EGPPolicy struct {
	Name             string   `json:"name"`
	Paths            []string `json:"paths"`
	EnforcementLevel string   `json:"enforcement_level"`
	Code             string   `json:"code"`
}

// EGPChecker retrieves EGP policy details from Vault.
type EGPChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewEGPChecker constructs an EGPChecker using the provided HTTP client.
func NewEGPChecker(client *http.Client, baseURL, token string) *EGPChecker {
	return &EGPChecker{client: client, base: baseURL, token: token}
}

// GetEGP fetches a single EGP policy by name.
func (e *EGPChecker) GetEGP(name string) (*EGPPolicy, error) {
	if name == "" {
		return nil, fmt.Errorf("egp policy name must not be empty")
	}

	url := fmt.Sprintf("%s/v1/sys/policies/egp/%s", e.base, name)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-Vault-Token", e.token)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for EGP %q", resp.StatusCode, name)
	}

	var wrapper struct {
		Data EGPPolicy `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &wrapper.Data, nil
}
