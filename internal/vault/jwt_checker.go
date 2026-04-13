package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// JWTRole holds configuration details for a JWT/OIDC auth role.
type JWTRole struct {
	Name            string `json:"name"`
	BoundAudiences  []string `json:"bound_audiences"`
	TokenTTL        int    `json:"token_ttl"`
	TokenMaxTTL     int    `json:"token_max_ttl"`
	TokenPolicies   []string `json:"token_policies"`
}

// JWTChecker reads JWT/OIDC role configuration from Vault.
type JWTChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewJWTChecker constructs a JWTChecker using the provided API client.
func NewJWTChecker(client *http.Client, baseURL, token string) *JWTChecker {
	return &JWTChecker{client: client, baseURL: baseURL, token: token}
}

// GetRole retrieves the JWT/OIDC role at the given mount and role name.
func (j *JWTChecker) GetRole(mount, role string) (*JWTRole, error) {
	if mount == "" || role == "" {
		return nil, fmt.Errorf("jwt: mount and role must not be empty")
	}

	url := fmt.Sprintf("%s/v1/auth/%s/role/%s", j.baseURL, mount, role)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("jwt: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", j.token)

	resp, err := j.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwt: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwt: unexpected status %d for role %s/%s", resp.StatusCode, mount, role)
	}

	var envelope struct {
		Data JWTRole `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("jwt: decode response: %w", err)
	}

	envelope.Data.Name = role
	return &envelope.Data, nil
}
