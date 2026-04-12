package vault

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// AppRoleInfo holds metadata about a Vault AppRole.
type AppRoleInfo struct {
	RoleID        string `json:"role_id"`
	SecretIDTTL   string `json:"secret_id_ttl"`
	TokenTTL      string `json:"token_ttl"`
	TokenMaxTTL   string `json:"token_max_ttl"`
	TokenPolicies []string `json:"token_policies"`
	Enabled       bool   `json:"bind_secret_id"`
}

// AppRoleChecker reads AppRole role metadata from Vault.
type AppRoleChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewAppRoleChecker returns an AppRoleChecker using the provided HTTP client.
func NewAppRoleChecker(client *http.Client, baseURL, token string) *AppRoleChecker {
	return &AppRoleChecker{client: client, base: baseURL, token: token}
}

// GetRole fetches metadata for the named AppRole from the given auth mount.
func (a *AppRoleChecker) GetRole(mount, role string) (*AppRoleInfo, error) {
	if mount == "" || role == "" {
		return nil, fmt.Errorf("approle: mount and role must not be empty")
	}
	url := fmt.Sprintf("%s/v1/auth/%s/role/%s", a.base, mount, role)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("approle: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", a.token)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("approle: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("approle: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("approle: read body: %w", err)
	}

	var envelope struct {
		Data AppRoleInfo `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("approle: decode response: %w", err)
	}
	return &envelope.Data, nil
}
