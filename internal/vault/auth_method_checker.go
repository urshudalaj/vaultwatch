package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// AuthMethodInfo holds details about a Vault auth method mount.
type AuthMethodInfo struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Accessor    string `json:"accessor"`
	Local       bool   `json:"local"`
	SealWrap    bool   `json:"seal_wrap"`
}

// AuthMethodChecker lists enabled auth methods from Vault.
type AuthMethodChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewAuthMethodChecker creates a new AuthMethodChecker.
func NewAuthMethodChecker(base, token string, client *http.Client) *AuthMethodChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &AuthMethodChecker{client: client, base: base, token: token}
}

// ListAuthMethods returns a map of mount path to AuthMethodInfo for all
// enabled auth methods.
func (c *AuthMethodChecker) ListAuthMethods() (map[string]AuthMethodInfo, error) {
	url := fmt.Sprintf("%s/v1/sys/auth", c.base)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("auth method checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth method checker: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth method checker: unexpected status %d", resp.StatusCode)
	}

	var payload struct {
		Data map[string]AuthMethodInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("auth method checker: decode response: %w", err)
	}

	if payload.Data == nil {
		return map[string]AuthMethodInfo{}, nil
	}
	return payload.Data, nil
}
