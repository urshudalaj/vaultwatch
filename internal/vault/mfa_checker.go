package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// MFAMethod holds information about a configured MFA method.
type MFAMethod struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// MFAChecker retrieves MFA method configurations from Vault.
type MFAChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewMFAChecker returns a new MFAChecker.
func NewMFAChecker(client *http.Client, baseURL, token string) *MFAChecker {
	return &MFAChecker{client: client, base: baseURL, token: token}
}

// ListMFAMethods lists all configured MFA methods.
func (m *MFAChecker) ListMFAMethods() ([]MFAMethod, error) {
	url := fmt.Sprintf("%s/v1/identity/mfa/method", m.base)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("mfa: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", m.token)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mfa: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mfa: unexpected status %d", resp.StatusCode)
	}

	var payload struct {
		Data struct {
			Keys []MFAMethod `json:"key_info"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("mfa: decode response: %w", err)
	}
	return payload.Data.Keys, nil
}
