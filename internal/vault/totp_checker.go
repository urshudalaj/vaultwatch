package vault

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// TOTPKey holds metadata about a TOTP key stored in Vault.
type TOTPKey struct {
	AccountName string `json:"account_name"`
	Issuer      string `json:"issuer"`
	Period      int    `json:"period"`
	Digits      int    `json:"digits"`
	Algorithm   string `json:"algorithm"`
}

// TOTPChecker reads TOTP key metadata from a Vault TOTP secrets engine mount.
type TOTPChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewTOTPChecker creates a TOTPChecker targeting the given Vault address.
func NewTOTPChecker(base, token string, client *http.Client) *TOTPChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &TOTPChecker{client: client, base: base, token: token}
}

// GetKey retrieves metadata for a named TOTP key under the given mount.
func (c *TOTPChecker) GetKey(mount, keyName string) (*TOTPKey, error) {
	if mount == "" || keyName == "" {
		return nil, fmt.Errorf("totp_checker: mount and keyName must not be empty")
	}
	url := fmt.Sprintf("%s/v1/%s/keys/%s", c.base, mount, keyName)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("totp_checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("totp_checker: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("totp_checker: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("totp_checker: read body: %w", err)
	}

	var envelope struct {
		Data TOTPKey `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("totp_checker: decode response: %w", err)
	}
	return &envelope.Data, nil
}
