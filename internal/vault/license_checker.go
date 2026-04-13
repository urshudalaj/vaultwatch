package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// LicenseInfo holds metadata about a Vault Enterprise license.
type LicenseInfo struct {
	LicenseID      string    `json:"license_id"`
	CustomerName   string    `json:"customer_name"`
	InstallationID string    `json:"installation_id"`
	IssueTime      time.Time `json:"issue_time"`
	StartTime      time.Time `json:"start_time"`
	ExpirationTime time.Time `json:"expiration_time"`
	Terminated     bool      `json:"terminated"`
	Features       []string  `json:"features"`
}

// LicenseChecker fetches Vault Enterprise license information.
type LicenseChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewLicenseChecker constructs a LicenseChecker using the provided API client.
func NewLicenseChecker(client *http.Client, baseURL, token string) *LicenseChecker {
	return &LicenseChecker{client: client, base: baseURL, token: token}
}

// GetLicense retrieves the current Vault Enterprise license details.
func (lc *LicenseChecker) GetLicense() (*LicenseInfo, error) {
	req, err := http.NewRequest(http.MethodGet, lc.base+"/v1/sys/license/status", nil)
	if err != nil {
		return nil, fmt.Errorf("license_checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", lc.token)

	resp, err := lc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("license_checker: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("license_checker: unexpected status %d", resp.StatusCode)
	}

	var wrapper struct {
		Data LicenseInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("license_checker: decode response: %w", err)
	}

	return &wrapper.Data, nil
}
