package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// AuditDevice represents a single Vault audit device.
type AuditDevice struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Enabled     bool
}

// AuditChecker queries Vault for enabled audit devices.
type AuditChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewAuditChecker creates a new AuditChecker using the provided Vault client.
func NewAuditChecker(baseURL, token string, client *http.Client) *AuditChecker {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &AuditChecker{client: client, baseURL: baseURL, token: token}
}

// ListAuditDevices returns all configured audit devices from Vault.
func (a *AuditChecker) ListAuditDevices(ctx context.Context) ([]AuditDevice, error) {
	url := fmt.Sprintf("%s/v1/sys/audit", a.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("audit: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", a.token)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("audit: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("audit: unexpected status %d", resp.StatusCode)
	}

	var raw map[string]struct {
		Type        string `json:"type"`
		Description string `json:"description"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("audit: decode response: %w", err)
	}

	devices := make([]AuditDevice, 0, len(raw))
	for path, info := range raw {
		devices = append(devices, AuditDevice{
			Path:        path,
			Type:        info.Type,
			Description: info.Description,
			Enabled:     true,
		})
	}
	return devices, nil
}
