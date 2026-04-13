package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// TransitKeyInfo holds metadata about a Vault transit encryption key.
type TransitKeyInfo struct {
	Name            string
	Type            string
	DeletionAllowed bool
	Exportable      bool
	MinDecryptVersion int
	LatestVersion   int
}

// NeedsRotation returns true if the key has never been rotated beyond version 1.
func (k *TransitKeyInfo) NeedsRotation() bool {
	return k.LatestVersion <= 1
}

// HasKeyDrift returns true if old key versions are still allowed for decryption,
// meaning MinDecryptVersion is behind LatestVersion.
func (k *TransitKeyInfo) HasKeyDrift() bool {
	return k.MinDecryptVersion < k.LatestVersion
}

// TransitChecker reads transit key metadata from Vault.
type TransitChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewTransitChecker returns a TransitChecker using the given HTTP client.
func NewTransitChecker(client *http.Client, baseURL, token string) *TransitChecker {
	return &TransitChecker{client: client, base: baseURL, token: token}
}

// GetKey returns metadata for the named transit key under the given mount.
func (tc *TransitChecker) GetKey(ctx context.Context, mount, keyName string) (*TransitKeyInfo, error) {
	if mount == "" || keyName == "" {
		return nil, fmt.Errorf("transit: mount and key name must not be empty")
	}
	url := fmt.Sprintf("%s/v1/%s/keys/%s", tc.base, mount, keyName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("transit: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", tc.token)

	resp, err := tc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("transit: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("transit: unexpected status %d for key %s/%s", resp.StatusCode, mount, keyName)
	}

	var payload struct {
		Data struct {
			Name              string `json:"name"`
			Type              string `json:"type"`
			DeletionAllowed   bool   `json:"deletion_allowed"`
			Exportable        bool   `json:"exportable"`
			MinDecryptVersion int    `json:"min_decryption_version"`
			LatestVersion     int    `json:"latest_version"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("transit: decode response: %w", err)
	}

	d := payload.Data
	return &TransitKeyInfo{
		Name:              d.Name,
		Type:              d.Type,
		DeletionAllowed:   d.DeletionAllowed,
		Exportable:        d.Exportable,
		MinDecryptVersion: d.MinDecryptVersion,
		LatestVersion:     d.LatestVersion,
	}, nil
}
