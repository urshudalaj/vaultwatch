package vault

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// SecretVersionInfo holds metadata about a KV v2 secret version.
type SecretVersionInfo struct {
	Path          string
	CurrentVersion int
	OldestVersion  int
	MaxVersions    int
	VersionCount   int
}

// SecretVersionChecker reads KV v2 secret metadata from Vault.
type SecretVersionChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewSecretVersionChecker creates a new SecretVersionChecker.
func NewSecretVersionChecker(base, token string, client *http.Client) *SecretVersionChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &SecretVersionChecker{client: client, base: base, token: token}
}

// GetSecretVersionInfo fetches version metadata for a KV v2 secret.
func (s *SecretVersionChecker) GetSecretVersionInfo(mount, path string) (*SecretVersionInfo, error) {
	if mount == "" || path == "" {
		return nil, fmt.Errorf("mount and path must not be empty")
	}
	url := fmt.Sprintf("%s/v1/%s/metadata/%s", s.base, mount, path)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for %s/%s", resp.StatusCode, mount, path)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Data struct {
			CurrentVersion int            `json:"current_version"`
			OldestVersion  int            `json:"oldest_version"`
			MaxVersions    int            `json:"max_versions"`
			Versions       map[string]any `json:"versions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return &SecretVersionInfo{
		Path:           path,
		CurrentVersion: payload.Data.CurrentVersion,
		OldestVersion:  payload.Data.OldestVersion,
		MaxVersions:    payload.Data.MaxVersions,
		VersionCount:   len(payload.Data.Versions),
	}, nil
}
