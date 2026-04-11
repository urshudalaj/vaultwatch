package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// MountInfo holds metadata about a Vault secrets engine mount.
type MountInfo struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Accessor    string `json:"accessor"`
}

// MountLister lists secrets engine mounts from Vault.
type MountLister struct {
	client *http.Client
	baseURL string
	token   string
}

// NewMountLister creates a MountLister using the provided API client fields.
func NewMountLister(baseURL, token string, client *http.Client) *MountLister {
	if client == nil {
		client = http.DefaultClient
	}
	return &MountLister{
		client:  client,
		baseURL: baseURL,
		token:   token,
	}
}

// ListMounts returns a map of mount path to MountInfo for all enabled mounts.
func (m *MountLister) ListMounts(ctx context.Context) (map[string]MountInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.baseURL+"/v1/sys/mounts", nil)
	if err != nil {
		return nil, fmt.Errorf("mount lister: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", m.token)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mount lister: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mount lister: unexpected status %d", resp.StatusCode)
	}

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("mount lister: decode response: %w", err)
	}

	mounts := make(map[string]MountInfo)
	for key, val := range raw {
		var info MountInfo
		if err := json.Unmarshal(val, &info); err != nil {
			continue
		}
		if info.Type != "" {
			mounts[key] = info
		}
	}
	return mounts, nil
}
