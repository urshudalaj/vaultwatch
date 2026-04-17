package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// KVMetadata holds metadata for a KV v2 secret.
type KVMetadata struct {
	Path            string
	CurrentVersion  int
	OldestVersion   int
	CreatedTime     time.Time
	UpdatedTime     time.Time
	MaxVersions     int
	DeleteVersionAfter string
}

// KVMetadataChecker reads KV v2 secret metadata from Vault.
type KVMetadataChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewKVMetadataChecker creates a new KVMetadataChecker.
func NewKVMetadataChecker(base, token string, client *http.Client) *KVMetadataChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &KVMetadataChecker{client: client, base: base, token: token}
}

// GetMetadata fetches metadata for a KV v2 secret at mount/path.
func (c *KVMetadataChecker) GetMetadata(mount, path string) (*KVMetadata, error) {
	if mount == "" || path == "" {
		return nil, fmt.Errorf("mount and path must not be empty")
	}
	url := fmt.Sprintf("%s/v1/%s/metadata/%s", c.base, mount, path)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			CurrentVersion int    `json:"current_version"`
			OldestVersion  int    `json:"oldest_version"`
			CreatedTime    string `json:"created_time"`
			UpdatedTime    string `json:"updated_time"`
			MaxVersions    int    `json:"max_versions"`
			DeleteVersionAfter string `json:"delete_version_after"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	created, _ := time.Parse(time.RFC3339Nano, body.Data.CreatedTime)
	updated, _ := time.Parse(time.RFC3339Nano, body.Data.UpdatedTime)
	return &KVMetadata{
		Path:               path,
		CurrentVersion:     body.Data.CurrentVersion,
		OldestVersion:      body.Data.OldestVersion,
		CreatedTime:        created,
		UpdatedTime:        updated,
		MaxVersions:        body.Data.MaxVersions,
		DeleteVersionAfter: body.Data.DeleteVersionAfter,
	}, nil
}
