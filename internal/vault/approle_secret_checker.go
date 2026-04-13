package vault

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// AppRoleSecretInfo holds metadata about an AppRole secret ID.
type AppRoleSecretInfo struct {
	SecretIDAccessor string `json:"secret_id_accessor"`
	CreationTime     string `json:"creation_time"`
	ExpirationTime   string `json:"expiration_time"`
	LastUpdatedTime  string `json:"last_updated_time"`
	TTL              int    `json:"secret_id_ttl"`
}

// AppRoleSecretChecker looks up metadata for an AppRole secret ID accessor.
type AppRoleSecretChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewAppRoleSecretChecker creates a new AppRoleSecretChecker.
func NewAppRoleSecretChecker(client *http.Client, baseURL, token string) *AppRoleSecretChecker {
	return &AppRoleSecretChecker{client: client, base: baseURL, token: token}
}

// LookupSecretID fetches metadata for the given AppRole secret ID accessor.
func (c *AppRoleSecretChecker) LookupSecretID(mount, roleID, accessor string) (*AppRoleSecretInfo, error) {
	if mount == "" || roleID == "" || accessor == "" {
		return nil, fmt.Errorf("mount, roleID, and accessor must not be empty")
	}

	url := fmt.Sprintf("%s/v1/auth/%s/role/%s/secret-id-accessor/lookup", c.base, mount, roleID)
	body := fmt.Sprintf(`{"secret_id_accessor":%q}`, accessor)

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var envelope struct {
		Data AppRoleSecretInfo `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &envelope.Data, nil
}
