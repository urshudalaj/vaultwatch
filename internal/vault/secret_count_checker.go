package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// SecretCountInfo holds the count of secrets at a given KV mount path.
type SecretCountInfo struct {
	Mount      string
	TotalKeys  int
	Subfolders int
}

// SecretCountChecker checks the number of secrets under a KV mount.
type SecretCountChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewSecretCountChecker creates a new SecretCountChecker.
func NewSecretCountChecker(baseURL, token string, client *http.Client) *SecretCountChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &SecretCountChecker{client: client, baseURL: baseURL, token: token}
}

// CountSecrets lists keys at the given KV v2 mount metadata path and returns counts.
func (c *SecretCountChecker) CountSecrets(mount string) (*SecretCountInfo, error) {
	if mount == "" {
		return nil, fmt.Errorf("mount path must not be empty")
	}

	url := fmt.Sprintf("%s/v1/%s/metadata?list=true", c.baseURL, mount)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for mount %q", resp.StatusCode, mount)
	}

	var body struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	info := &SecretCountInfo{Mount: mount}
	for _, k := range body.Data.Keys {
		if len(k) > 0 && k[len(k)-1] == '/' {
			info.Subfolders++
		} else {
			info.TotalKeys++
		}
	}
	return info, nil
}
