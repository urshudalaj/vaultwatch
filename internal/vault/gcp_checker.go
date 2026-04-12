package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// GCPRoleInfo holds metadata about a GCP secrets engine role.
type GCPRoleInfo struct {
	Name        string `json:"name"`
	SecretType  string `json:"secret_type"`
	Project     string `json:"project"`
	TokenScopes []string `json:"token_scopes"`
	TTL         string `json:"ttl"`
	MaxTTL      string `json:"max_ttl"`
}

// GCPChecker reads GCP roleset information from Vault.
type GCPChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewGCPChecker creates a new GCPChecker.
func NewGCPChecker(base, token string, client *http.Client) *GCPChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &GCPChecker{client: client, base: base, token: token}
}

// GetRoleset retrieves information about a GCP roleset from the given mount.
func (g *GCPChecker) GetRoleset(mount, roleset string) (*GCPRoleInfo, error) {
	if mount == "" || roleset == "" {
		return nil, fmt.Errorf("gcp: mount and roleset must not be empty")
	}
	url := fmt.Sprintf("%s/v1/%s/roleset/%s", g.base, mount, roleset)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("gcp: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", g.token)

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gcp: http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcp: unexpected status %d", resp.StatusCode)
	}

	var wrapper struct {
		Data GCPRoleInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("gcp: decode response: %w", err)
	}
	return &wrapper.Data, nil
}
