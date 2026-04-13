package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// GitHubRole holds configuration for a GitHub auth role.
type GitHubRole struct {
	Organization string   `json:"organization"`
	Teams        []string `json:"teams"`
	Policies     []string `json:"policies"`
	TTL          string   `json:"ttl"`
	MaxTTL       string   `json:"max_ttl"`
}

// GitHubChecker retrieves GitHub auth role configuration from Vault.
type GitHubChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewGitHubChecker creates a new GitHubChecker.
func NewGitHubChecker(base, token string, client *http.Client) *GitHubChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &GitHubChecker{client: client, base: base, token: token}
}

// GetConfig returns the GitHub auth configuration for the given mount.
func (g *GitHubChecker) GetConfig(mount string) (*GitHubRole, error) {
	if mount == "" {
		return nil, fmt.Errorf("mount must not be empty")
	}
	url := fmt.Sprintf("%s/v1/auth/%s/config", g.base, mount)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", g.token)
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	var wrapper struct {
		Data GitHubRole `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, err
	}
	return &wrapper.Data, nil
}
