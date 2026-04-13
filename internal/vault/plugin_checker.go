package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// PluginInfo holds metadata about a registered Vault plugin.
type PluginInfo struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Version string `json:"version"`
	Builtin bool   `json:"builtin"`
}

// pluginListResponse mirrors the Vault API response for listing plugins.
type pluginListResponse struct {
	Data struct {
		Detailed []PluginInfo `json:"detailed"`
	} `json:"data"`
}

// PluginChecker lists registered plugins from Vault.
type PluginChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewPluginChecker creates a PluginChecker using the provided HTTP client.
func NewPluginChecker(client *http.Client, baseURL, token string) *PluginChecker {
	return &PluginChecker{client: client, base: baseURL, token: token}
}

// ListPlugins returns all registered plugins of the given type ("auth", "secret", "database", or "unknown").
func (p *PluginChecker) ListPlugins(pluginType string) ([]PluginInfo, error) {
	if pluginType == "" {
		return nil, fmt.Errorf("plugin type must not be empty")
	}

	url := fmt.Sprintf("%s/v1/sys/plugins/catalog/%s", p.base, pluginType)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-Vault-Token", p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for plugin type %q", resp.StatusCode, pluginType)
	}

	var result pluginListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return result.Data.Detailed, nil
}
