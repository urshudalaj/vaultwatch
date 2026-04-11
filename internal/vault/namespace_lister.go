package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// NamespaceLister lists Vault namespaces via the sys/namespaces API.
type NamespaceLister struct {
	client *http.Client
	baseURL string
	token   string
}

// NamespaceInfo holds metadata about a single Vault namespace.
type NamespaceInfo struct {
	Path string
	ID   string
}

// NewNamespaceLister creates a NamespaceLister using the provided HTTP client,
// Vault base URL, and auth token.
func NewNamespaceLister(client *http.Client, baseURL, token string) *NamespaceLister {
	return &NamespaceLister{
		client:  client,
		baseURL: baseURL,
		token:   token,
	}
}

// ListNamespaces returns all namespaces visible under the root namespace.
func (n *NamespaceLister) ListNamespaces() ([]NamespaceInfo, error) {
	url := fmt.Sprintf("%s/v1/sys/namespaces", n.baseURL)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("namespace lister: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", n.token)
	req.Header.Set("X-Vault-Request", "true")

	resp, err := n.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("namespace lister: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("namespace lister: unexpected status %d", resp.StatusCode)
	}

	var payload struct {
		Data map[string]struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("namespace lister: decode response: %w", err)
	}

	result := make([]NamespaceInfo, 0, len(payload.Data))
	for path, meta := range payload.Data {
		result = append(result, NamespaceInfo{Path: path, ID: meta.ID})
	}
	return result, nil
}
