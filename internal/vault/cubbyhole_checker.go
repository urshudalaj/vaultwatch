package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// CubbyholeInfo holds metadata about a cubbyhole secret path.
type CubbyholeInfo struct {
	Path string
	Keys []string
}

// CubbyholeChecker reads keys stored in a token's cubbyhole.
type CubbyholeChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewCubbyholeChecker creates a CubbyholeChecker using the provided HTTP client.
func NewCubbyholeChecker(client *http.Client, baseURL, token string) *CubbyholeChecker {
	return &CubbyholeChecker{client: client, base: baseURL, token: token}
}

// ListKeys returns the keys stored at the given cubbyhole path.
func (c *CubbyholeChecker) ListKeys(path string) (*CubbyholeInfo, error) {
	if path == "" {
		return nil, fmt.Errorf("cubbyhole path must not be empty")
	}

	url := fmt.Sprintf("%s/v1/cubbyhole/%s?list=true", c.base, path)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for cubbyhole/%s", resp.StatusCode, path)
	}

	var payload struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &CubbyholeInfo{
		Path: path,
		Keys: payload.Data.Keys,
	}, nil
}
