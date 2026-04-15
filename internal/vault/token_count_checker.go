package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// TokenCountInfo holds token count metrics from Vault.
type TokenCountInfo struct {
	ServiceTokens int `json:"service_tokens"`
	BatchTokens   int `json:"batch_tokens"`
	Total         int `json:"total"`
}

// TokenCountChecker retrieves token count information from Vault.
type TokenCountChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewTokenCountChecker creates a new TokenCountChecker.
func NewTokenCountChecker(baseURL, token string, client *http.Client) *TokenCountChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &TokenCountChecker{
		client:  client,
		baseURL: baseURL,
		token:   token,
	}
}

// GetTokenCount fetches the current token count from Vault.
func (c *TokenCountChecker) GetTokenCount() (*TokenCountInfo, error) {
	url := fmt.Sprintf("%s/v1/auth/token/count", c.baseURL)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("token count checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token count checker: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token count checker: unexpected status %d", resp.StatusCode)
	}

	var envelope struct {
		Data TokenCountInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("token count checker: decode response: %w", err)
	}

	info := envelope.Data
	info.Total = info.ServiceTokens + info.BatchTokens
	return &info, nil
}
