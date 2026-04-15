package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// TokenTTLInfo holds the remaining TTL and creation time of a token.
type TokenTTLInfo struct {
	TTL         int    `json:"ttl"`
	CreationTTL int    `json:"creation_ttl"`
	DisplayName string `json:"display_name"`
	ExpireTime  string `json:"expire_time"`
}

// TokenTTLChecker queries Vault for the remaining TTL of a token by accessor.
type TokenTTLChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewTokenTTLChecker creates a new TokenTTLChecker.
func NewTokenTTLChecker(base, token string, client *http.Client) *TokenTTLChecker {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &TokenTTLChecker{client: client, base: base, token: token}
}

// LookupTokenTTL returns the TTL info for the given token accessor.
func (c *TokenTTLChecker) LookupTokenTTL(accessor string) (*TokenTTLInfo, error) {
	if accessor == "" {
		return nil, fmt.Errorf("accessor must not be empty")
	}

	url := fmt.Sprintf("%s/v1/auth/token/lookup-accessor", c.base)
	body := fmt.Sprintf(`{"accessor":%q}`, accessor)

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
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

	var wrapper struct {
		Data TokenTTLInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &wrapper.Data, nil
}
