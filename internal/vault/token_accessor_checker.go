package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// TokenAccessorInfo holds metadata about a token looked up by accessor.
type TokenAccessorInfo struct {
	Accessor    string
	DisplayName string
	Policies    []string
	ExpireTime  string
	CreationTTL int
	TTL         int
}

// TokenAccessorChecker looks up token metadata by accessor via the Vault API.
type TokenAccessorChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewTokenAccessorChecker creates a new TokenAccessorChecker.
func NewTokenAccessorChecker(baseURL, token string, client *http.Client) *TokenAccessorChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &TokenAccessorChecker{client: client, baseURL: baseURL, token: token}
}

// LookupByAccessor retrieves token info for the given accessor.
func (c *TokenAccessorChecker) LookupByAccessor(accessor string) (*TokenAccessorInfo, error) {
	if accessor == "" {
		return nil, fmt.Errorf("accessor must not be empty")
	}

	body := fmt.Sprintf(`{"accessor":%q}`, accessor)
	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/v1/auth/token/lookup-accessor", stringReader(body))
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
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var out struct {
		Data struct {
			Accessor    string   `json:"accessor"`
			DisplayName string   `json:"display_name"`
			Policies    []string `json:"policies"`
			ExpireTime  string   `json:"expire_time"`
			CreationTTL int      `json:"creation_ttl"`
			TTL         int      `json:"ttl"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &TokenAccessorInfo{
		Accessor:    out.Data.Accessor,
		DisplayName: out.Data.DisplayName,
		Policies:    out.Data.Policies,
		ExpireTime:  out.Data.ExpireTime,
		CreationTTL: out.Data.CreationTTL,
		TTL:         out.Data.TTL,
	}, nil
}
