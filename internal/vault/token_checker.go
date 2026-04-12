package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// TokenInfo holds metadata about the current Vault token.
type TokenInfo struct {
	ID          string
	DisplayName string
	Policies    []string
	ExpireTime  time.Time
	Renewable   bool
	TTL         int
}

// TokenChecker inspects the current Vault token via the /auth/token/lookup-self endpoint.
type TokenChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewTokenChecker constructs a TokenChecker using the provided HTTP client, address, and token.
func NewTokenChecker(client *http.Client, address, token string) *TokenChecker {
	return &TokenChecker{client: client, base: address, token: token}
}

// LookupSelf returns TokenInfo for the token currently configured on the checker.
func (tc *TokenChecker) LookupSelf(ctx context.Context) (*TokenInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tc.base+"/v1/auth/token/lookup-self", nil)
	if err != nil {
		return nil, fmt.Errorf("token checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", tc.token)

	resp, err := tc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token checker: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token checker: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Data struct {
			ID          string   `json:"id"`
			DisplayName string   `json:"display_name"`
			Policies    []string `json:"policies"`
			ExpireTime  string   `json:"expire_time"`
			Renewable   bool     `json:"renewable"`
			TTL         int      `json:"ttl"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("token checker: decode response: %w", err)
	}

	var expiry time.Time
	if body.Data.ExpireTime != "" {
		expiry, _ = time.Parse(time.RFC3339, body.Data.ExpireTime)
	}

	return &TokenInfo{
		ID:          body.Data.ID,
		DisplayName: body.Data.DisplayName,
		Policies:    body.Data.Policies,
		ExpireTime:  expiry,
		Renewable:   body.Data.Renewable,
		TTL:         body.Data.TTL,
	}, nil
}
