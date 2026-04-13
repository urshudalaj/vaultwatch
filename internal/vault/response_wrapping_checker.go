package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ResponseWrappingInfo holds metadata about a response-wrapping token.
type ResponseWrappingInfo struct {
	CreationTime   time.Time `json:"creation_time"`
	CreationPath   string    `json:"creation_path"`
	TTL            int       `json:"creation_ttl"`
	WrappedAccessor string   `json:"wrapped_accessor"`
}

// ResponseWrappingChecker queries Vault for response-wrapping token metadata.
type ResponseWrappingChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewResponseWrappingChecker creates a ResponseWrappingChecker.
func NewResponseWrappingChecker(base, token string, client *http.Client) *ResponseWrappingChecker {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &ResponseWrappingChecker{client: client, base: base, token: token}
}

// Lookup retrieves wrapping token info for the given wrapping token value.
func (c *ResponseWrappingChecker) Lookup(ctx context.Context, wrappingToken string) (*ResponseWrappingInfo, error) {
	if wrappingToken == "" {
		return nil, fmt.Errorf("wrapping token must not be empty")
	}

	url := fmt.Sprintf("%s/v1/sys/wrapping/lookup", c.base)
	body := fmt.Sprintf(`{"token":%q}`, wrappingToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var out struct {
		Data ResponseWrappingInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out.Data, nil
}
