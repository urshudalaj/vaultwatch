package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// WrappingInfo holds metadata about a wrapped token response.
type WrappingInfo struct {
	Token          string `json:"token"`
	Accessor       string `json:"accessor"`
	TTL            int    `json:"ttl"`
	CreationTime   string `json:"creation_time"`
	CreationPath   string `json:"creation_path"`
	WrappedAccessor string `json:"wrapped_accessor"`
}

// WrappingChecker looks up wrapping token metadata from Vault.
type WrappingChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewWrappingChecker constructs a WrappingChecker using the provided HTTP client.
func NewWrappingChecker(client *http.Client, baseURL, token string) *WrappingChecker {
	return &WrappingChecker{client: client, base: baseURL, token: token}
}

// LookupWrappingToken calls /v1/sys/wrapping/lookup to inspect a wrapping token.
func (w *WrappingChecker) LookupWrappingToken(ctx context.Context, wrappingToken string) (*WrappingInfo, error) {
	if wrappingToken == "" {
		return nil, fmt.Errorf("wrapping token must not be empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.base+"/v1/sys/wrapping/lookup", nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-Vault-Token", wrappingToken)

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from wrapping lookup", resp.StatusCode)
	}

	var envelope struct {
		Data WrappingInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &envelope.Data, nil
}
