package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// PassthroughInfo holds metadata about a passthrough secret backend mount.
type PassthroughInfo struct {
	Mount       string
	DefaultTTL  int `json:"default_ttl"`
	MaxTTL      int `json:"max_ttl"`
	ForceNoCache bool `json:"force_no_cache"`
}

// PassthroughChecker reads configuration for a passthrough (generic) secret
// engine mount from Vault's sys/mounts endpoint.
type PassthroughChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewPassthroughChecker returns a PassthroughChecker backed by the given HTTP
// client, Vault address and token.
func NewPassthroughChecker(client *http.Client, baseURL, token string) *PassthroughChecker {
	return &PassthroughChecker{client: client, base: baseURL, token: token}
}

// GetMount fetches the tuning configuration of the named passthrough mount.
func (p *PassthroughChecker) GetMount(mount string) (*PassthroughInfo, error) {
	if mount == "" {
		return nil, fmt.Errorf("passthrough checker: mount must not be empty")
	}

	url := fmt.Sprintf("%s/v1/sys/mounts/%s/tune", p.base, mount)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("passthrough checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("passthrough checker: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("passthrough checker: unexpected status %d for mount %q", resp.StatusCode, mount)
	}

	var info PassthroughInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("passthrough checker: decode: %w", err)
	}
	info.Mount = mount
	return &info, nil
}
