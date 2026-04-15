package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// OrphanTokenInfo holds metadata about an orphan token.
type OrphanTokenInfo struct {
	Accessor    string
	DisplayName string
	Orphan      bool
	TTL         int
	ExpireTime  string
}

// OrphanTokenChecker lists and inspects orphan tokens via the Vault API.
type OrphanTokenChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewOrphanTokenChecker creates a new OrphanTokenChecker.
func NewOrphanTokenChecker(base, token string, client *http.Client) *OrphanTokenChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &OrphanTokenChecker{client: client, base: base, token: token}
}

// LookupByAccessor returns OrphanTokenInfo for the given accessor.
func (c *OrphanTokenChecker) LookupByAccessor(accessor string) (*OrphanTokenInfo, error) {
	if accessor == "" {
		return nil, fmt.Errorf("accessor must not be empty")
	}
	url := fmt.Sprintf("%s/v1/auth/token/lookup-accessor", c.base)
	body, err := jsonPost(c.client, url, c.token, map[string]string{"accessor": accessor})
	if err != nil {
		return nil, fmt.Errorf("lookup accessor: %w", err)
	}
	var resp struct {
		Data struct {
			Accessor    string `json:"accessor"`
			DisplayName string `json:"display_name"`
			Orphan      bool   `json:"orphan"`
			TTL         int    `json:"ttl"`
			ExpireTime  string `json:"expire_time"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &OrphanTokenInfo{
		Accessor:    resp.Data.Accessor,
		DisplayName: resp.Data.DisplayName,
		Orphan:      resp.Data.Orphan,
		TTL:         resp.Data.TTL,
		ExpireTime:  resp.Data.ExpireTime,
	}, nil
}
