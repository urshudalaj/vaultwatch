package vault

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ACLInfo holds information about a Vault ACL token accessor.
type ACLInfo struct {
	Accessor    string   `json:"accessor"`
	DisplayName string   `json:"display_name"`
	Policies    []string `json:"policies"`
	Orphan      bool     `json:"orphan"`
	ExpireTime  string   `json:"expire_time"`
}

// ACLChecker checks ACL token accessor details via the Vault API.
type ACLChecker struct {
	client  *http.Client
	baseURL string
	token   string
}

// NewACLChecker creates a new ACLChecker.
func NewACLChecker(client *http.Client, baseURL, token string) *ACLChecker {
	return &ACLChecker{client: client, baseURL: baseURL, token: token}
}

// LookupAccessor fetches ACL info for the given token accessor.
func (a *ACLChecker) LookupAccessor(accessor string) (*ACLInfo, error) {
	if accessor == "" {
		return nil, fmt.Errorf("accessor must not be empty")
	}

	url := fmt.Sprintf("%s/v1/auth/token/lookup-accessor", a.baseURL)
	body := fmt.Sprintf(`{"accessor":%q}`, accessor)

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", a.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lookup accessor: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var wrapper struct {
		Data ACLInfo `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &wrapper.Data, nil
}
