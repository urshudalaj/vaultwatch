package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// GroupInfo holds identity group metadata returned by Vault.
type GroupInfo struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Policies []string `json:"policies"`
	Disabled bool     `json:"disabled"`
}

// GroupChecker fetches identity group details from Vault.
type GroupChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewGroupChecker returns a GroupChecker using the provided API client fields.
func NewGroupChecker(client *http.Client, baseURL, token string) *GroupChecker {
	return &GroupChecker{client: client, base: baseURL, token: token}
}

// GetGroup retrieves an identity group by ID.
func (g *GroupChecker) GetGroup(id string) (*GroupInfo, error) {
	if id == "" {
		return nil, fmt.Errorf("group id must not be empty")
	}

	url := fmt.Sprintf("%s/v1/identity/group/id/%s", g.base, id)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", g.token)

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for group %s", resp.StatusCode, id)
	}

	var envelope struct {
		Data GroupInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, err
	}
	return &envelope.Data, nil
}
