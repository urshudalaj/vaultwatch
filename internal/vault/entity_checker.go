package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// EntityInfo holds identity entity metadata returned by Vault.
type EntityInfo struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Disabled bool     `json:"disabled"`
	Policies []string `json:"policies"`
}

// EntityChecker lists and inspects Vault identity entities.
type EntityChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewEntityChecker constructs an EntityChecker using the provided Vault client.
func NewEntityChecker(base, token string, client *http.Client) *EntityChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &EntityChecker{client: client, base: base, token: token}
}

// ListEntities returns the IDs of all identity entities.
func (e *EntityChecker) ListEntities() ([]string, error) {
	req, err := http.NewRequest("LIST", e.base+"/v1/identity/entity/id", nil)
	if err != nil {
		return nil, fmt.Errorf("entity list request: %w", err)
	}
	req.Header.Set("X-Vault-Token", e.token)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("entity list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("entity list: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("entity list decode: %w", err)
	}
	return body.Data.Keys, nil
}

// GetEntity retrieves details for a single entity by ID.
func (e *EntityChecker) GetEntity(id string) (*EntityInfo, error) {
	if id == "" {
		return nil, fmt.Errorf("entity id must not be empty")
	}
	req, err := http.NewRequest(http.MethodGet, e.base+"/v1/identity/entity/id/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("entity get request: %w", err)
	}
	req.Header.Set("X-Vault-Token", e.token)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("entity get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("entity get: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Data EntityInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("entity get decode: %w", err)
	}
	return &body.Data, nil
}
