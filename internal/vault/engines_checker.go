package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// EngineInfo holds metadata about a mounted secrets engine.
type EngineInfo struct {
	Path        string
	Type        string
	Description string
	Options     map[string]string
}

// EnginesChecker lists and inspects mounted secrets engines.
type EnginesChecker struct {
	client *http.Client
	baseURL string
	token   string
}

// NewEnginesChecker creates a new EnginesChecker.
func NewEnginesChecker(baseURL, token string, client *http.Client) *EnginesChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &EnginesChecker{client: client, baseURL: baseURL, token: token}
}

// ListEngines returns all mounted secrets engines.
func (e *EnginesChecker) ListEngines() ([]EngineInfo, error) {
	url := fmt.Sprintf("%s/v1/sys/mounts", e.baseURL)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("engines checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", e.token)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("engines checker: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("engines checker: unexpected status %d", resp.StatusCode)
	}

	var raw map[string]struct {
		Type        string            `json:"type"`
		Description string            `json:"description"`
		Options     map[string]string `json:"options"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("engines checker: decode response: %w", err)
	}

	var engines []EngineInfo
	for path, info := range raw {
		if info.Type == "" {
			continue
		}
		engines = append(engines, EngineInfo{
			Path:        path,
			Type:        info.Type,
			Description: info.Description,
			Options:     info.Options,
		})
	}
	return engines, nil
}
