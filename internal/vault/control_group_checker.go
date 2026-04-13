package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ControlGroupRequest represents a Vault control group request.
type ControlGroupRequest struct {
	ID          string `json:"id"`
	RequestPath string `json:"request_path"`
	Approved    bool   `json:"approved"`
	RequestEntity struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"request_entity"`
}

// ControlGroupChecker checks the status of control group requests.
type ControlGroupChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewControlGroupChecker returns a new ControlGroupChecker.
func NewControlGroupChecker(base, token string, client *http.Client) *ControlGroupChecker {
	if client == nil {
		client = http.DefaultClient
	}
	return &ControlGroupChecker{client: client, base: base, token: token}
}

// CheckRequest looks up a control group request by accessor token.
func (c *ControlGroupChecker) CheckRequest(ctx context.Context, accessor string) (*ControlGroupRequest, error) {
	if accessor == "" {
		return nil, fmt.Errorf("accessor must not be empty")
	}

	url := fmt.Sprintf("%s/v1/sys/control-group/request", c.base)
	body := fmt.Sprintf(`{"accessor":%q}`, accessor)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var wrapper struct {
		Data ControlGroupRequest `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &wrapper.Data, nil
}
