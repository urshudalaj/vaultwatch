package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// LoginRecord represents a single auth log entry from Vault.
type LoginRecord struct {
	Accessor  string    `json:"accessor"`
	Path      string    `json:"path"`
	CreatedAt time.Time `json:"creation_time"`
	ExpireAt  time.Time `json:"expire_time"`
	Meta      map[string]string `json:"meta"`
}

// LoginChecker fetches recent auth token accessor records from Vault.
type LoginChecker struct {
	client *http.Client
	base   string
	token  string
}

// NewLoginChecker creates a LoginChecker using the provided HTTP client, base URL, and token.
func NewLoginChecker(client *http.Client, baseURL, token string) *LoginChecker {
	return &LoginChecker{
		client: client,
		base:   baseURL,
		token:  token,
	}
}

// ListLogins returns a slice of LoginRecord for the given auth mount path.
// It calls GET /v1/auth/<mount>/accessors then reads each accessor.
func (lc *LoginChecker) ListLogins(ctx context.Context, mount string) ([]LoginRecord, error) {
	url := fmt.Sprintf("%s/v1/auth/%s/accessors", lc.base, mount)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("login checker: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", lc.token)

	resp, err := lc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login checker: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("login checker: unexpected status %d for mount %q", resp.StatusCode, mount)
	}

	var payload struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("login checker: decode accessors: %w", err)
	}

	var records []LoginRecord
	for _, accessor := range payload.Data.Keys {
		rec, err := lc.lookupAccessor(ctx, accessor)
		if err != nil {
			continue // skip unreadable accessors
		}
		records = append(records, rec)
	}
	return records, nil
}

func (lc *LoginChecker) lookupAccessor(ctx context.Context, accessor string) (LoginRecord, error) {
	url := fmt.Sprintf("%s/v1/auth/token/lookup-accessor", lc.base)
	body := fmt.Sprintf(`{"accessor":%q}`, accessor)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		stringsReader(body))
	if err != nil {
		return LoginRecord{}, err
	}
	req.Header.Set("X-Vault-Token", lc.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := lc.client.Do(req)
	if err != nil {
		return LoginRecord{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return LoginRecord{}, fmt.Errorf("accessor %s: status %d", accessor, resp.StatusCode)
	}

	var out struct {
		Data LoginRecord `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return LoginRecord{}, err
	}
	return out.Data, nil
}
