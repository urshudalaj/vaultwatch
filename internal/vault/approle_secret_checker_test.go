package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newAppRoleSecretMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newAppRoleSecretAPIClient(baseURL string) *AppRoleSecretChecker {
	return NewAppRoleSecretChecker(http.DefaultClient, baseURL, "test-token")
}

func TestLookupSecretID_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"secret_id_accessor": "abc123",
			"creation_time":      "2024-01-01T00:00:00Z",
			"expiration_time":    "2025-01-01T00:00:00Z",
			"secret_id_ttl":      3600,
		},
	}
	srv := newAppRoleSecretMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	c := newAppRoleSecretAPIClient(srv.URL)
	info, err := c.LookupSecretID("approle", "my-role", "abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.SecretIDAccessor != "abc123" {
		t.Errorf("expected accessor abc123, got %s", info.SecretIDAccessor)
	}
	if info.TTL != 3600 {
		t.Errorf("expected TTL 3600, got %d", info.TTL)
	}
}

func TestLookupSecretID_ErrorOnEmptyParams(t *testing.T) {
	c := newAppRoleSecretAPIClient("http://localhost")
	_, err := c.LookupSecretID("", "role", "acc")
	if err == nil {
		t.Fatal("expected error for empty mount")
	}
}

func TestLookupSecretID_ErrorOnBadStatus(t *testing.T) {
	srv := newAppRoleSecretMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	c := newAppRoleSecretAPIClient(srv.URL)
	_, err := c.LookupSecretID("approle", "my-role", "bad-acc")
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}
