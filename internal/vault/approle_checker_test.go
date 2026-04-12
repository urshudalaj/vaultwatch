package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newAppRoleMockServer(t *testing.T, mount, role string, payload interface{}, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/v1/auth/" + mount + "/role/" + role
		if r.URL.Path != expected {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newAppRoleAPIClient(baseURL, token string) *vault.AppRoleChecker {
	return vault.NewAppRoleChecker(http.DefaultClient, baseURL, token)
}

func TestGetAppRole_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"role_id":       "test-role-id",
			"secret_id_ttl": "1h",
			"token_ttl":     "30m",
			"token_max_ttl": "2h",
			"bind_secret_id": true,
		},
	}
	srv := newAppRoleMockServer(t, "approle", "my-role", payload, http.StatusOK)
	defer srv.Close()

	checker := newAppRoleAPIClient(srv.URL, "test-token")
	info, err := checker.GetRole("approle", "my-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.RoleID != "test-role-id" {
		t.Errorf("expected role_id 'test-role-id', got %q", info.RoleID)
	}
	if info.SecretIDTTL != "1h" {
		t.Errorf("expected secret_id_ttl '1h', got %q", info.SecretIDTTL)
	}
	if !info.Enabled {
		t.Error("expected bind_secret_id to be true")
	}
}

func TestGetAppRole_ErrorOnEmptyMountOrRole(t *testing.T) {
	checker := newAppRoleAPIClient("http://localhost", "tok")

	if _, err := checker.GetRole("", "role"); err == nil {
		t.Error("expected error for empty mount")
	}
	if _, err := checker.GetRole("mount", ""); err == nil {
		t.Error("expected error for empty role")
	}
}

func TestGetAppRole_ErrorOnBadStatus(t *testing.T) {
	srv := newAppRoleMockServer(t, "approle", "missing", nil, http.StatusNotFound)
	defer srv.Close()

	checker := newAppRoleAPIClient(srv.URL, "tok")
	_, err := checker.GetRole("approle", "missing")
	if err == nil {
		t.Fatal("expected error on 404 status")
	}
}
