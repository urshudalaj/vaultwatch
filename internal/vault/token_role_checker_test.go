package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newTokenRoleMockServer(t *testing.T, roleName string, payload interface{}, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/v1/auth/token/roles/" + roleName
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

func newTokenRoleAPIClient(serverURL, token string) *vault.TokenRoleChecker {
	return vault.NewTokenRoleChecker(http.DefaultClient, serverURL, token)
}

func TestGetTokenRole_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"token_ttl":     3600,
			"token_max_ttl": 86400,
			"orphan":        true,
			"renewable":     true,
		},
	}
	srv := newTokenRoleMockServer(t, "myrole", payload, http.StatusOK)
	defer srv.Close()

	checker := newTokenRoleAPIClient(srv.URL, "test-token")
	info, err := checker.GetTokenRole("myrole")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name != "myrole" {
		t.Errorf("expected name %q, got %q", "myrole", info.Name)
	}
	if info.TokenTTL != 3600 {
		t.Errorf("expected TokenTTL 3600, got %d", info.TokenTTL)
	}
	if !info.Orphan {
		t.Error("expected Orphan to be true")
	}
}

func TestGetTokenRole_ErrorOnEmptyName(t *testing.T) {
	checker := newTokenRoleAPIClient("http://localhost", "tok")
	_, err := checker.GetTokenRole("")
	if err == nil {
		t.Fatal("expected error for empty role name")
	}
}

func TestGetTokenRole_ErrorOnBadStatus(t *testing.T) {
	srv := newTokenRoleMockServer(t, "badrole", nil, http.StatusForbidden)
	defer srv.Close()

	checker := newTokenRoleAPIClient(srv.URL, "tok")
	_, err := checker.GetTokenRole("badrole")
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
}
