package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newLDAPMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newLDAPAPIClient(t *testing.T, baseURL string) *LDAPChecker {
	t.Helper()
	return NewLDAPChecker(baseURL, "test-token", nil)
}

func TestGetLDAPRole_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"role_name":     "my-role",
			"creation_ldif": "dn: ...",
			"deletion_ldif": "dn: ...",
			"default_ttl":   "1h",
			"max_ttl":       "24h",
		},
	}
	srv := newLDAPMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := newLDAPAPIClient(t, srv.URL)
	role, err := checker.GetRole("ldap", "my-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.RoleName != "my-role" {
		t.Errorf("expected role_name 'my-role', got %q", role.RoleName)
	}
	if role.DefaultTTL != "1h" {
		t.Errorf("expected default_ttl '1h', got %q", role.DefaultTTL)
	}
	if role.MaxTTL != "24h" {
		t.Errorf("expected max_ttl '24h', got %q", role.MaxTTL)
	}
}

func TestGetLDAPRole_ErrorOnEmptyMountOrRole(t *testing.T) {
	checker := NewLDAPChecker("http://localhost", "token", nil)

	_, err := checker.GetRole("", "role")
	if err == nil {
		t.Fatal("expected error for empty mount")
	}
	_, err = checker.GetRole("ldap", "")
	if err == nil {
		t.Fatal("expected error for empty role")
	}
}

func TestGetLDAPRole_ErrorOnBadStatus(t *testing.T) {
	srv := newLDAPMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := newLDAPAPIClient(t, srv.URL)
	_, err := checker.GetRole("ldap", "my-role")
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
}
