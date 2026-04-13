package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newUserpassMockServer(t *testing.T, status int, role *UserpassRole) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": role})
	}))
}

func newUserpassAPIClient(t *testing.T, srv *httptest.Server) *UserpassChecker {
	t.Helper()
	return NewUserpassChecker(srv.URL, "test-token", srv.Client())
}

func TestGetUserpassRole_ReturnsInfo(t *testing.T) {
	expected := &UserpassRole{
		TokenTTL:    "1h",
		TokenMaxTTL: "24h",
		TokenPolicies: []string{"default"},
	}
	srv := newUserpassMockServer(t, http.StatusOK, expected)
	defer srv.Close()

	c := newUserpassAPIClient(t, srv)
	role, err := c.GetUserpassRole("userpass", "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.TokenTTL != expected.TokenTTL {
		t.Errorf("TokenTTL: got %q, want %q", role.TokenTTL, expected.TokenTTL)
	}
	if role.TokenMaxTTL != expected.TokenMaxTTL {
		t.Errorf("TokenMaxTTL: got %q, want %q", role.TokenMaxTTL, expected.TokenMaxTTL)
	}
}

func TestGetUserpassRole_ErrorOnEmptyMountOrRole(t *testing.T) {
	c := NewUserpassChecker("http://localhost", "tok", nil)

	if _, err := c.GetUserpassRole("", "alice"); err == nil {
		t.Error("expected error for empty mount")
	}
	if _, err := c.GetUserpassRole("userpass", ""); err == nil {
		t.Error("expected error for empty username")
	}
}

func TestGetUserpassRole_ErrorOnBadStatus(t *testing.T) {
	srv := newUserpassMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	c := newUserpassAPIClient(t, srv)
	_, err := c.GetUserpassRole("userpass", "alice")
	if err == nil {
		t.Fatal("expected error on 403 response")
	}
}
