package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newOIDCMockServer(t *testing.T, mount, role string, payload map[string]any, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/v1/auth/" + mount + "/role/" + role
		if r.URL.Path != expected {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": payload})
		}
	}))
}

func newOIDCAPIClient(t *testing.T, srv *httptest.Server) *OIDCChecker {
	t.Helper()
	return NewOIDCChecker(srv.URL, "test-token", srv.Client())
}

func TestGetOIDCRole_ReturnsInfo(t *testing.T) {
	srv := newOIDCMockServer(t, "oidc", "webapp", map[string]any{
		"ttl":         "1h",
		"max_ttl":     "24h",
		"user_claim":  "sub",
		"bound_audiences": []string{"https://example.com"},
	}, http.StatusOK)
	defer srv.Close()
	c := newOIDCAPIClient(t, srv)
	role, err := c.GetOIDCRole("oidc", "webapp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.TTL != "1h" {
		t.Errorf("expected ttl=1h, got %s", role.TTL)
	}
	if role.MaxTTL != "24h" {
		t.Errorf("expected max_ttl=24h, got %s", role.MaxTTL)
	}
	if role.UserClaim != "sub" {
		t.Errorf("expected user_claim=sub, got %s", role.UserClaim)
	}
	if role.RoleName != "webapp" {
		t.Errorf("expected role name webapp, got %s", role.RoleName)
	}
}

func TestGetOIDCRole_ErrorOnEmptyMountOrRole(t *testing.T) {
	c := NewOIDCChecker("http://localhost", "tok", nil)
	if _, err := c.GetOIDCRole("", "role"); err == nil {
		t.Error("expected error for empty mount")
	}
	if _, err := c.GetOIDCRole("mount", ""); err == nil {
		t.Error("expected error for empty role")
	}
}

func TestGetOIDCRole_ErrorOnBadStatus(t *testing.T) {
	srv := newOIDCMockServer(t, "oidc", "missing", nil, http.StatusForbidden)
	defer srv.Close()
	c := newOIDCAPIClient(t, srv)
	if _, err := c.GetOIDCRole("oidc", "missing"); err == nil {
		t.Error("expected error on 403")
	}
}
