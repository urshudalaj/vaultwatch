package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newJWTMockServer(t *testing.T, mount, role string, payload any, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/v1/auth/" + mount + "/role/" + role
		if r.URL.Path != expected {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newJWTAPIClient(srv *httptest.Server) (*http.Client, string, string) {
	return srv.Client(), srv.URL, "test-token"
}

func TestGetJWTRole_ReturnsInfo(t *testing.T) {
	payload := map[string]any{
		"data": map[string]any{
			"bound_audiences": []string{"https://example.com"},
			"token_ttl":       3600,
			"token_max_ttl":   7200,
			"token_policies":  []string{"default"},
		},
	}
	srv := newJWTMockServer(t, "jwt", "myrole", payload, http.StatusOK)
	defer srv.Close()

	c, base, tok := newJWTAPIClient(srv)
	checker := NewJWTChecker(c, base, tok)
	role, err := checker.GetRole("jwt", "myrole")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.Name != "myrole" {
		t.Errorf("expected name 'myrole', got %q", role.Name)
	}
	if role.TokenTTL != 3600 {
		t.Errorf("expected token_ttl 3600, got %d", role.TokenTTL)
	}
}

func TestGetJWTRole_ErrorOnEmptyMountOrRole(t *testing.T) {
	checker := NewJWTChecker(http.DefaultClient, "http://localhost", "tok")
	_, err := checker.GetRole("", "role")
	if err == nil {
		t.Fatal("expected error for empty mount")
	}
	_, err = checker.GetRole("jwt", "")
	if err == nil {
		t.Fatal("expected error for empty role")
	}
}

func TestGetJWTRole_ErrorOnBadStatus(t *testing.T) {
	srv := newJWTMockServer(t, "jwt", "missing", nil, http.StatusForbidden)
	defer srv.Close()

	c, base, tok := newJWTAPIClient(srv)
	checker := NewJWTChecker(c, base, tok)
	_, err := checker.GetRole("jwt", "missing")
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
}
