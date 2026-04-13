package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newSAMLMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newSAMLAPIClient(t *testing.T, base string) *SAMLChecker {
	t.Helper()
	return NewSAMLChecker(base, "test-token", nil)
}

func TestGetSAMLRole_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"ttl":     "1h",
			"max_ttl": "24h",
			"token_policies": []string{"default"},
		},
	}
	srv := newSAMLMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	c := newSAMLAPIClient(t, srv.URL)
	role, err := c.GetSAMLRole("saml", "my-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.TTL != "1h" {
		t.Errorf("expected TTL '1h', got %q", role.TTL)
	}
	if role.MaxTTL != "24h" {
		t.Errorf("expected MaxTTL '24h', got %q", role.MaxTTL)
	}
}

func TestGetSAMLRole_ErrorOnEmptyMountOrRole(t *testing.T) {
	c := NewSAMLChecker("http://localhost", "tok", nil)
	_, err := c.GetSAMLRole("", "role")
	if err == nil {
		t.Fatal("expected error for empty mount")
	}
	_, err = c.GetSAMLRole("mount", "")
	if err == nil {
		t.Fatal("expected error for empty role")
	}
}

func TestGetSAMLRole_ErrorOnBadStatus(t *testing.T) {
	srv := newSAMLMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	c := newSAMLAPIClient(t, srv.URL)
	_, err := c.GetSAMLRole("saml", "my-role")
	if err == nil {
		t.Fatal("expected error on 403 status")
	}
}
