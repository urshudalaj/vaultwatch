package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newRADIUSMockServer(t *testing.T, mount, role string, payload interface{}, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/v1/auth/" + mount + "/users/" + role
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

func newRADIUSAPIClient(t *testing.T, base string) *vault.RADIUSChecker {
	t.Helper()
	return vault.NewRADIUSChecker(base, "test-token", nil)
}

func TestGetRADIUSRole_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"policies": []string{"default"},
			"ttl":      "1h",
			"max_ttl":  "24h",
		},
	}
	srv := newRADIUSMockServer(t, "radius", "alice", payload, http.StatusOK)
	defer srv.Close()

	checker := newRADIUSAPIClient(t, srv.URL)
	role, err := checker.GetRADIUSRole("radius", "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.TTL != "1h" {
		t.Errorf("expected ttl 1h, got %s", role.TTL)
	}
	if role.MaxTTL != "24h" {
		t.Errorf("expected max_ttl 24h, got %s", role.MaxTTL)
	}
}

func TestGetRADIUSRole_ErrorOnEmptyMountOrRole(t *testing.T) {
	checker := vault.NewRADIUSChecker("http://localhost", "tok", nil)
	_, err := checker.GetRADIUSRole("", "alice")
	if err == nil {
		t.Fatal("expected error for empty mount")
	}
	_, err = checker.GetRADIUSRole("radius", "")
	if err == nil {
		t.Fatal("expected error for empty role")
	}
}

func TestGetRADIUSRole_ErrorOnBadStatus(t *testing.T) {
	srv := newRADIUSMockServer(t, "radius", "alice", nil, http.StatusForbidden)
	defer srv.Close()

	checker := newRADIUSAPIClient(t, srv.URL)
	_, err := checker.GetRADIUSRole("radius", "alice")
	if err == nil {
		t.Fatal("expected error on 403 response")
	}
}
