package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newEGPMockServer(t *testing.T, name string, policy vault.EGPPolicy, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/v1/sys/policies/egp/" + name
		if r.URL.Path != expected {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": policy})
		}
	}))
}

func newEGPAPIClient(t *testing.T, srv *httptest.Server) *vault.EGPChecker {
	t.Helper()
	return vault.NewEGPChecker(srv.Client(), srv.URL, "test-token")
}

func TestGetEGP_ReturnsInfo(t *testing.T) {
	policy := vault.EGPPolicy{
		Name:             "allow-finance",
		Paths:            []string{"secret/finance/*"},
		EnforcementLevel: "hard-mandatory",
		Code:             `main = rule { true }`,
	}
	srv := newEGPMockServer(t, "allow-finance", policy, http.StatusOK)
	defer srv.Close()

	checker := newEGPAPIClient(t, srv)
	got, err := checker.GetEGP("allow-finance")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != policy.Name {
		t.Errorf("expected name %q, got %q", policy.Name, got.Name)
	}
	if got.EnforcementLevel != policy.EnforcementLevel {
		t.Errorf("expected enforcement_level %q, got %q", policy.EnforcementLevel, got.EnforcementLevel)
	}
}

func TestGetEGP_ReturnsPaths(t *testing.T) {
	policy := vault.EGPPolicy{
		Name:             "allow-finance",
		Paths:            []string{"secret/finance/*", "secret/shared/*"},
		EnforcementLevel: "soft-mandatory",
		Code:             `main = rule { true }`,
	}
	srv := newEGPMockServer(t, "allow-finance", policy, http.StatusOK)
	defer srv.Close()

	checker := newEGPAPIClient(t, srv)
	got, err := checker.GetEGP("allow-finance")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Paths) != len(policy.Paths) {
		t.Fatalf("expected %d paths, got %d", len(policy.Paths), len(got.Paths))
	}
	for i, p := range policy.Paths {
		if got.Paths[i] != p {
			t.Errorf("expected path[%d] %q, got %q", i, p, got.Paths[i])
		}
	}
}

func TestGetEGP_ErrorOnEmptyName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	checker := vault.NewEGPChecker(srv.Client(), srv.URL, "tok")
	_, err := checker.GetEGP("")
	if err == nil {
		t.Fatal("expected error for empty name, got nil")
	}
}

func TestGetEGP_ErrorOnBadStatus(t *testing.T) {
	policy := vault.EGPPolicy{Name: "deny-all"}
	srv := newEGPMockServer(t, "deny-all", policy, http.StatusForbidden)
	defer srv.Close()

	checker := newEGPAPIClient(t, srv)
	_, err := checker.GetEGP("deny-all")
	if err == nil {
		t.Fatal("expected error for non-200 status, got nil")
	}
}
