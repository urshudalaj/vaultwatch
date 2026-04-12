package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newPKIMockServer(t *testing.T, mount, role string, payload interface{}, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/v1/" + mount + "/roles/" + role
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

func TestGetRole_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"max_ttl":         "8760h",
			"ttl":             "720h",
			"allowed_domains": []string{"example.com"},
		},
	}
	srv := newPKIMockServer(t, "pki", "web", payload, http.StatusOK)
	defer srv.Close()

	checker := vault.NewPKIChecker(srv.URL, "test-token", srv.Client())
	info, err := checker.GetRole("pki", "web")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.MaxTTL != "8760h" {
		t.Errorf("expected max_ttl 8760h, got %s", info.MaxTTL)
	}
	if info.TTL != "720h" {
		t.Errorf("expected ttl 720h, got %s", info.TTL)
	}
	if len(info.AllowedDomains) != 1 || info.AllowedDomains[0] != "example.com" {
		t.Errorf("unexpected allowed_domains: %v", info.AllowedDomains)
	}
}

func TestGetRole_ErrorOnEmptyMountOrRole(t *testing.T) {
	checker := vault.NewPKIChecker("http://localhost", "token", nil)
	_, err := checker.GetRole("", "web")
	if err == nil {
		t.Error("expected error for empty mount")
	}
	_, err = checker.GetRole("pki", "")
	if err == nil {
		t.Error("expected error for empty role")
	}
}

func TestGetRole_ErrorOnBadStatus(t *testing.T) {
	srv := newPKIMockServer(t, "pki", "web", nil, http.StatusForbidden)
	defer srv.Close()

	checker := vault.NewPKIChecker(srv.URL, "bad-token", srv.Client())
	_, err := checker.GetRole("pki", "web")
	if err == nil {
		t.Error("expected error on non-200 status")
	}
}
