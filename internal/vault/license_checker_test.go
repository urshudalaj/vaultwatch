package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newLicenseMockServer(t *testing.T, status int, payload any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newLicenseAPIClient(srv *httptest.Server) *vault.LicenseChecker {
	return vault.NewLicenseChecker(srv.Client(), srv.URL, "test-token")
}

func TestGetLicense_ReturnsInfo(t *testing.T) {
	expiry := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	payload := map[string]any{
		"data": map[string]any{
			"license_id":      "lic-abc-123",
			"customer_name":   "Acme Corp",
			"expiration_time": expiry.Format(time.RFC3339),
			"terminated":      false,
			"features":        []string{"HSM", "Replication"},
		},
	}
	srv := newLicenseMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := newLicenseAPIClient(srv)
	info, err := checker.GetLicense()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.LicenseID != "lic-abc-123" {
		t.Errorf("expected license_id 'lic-abc-123', got %q", info.LicenseID)
	}
	if info.CustomerName != "Acme Corp" {
		t.Errorf("expected customer_name 'Acme Corp', got %q", info.CustomerName)
	}
	if len(info.Features) != 2 {
		t.Errorf("expected 2 features, got %d", len(info.Features))
	}
}

func TestGetLicense_ErrorOnBadStatus(t *testing.T) {
	srv := newLicenseMockServer(t, http.StatusInternalServerError, nil)
	defer srv.Close()

	checker := newLicenseAPIClient(srv)
	_, err := checker.GetLicense()
	if err == nil {
		t.Fatal("expected error on non-200 status, got nil")
	}
}

func TestGetLicense_ErrorOnInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	checker := vault.NewLicenseChecker(srv.Client(), srv.URL, "tok")
	_, err := checker.GetLicense()
	if err == nil {
		t.Fatal("expected error on invalid JSON, got nil")
	}
}
