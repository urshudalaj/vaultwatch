package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wernerstrydom/vaultwatch/internal/vault"
)

func newMaintenanceMockServer(t *testing.T, status int, payload any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestCheckMaintenance_ReturnsInfo(t *testing.T) {
	payload := map[string]any{
		"data": map[string]any{
			"enabled":       true,
			"message":       "scheduled downtime",
			"request_count": 42,
		},
	}
	srv := newMaintenanceMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	c := vault.NewMaintenanceChecker(srv.URL, "test-token", nil)
	info, err := c.CheckMaintenance()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.Enabled {
		t.Errorf("expected Enabled=true, got false")
	}
	if info.Message != "scheduled downtime" {
		t.Errorf("unexpected message: %s", info.Message)
	}
	if info.RequestCount != 42 {
		t.Errorf("unexpected request_count: %d", info.RequestCount)
	}
}

func TestCheckMaintenance_ErrorOnBadStatus(t *testing.T) {
	srv := newMaintenanceMockServer(t, http.StatusInternalServerError, nil)
	defer srv.Close()

	c := vault.NewMaintenanceChecker(srv.URL, "test-token", nil)
	_, err := c.CheckMaintenance()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCheckMaintenance_ErrorOnInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	c := vault.NewMaintenanceChecker(srv.URL, "test-token", nil)
	_, err := c.CheckMaintenance()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
