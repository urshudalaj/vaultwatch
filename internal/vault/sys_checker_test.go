package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/watcher/vaultwatch/internal/vault"
)

func newSysMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newSysAPIClient(baseURL string) *vault.SysChecker {
	return vault.NewSysChecker(http.DefaultClient, baseURL, "test-token")
}

func TestGetSysInfo_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"cluster_name": "vault-cluster-a",
		"cluster_id":   "abc-123",
		"version":      "1.15.0",
		"build_date":   "2024-01-01",
	}
	srv := newSysMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := newSysAPIClient(srv.URL)
	info, err := checker.GetSysInfo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ClusterName != "vault-cluster-a" {
		t.Errorf("expected cluster_name 'vault-cluster-a', got %q", info.ClusterName)
	}
	if info.Version != "1.15.0" {
		t.Errorf("expected version '1.15.0', got %q", info.Version)
	}
}

func TestGetSysInfo_ErrorOnBadStatus(t *testing.T) {
	srv := newSysMockServer(t, http.StatusInternalServerError, nil)
	defer srv.Close()

	checker := newSysAPIClient(srv.URL)
	_, err := checker.GetSysInfo()
	if err == nil {
		t.Fatal("expected error on 500 response, got nil")
	}
}

func TestGetSysInfo_ErrorOnInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	checker := newSysAPIClient(srv.URL)
	_, err := checker.GetSysInfo()
	if err == nil {
		t.Fatal("expected error on invalid JSON, got nil")
	}
}
