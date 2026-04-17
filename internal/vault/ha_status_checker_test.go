package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newHAStatusMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
}

func TestCheckHAStatus_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"ha_enabled":     true,
		"is_self":        true,
		"leader_address": "https://vault.example.com:8200",
		"cluster_name":   "vault-cluster",
		"cluster_id":     "abc-123",
	}
	srv := newHAStatusMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := NewHAStatusChecker(srv.URL, "test-token", nil)
	info, err := checker.CheckHAStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.HAEnabled {
		t.Error("expected HAEnabled to be true")
	}
	if info.ClusterName != "vault-cluster" {
		t.Errorf("expected cluster_name vault-cluster, got %s", info.ClusterName)
	}
	if info.LeaderAddr != "https://vault.example.com:8200" {
		t.Errorf("unexpected leader address: %s", info.LeaderAddr)
	}
}

func TestCheckHAStatus_ErrorOnBadStatus(t *testing.T) {
	srv := newHAStatusMockServer(t, http.StatusInternalServerError, nil)
	defer srv.Close()

	checker := NewHAStatusChecker(srv.URL, "test-token", nil)
	_, err := checker.CheckHAStatus()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCheckHAStatus_ErrorOnInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	checker := NewHAStatusChecker(srv.URL, "test-token", nil)
	_, err := checker.CheckHAStatus()
	if err == nil {
		t.Fatal("expected error on invalid JSON, got nil")
	}
}
