package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newReplicationMockServer(t *testing.T, statusCode int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestCheckReplication_ReturnsStatus(t *testing.T) {
	body := map[string]interface{}{
		"data": map[string]interface{}{
			"dr": map[string]string{"mode": "primary", "state": "running"},
			"performance": map[string]string{"mode": "disabled", "state": ""},
		},
	}
	srv := newReplicationMockServer(t, http.StatusOK, body)
	defer srv.Close()

	checker := vault.NewReplicationChecker(srv.URL, "test-token", nil)
	status, err := checker.CheckReplication(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.DRMode != "primary" {
		t.Errorf("expected DRMode=primary, got %s", status.DRMode)
	}
	if status.DRState != "running" {
		t.Errorf("expected DRState=running, got %s", status.DRState)
	}
	if status.PerformanceMode != "disabled" {
		t.Errorf("expected PerformanceMode=disabled, got %s", status.PerformanceMode)
	}
}

func TestCheckReplication_ErrorOnBadStatus(t *testing.T) {
	srv := newReplicationMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := vault.NewReplicationChecker(srv.URL, "bad-token", nil)
	_, err := checker.CheckReplication(context.Background())
	if err == nil {
		t.Fatal("expected error on forbidden status")
	}
}

func TestCheckReplication_ErrorOnInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	checker := vault.NewReplicationChecker(srv.URL, "token", nil)
	_, err := checker.CheckReplication(context.Background())
	if err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}
