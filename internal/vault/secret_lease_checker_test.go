package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newSecretLeaseMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newSecretLeaseAPIClient(t *testing.T, srv *httptest.Server) *SecretLeaseChecker {
	t.Helper()
	return NewSecretLeaseChecker(srv.Client(), srv.URL, "test-token")
}

func TestCheckLease_ReturnsInfo(t *testing.T) {
	expire := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"id":         "database/creds/my-role/abc123",
			"renewable":  true,
			"ttl":        7200,
			"expire_time": expire,
		},
	}
	srv := newSecretLeaseMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := newSecretLeaseAPIClient(t, srv)
	info, err := checker.CheckLease("database/creds/my-role/abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.LeaseID != "database/creds/my-role/abc123" {
		t.Errorf("expected lease ID, got %q", info.LeaseID)
	}
	if !info.Renewable {
		t.Error("expected renewable to be true")
	}
	if info.LeaseDuration != 7200*time.Second {
		t.Errorf("unexpected duration: %v", info.LeaseDuration)
	}
	if info.ExpireTime.IsZero() {
		t.Error("expected non-zero expire time")
	}
}

func TestCheckLease_ErrorOnEmptyLeaseID(t *testing.T) {
	srv := newSecretLeaseMockServer(t, http.StatusOK, nil)
	defer srv.Close()

	checker := newSecretLeaseAPIClient(t, srv)
	_, err := checker.CheckLease("")
	if err == nil {
		t.Fatal("expected error for empty lease ID")
	}
}

func TestCheckLease_ErrorOnBadStatus(t *testing.T) {
	srv := newSecretLeaseMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := newSecretLeaseAPIClient(t, srv)
	_, err := checker.CheckLease("some/lease/id")
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
}
