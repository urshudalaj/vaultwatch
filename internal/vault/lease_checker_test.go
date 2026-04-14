package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newLeaseCheckerMockServer(t *testing.T, status int, payload interface{}) (*httptest.Server, *LeaseChecker) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
	t.Cleanup(ts.Close)
	checker := NewLeaseChecker(ts.Client(), ts.URL, "test-token")
	return ts, checker
}

func TestLookupLease_ReturnsInfo(t *testing.T) {
	expireTime := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"id":          "database/creds/my-role/abc123",
			"renewable":   true,
			"ttl":         600,
			"expire_time": expireTime,
		},
	}
	_, checker := newLeaseCheckerMockServer(t, http.StatusOK, payload)

	info, err := checker.LookupLease("database/creds/my-role/abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.LeaseID != "database/creds/my-role/abc123" {
		t.Errorf("expected lease ID, got %q", info.LeaseID)
	}
	if !info.Renewable {
		t.Error("expected renewable to be true")
	}
	if info.LeaseDuration != 600*time.Second {
		t.Errorf("expected 600s duration, got %v", info.LeaseDuration)
	}
	if info.ExpireTime.IsZero() {
		t.Error("expected non-zero expire time")
	}
}

func TestLookupLease_ErrorOnEmptyLeaseID(t *testing.T) {
	_, checker := newLeaseCheckerMockServer(t, http.StatusOK, nil)
	_, err := checker.LookupLease("")
	if err == nil {
		t.Fatal("expected error for empty lease ID")
	}
}

func TestLookupLease_ErrorOnBadStatus(t *testing.T) {
	_, checker := newLeaseCheckerMockServer(t, http.StatusForbidden, nil)
	_, err := checker.LookupLease("some/lease/id")
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
}
