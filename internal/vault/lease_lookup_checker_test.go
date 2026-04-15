package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newLeaseLookupMockServer(t *testing.T, leaseID string, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/v1/sys/leases/lookup" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(statusCode)
		if statusCode == http.StatusOK {
			payload := map[string]interface{}{
				"data": map[string]interface{}{
					"id":          leaseID,
					"renewable":   true,
					"ttl":         3600,
					"issue_time":  time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
					"expire_time": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
				},
			}
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestLookupLease_ReturnsInfo(t *testing.T) {
	leaseID := "database/creds/my-role/abc123"
	srv := newLeaseLookupMockServer(t, leaseID, http.StatusOK)
	defer srv.Close()

	checker := vault.NewLeaseLookupChecker(srv.URL, "test-token", srv.Client())
	info, err := checker.LookupLease(leaseID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.LeaseID != leaseID {
		t.Errorf("expected lease ID %q, got %q", leaseID, info.LeaseID)
	}
	if info.TTL != 3600 {
		t.Errorf("expected TTL 3600, got %d", info.TTL)
	}
	if !info.Renewable {
		t.Error("expected renewable to be true")
	}
}

func TestLookupLease_ErrorOnEmptyLeaseID(t *testing.T) {
	checker := vault.NewLeaseLookupChecker("http://localhost", "token", nil)
	_, err := checker.LookupLease("")
	if err == nil {
		t.Fatal("expected error for empty lease ID, got nil")
	}
}

func TestLookupLease_ErrorOnBadStatus(t *testing.T) {
	srv := newLeaseLookupMockServer(t, "", http.StatusForbidden)
	defer srv.Close()

	checker := vault.NewLeaseLookupChecker(srv.URL, "bad-token", srv.Client())
	_, err := checker.LookupLease("some/lease/id")
	if err == nil {
		t.Fatal("expected error for non-200 status, got nil")
	}
}
