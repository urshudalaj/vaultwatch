package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newRenewServer(t *testing.T, leaseDuration int, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/v1/sys/renew" {
			w.WriteHeader(statusCode)
			if statusCode == http.StatusOK {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"lease_id":       "secret/data/myapp/db/abc123",
					"lease_duration": leaseDuration,
					"renewable":      true,
				})
			}
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"initialized": true})
	}))
}

func TestRenew_Success(t *testing.T) {
	srv := newRenewServer(t, 3600, http.StatusOK)
	defer srv.Close()

	client, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	renewer := NewLeaseRenewer(client)
	res := renewer.Renew(context.Background(), "secret/data/myapp/db/abc123", 0)

	if res.Err != nil {
		t.Fatalf("expected no error, got %v", res.Err)
	}
	if res.NewTTL != 3600*time.Second {
		t.Errorf("expected TTL 3600s, got %v", res.NewTTL)
	}
	if res.LeaseID != "secret/data/myapp/db/abc123" {
		t.Errorf("unexpected leaseID: %q", res.LeaseID)
	}
}

func TestRenew_EmptyLeaseID(t *testing.T) {
	srv := newRenewServer(t, 3600, http.StatusOK)
	defer srv.Close()

	client, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	renewer := NewLeaseRenewer(client)
	res := renewer.Renew(context.Background(), "", 0)

	if res.Err == nil {
		t.Fatal("expected error for empty leaseID, got nil")
	}
}

func TestRenewMany_AllSucceed(t *testing.T) {
	srv := newRenewServer(t, 7200, http.StatusOK)
	defer srv.Close()

	client, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	renewer := NewLeaseRenewer(client)
	ids := []string{"lease/a", "lease/b", "lease/c"}
	results := renewer.RenewMany(context.Background(), ids, 30*time.Minute)

	if len(results) != len(ids) {
		t.Fatalf("expected %d results, got %d", len(ids), len(results))
	}
	for i, res := range results {
		if res.Err != nil {
			t.Errorf("result[%d] unexpected error: %v", i, res.Err)
		}
	}
}
