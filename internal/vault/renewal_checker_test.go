package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newRenewalMockServer(t *testing.T, leaseID string, renewable bool, ttl, maxTTL int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/leases/lookup" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id":        leaseID,
				"renewable": renewable,
				"ttl":       ttl,
				"max_ttl":   maxTTL,
			},
		})
	}))
}

func TestCheckRenewal_ReturnsInfo(t *testing.T) {
	srv := newRenewalMockServer(t, "lease/abc123", true, 3600, 86400)
	defer srv.Close()

	c := NewRenewalChecker(srv.URL, "test-token", srv.Client())
	info, err := c.CheckRenewal("lease/abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.LeaseID != "lease/abc123" {
		t.Errorf("expected lease ID 'lease/abc123', got %q", info.LeaseID)
	}
	if !info.Renewable {
		t.Error("expected renewable to be true")
	}
	if info.TTL != 3600 {
		t.Errorf("expected TTL 3600, got %d", info.TTL)
	}
	if info.MaxTTL != 86400 {
		t.Errorf("expected MaxTTL 86400, got %d", info.MaxTTL)
	}
}

func TestCheckRenewal_ErrorOnEmptyLeaseID(t *testing.T) {
	c := NewRenewalChecker("http://localhost", "token", nil)
	_, err := c.CheckRenewal("")
	if err == nil {
		t.Fatal("expected error for empty lease ID")
	}
}

func TestCheckRenewal_ErrorOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewRenewalChecker(srv.URL, "token", srv.Client())
	_, err := c.CheckRenewal("lease/xyz")
	if err == nil {
		t.Fatal("expected error on bad status")
	}
}
