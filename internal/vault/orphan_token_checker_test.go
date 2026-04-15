package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newOrphanTokenMockServer(t *testing.T, accessor string, orphan bool, ttl int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req["accessor"] == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"accessor":     accessor,
				"display_name": "test-token",
				"orphan":       orphan,
				"ttl":          ttl,
				"expire_time":  "2099-01-01T00:00:00Z",
			},
		})
	}))
}

func newOrphanTokenAPIClient(srv *httptest.Server) *OrphanTokenChecker {
	return NewOrphanTokenChecker(srv.URL, "test-token", srv.Client())
}

func TestLookupOrphanToken_ReturnsInfo(t *testing.T) {
	srv := newOrphanTokenMockServer(t, "abc123", true, 3600)
	defer srv.Close()
	c := newOrphanTokenAPIClient(srv)

	info, err := c.LookupByAccessor("abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Accessor != "abc123" {
		t.Errorf("expected accessor abc123, got %s", info.Accessor)
	}
	if !info.Orphan {
		t.Error("expected orphan=true")
	}
	if info.TTL != 3600 {
		t.Errorf("expected ttl=3600, got %d", info.TTL)
	}
}

func TestLookupOrphanToken_ErrorOnEmptyAccessor(t *testing.T) {
	srv := newOrphanTokenMockServer(t, "", false, 0)
	defer srv.Close()
	c := newOrphanTokenAPIClient(srv)

	_, err := c.LookupByAccessor("")
	if err == nil {
		t.Fatal("expected error for empty accessor")
	}
}

func TestLookupOrphanToken_ErrorOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	c := NewOrphanTokenChecker(srv.URL, "bad-token", srv.Client())

	_, err := c.LookupByAccessor("someaccessor")
	if err == nil {
		t.Fatal("expected error on non-OK status")
	}
}
