package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTokenTTLMockServer(t *testing.T, ttl int, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"ttl":          ttl,
				"creation_ttl": 3600,
				"display_name": "test-token",
				"expire_time":  "2099-01-01T00:00:00Z",
			},
		})
	}))
}

func newTokenTTLAPIClient(srv *httptest.Server) *TokenTTLChecker {
	return NewTokenTTLChecker(srv.URL, "test-token", srv.Client())
}

func TestLookupTokenTTL_ReturnsInfo(t *testing.T) {
	srv := newTokenTTLMockServer(t, 1800, http.StatusOK)
	defer srv.Close()

	checker := newTokenTTLAPIClient(srv)
	info, err := checker.LookupTokenTTL("test-accessor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.TTL != 1800 {
		t.Errorf("expected TTL 1800, got %d", info.TTL)
	}
	if info.DisplayName != "test-token" {
		t.Errorf("expected display_name 'test-token', got %q", info.DisplayName)
	}
}

func TestLookupTokenTTL_ErrorOnEmptyAccessor(t *testing.T) {
	srv := newTokenTTLMockServer(t, 0, http.StatusOK)
	defer srv.Close()

	checker := newTokenTTLAPIClient(srv)
	_, err := checker.LookupTokenTTL("")
	if err == nil {
		t.Fatal("expected error for empty accessor, got nil")
	}
}

func TestLookupTokenTTL_ErrorOnBadStatus(t *testing.T) {
	srv := newTokenTTLMockServer(t, 0, http.StatusForbidden)
	defer srv.Close()

	checker := newTokenTTLAPIClient(srv)
	_, err := checker.LookupTokenTTL("some-accessor")
	if err == nil {
		t.Fatal("expected error on non-200 status, got nil")
	}
}
