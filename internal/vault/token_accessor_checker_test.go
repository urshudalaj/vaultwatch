package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTokenAccessorMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/lookup-accessor" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newTokenAccessorAPIClient(baseURL string) *TokenAccessorChecker {
	return NewTokenAccessorChecker(baseURL, "test-token", nil)
}

func TestLookupByAccessor_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"accessor":     "abc123",
			"display_name": "token-test",
			"policies":     []string{"default", "admin"},
			"expire_time":  "2099-01-01T00:00:00Z",
			"creation_ttl": 3600,
			"ttl":          1800,
		},
	}
	srv := newTokenAccessorMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := newTokenAccessorAPIClient(srv.URL)
	info, err := checker.LookupByAccessor("abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Accessor != "abc123" {
		t.Errorf("expected accessor abc123, got %s", info.Accessor)
	}
	if info.DisplayName != "token-test" {
		t.Errorf("expected display_name token-test, got %s", info.DisplayName)
	}
	if len(info.Policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(info.Policies))
	}
	if info.TTL != 1800 {
		t.Errorf("expected ttl 1800, got %d", info.TTL)
	}
}

func TestLookupByAccessor_ErrorOnEmptyAccessor(t *testing.T) {
	checker := NewTokenAccessorChecker("http://localhost", "tok", nil)
	_, err := checker.LookupByAccessor("")
	if err == nil {
		t.Fatal("expected error for empty accessor")
	}
}

func TestLookupByAccessor_ErrorOnBadStatus(t *testing.T) {
	srv := newTokenAccessorMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := newTokenAccessorAPIClient(srv.URL)
	_, err := checker.LookupByAccessor("someaccessor")
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
}
