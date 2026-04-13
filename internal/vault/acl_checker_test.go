package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newACLMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newACLAPIClient(baseURL string) *ACLChecker {
	return NewACLChecker(http.DefaultClient, baseURL, "test-token")
}

func TestLookupAccessor_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"accessor":     "abc123",
			"display_name": "my-token",
			"policies":     []string{"default", "admin"},
			"orphan":       false,
			"expire_time":  "2099-01-01T00:00:00Z",
		},
	}
	srv := newACLMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := newACLAPIClient(srv.URL)
	info, err := checker.LookupAccessor("abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Accessor != "abc123" {
		t.Errorf("expected accessor abc123, got %s", info.Accessor)
	}
	if info.DisplayName != "my-token" {
		t.Errorf("expected display_name my-token, got %s", info.DisplayName)
	}
	if len(info.Policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(info.Policies))
	}
}

func TestLookupAccessor_ErrorOnEmptyAccessor(t *testing.T) {
	checker := newACLAPIClient("http://localhost")
	_, err := checker.LookupAccessor("")
	if err == nil {
		t.Fatal("expected error for empty accessor")
	}
}

func TestLookupAccessor_ErrorOnBadStatus(t *testing.T) {
	srv := newACLMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := newACLAPIClient(srv.URL)
	_, err := checker.LookupAccessor("some-accessor")
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
}
