package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newPassthroughMockServer(t *testing.T, status int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func newPassthroughAPIClient(srv *httptest.Server) *PassthroughChecker {
	return NewPassthroughChecker(srv.Client(), srv.URL, "test-token")
}

func TestGetMount_ReturnsInfo(t *testing.T) {
	srv := newPassthroughMockServer(t, http.StatusOK, map[string]interface{}{
		"default_ttl":   3600,
		"max_ttl":       7200,
		"force_no_cache": false,
	})
	defer srv.Close()

	checker := newPassthroughAPIClient(srv)
	info, err := checker.GetMount("secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.DefaultTTL != 3600 {
		t.Errorf("expected DefaultTTL 3600, got %d", info.DefaultTTL)
	}
	if info.MaxTTL != 7200 {
		t.Errorf("expected MaxTTL 7200, got %d", info.MaxTTL)
	}
	if info.Mount != "secret" {
		t.Errorf("expected mount 'secret', got %q", info.Mount)
	}
}

func TestGetMount_ErrorOnEmptyMount(t *testing.T) {
	srv := newPassthroughMockServer(t, http.StatusOK, nil)
	defer srv.Close()

	checker := newPassthroughAPIClient(srv)
	_, err := checker.GetMount("")
	if err == nil {
		t.Fatal("expected error for empty mount, got nil")
	}
}

func TestGetMount_ErrorOnBadStatus(t *testing.T) {
	srv := newPassthroughMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := newPassthroughAPIClient(srv)
	_, err := checker.GetMount("secret")
	if err == nil {
		t.Fatal("expected error for non-200 status, got nil")
	}
}
