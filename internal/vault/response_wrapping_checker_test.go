package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newResponseWrappingMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestLookupResponseWrapping_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"creation_time":    time.Now().UTC().Format(time.RFC3339),
			"creation_path":    "auth/token/create",
			"creation_ttl":    300,
			"wrapped_accessor": "abc123",
		},
	}
	srv := newResponseWrappingMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := vault.NewResponseWrappingChecker(srv.URL, "test-token", nil)
	info, err := checker.Lookup(t.Context(), "wrapping-token-value")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.CreationPath != "auth/token/create" {
		t.Errorf("expected creation_path=auth/token/create, got %s", info.CreationPath)
	}
	if info.TTL != 300 {
		t.Errorf("expected TTL=300, got %d", info.TTL)
	}
}

func TestLookupResponseWrapping_ErrorOnEmptyToken(t *testing.T) {
	checker := vault.NewResponseWrappingChecker("http://localhost", "test-token", nil)
	_, err := checker.Lookup(t.Context(), "")
	if err == nil {
		t.Fatal("expected error for empty wrapping token")
	}
}

func TestLookupResponseWrapping_ErrorOnBadStatus(t *testing.T) {
	srv := newResponseWrappingMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := vault.NewResponseWrappingChecker(srv.URL, "bad-token", nil)
	_, err := checker.Lookup(t.Context(), "some-token")
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}
