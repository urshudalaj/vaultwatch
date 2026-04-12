package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newWrappingMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestLookupWrappingToken_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"token":           "s.wrappedtoken",
			"accessor":        "acc123",
			"ttl":             300,
			"creation_time":   "2024-01-01T00:00:00Z",
			"creation_path":   "auth/token/create",
			"wrapped_accessor": "wacc456",
		},
	}
	srv := newWrappingMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := vault.NewWrappingChecker(srv.Client(), srv.URL, "root")
	info, err := checker.LookupWrappingToken(context.Background(), "s.wrappedtoken")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Accessor != "acc123" {
		t.Errorf("expected accessor acc123, got %s", info.Accessor)
	}
	if info.TTL != 300 {
		t.Errorf("expected TTL 300, got %d", info.TTL)
	}
}

func TestLookupWrappingToken_ErrorOnEmptyToken(t *testing.T) {
	checker := vault.NewWrappingChecker(http.DefaultClient, "http://localhost", "root")
	_, err := checker.LookupWrappingToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty wrapping token")
	}
}

func TestLookupWrappingToken_ErrorOnBadStatus(t *testing.T) {
	srv := newWrappingMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := vault.NewWrappingChecker(srv.Client(), srv.URL, "root")
	_, err := checker.LookupWrappingToken(context.Background(), "s.expired")
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
}
