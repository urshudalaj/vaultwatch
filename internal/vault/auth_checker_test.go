package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/your-org/vaultwatch/internal/vault"
)

func newAuthMockServer(t *testing.T, payload map[string]interface{}, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": payload})
	}))
}

func newAuthAPIClient(t *testing.T, addr string) *vaultapi.Client {
	t.Helper()
	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	c, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create vault client: %v", err)
	}
	c.SetToken("test-token")
	return c
}

func TestCheck_ReturnsAuthInfo(t *testing.T) {
	expire := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	srv := newAuthMockServer(t, map[string]interface{}{
		"id":          "test-token",
		"renewable":   true,
		"policies":    []interface{}{"default", "admin"},
		"expire_time": expire,
	}, http.StatusOK)
	defer srv.Close()

	checker := vault.NewAuthChecker(newAuthAPIClient(t, srv.URL))
	info, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.TokenID != "test-token" {
		t.Errorf("expected token id 'test-token', got %q", info.TokenID)
	}
	if !info.Renewable {
		t.Error("expected renewable to be true")
	}
	if len(info.Policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(info.Policies))
	}
	if info.ExpireTime.IsZero() {
		t.Error("expected non-zero expire time")
	}
}

func TestCheck_ErrorOnExpiredToken(t *testing.T) {
	expire := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	srv := newAuthMockServer(t, map[string]interface{}{
		"id":          "old-token",
		"renewable":   false,
		"expire_time": expire,
	}, http.StatusOK)
	defer srv.Close()

	checker := vault.NewAuthChecker(newAuthAPIClient(t, srv.URL))
	_, err := checker.Check(context.Background())
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestCheck_ErrorOnHTTPFailure(t *testing.T) {
	srv := newAuthMockServer(t, nil, http.StatusForbidden)
	defer srv.Close()

	checker := vault.NewAuthChecker(newAuthAPIClient(t, srv.URL))
	_, err := checker.Check(context.Background())
	if err == nil {
		t.Fatal("expected error on non-200 response, got nil")
	}
}
