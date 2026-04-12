package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newTokenCheckerMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/lookup-self" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestTokenChecker_LookupSelf_ReturnsInfo(t *testing.T) {
	expire := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"id":           "tok-abc",
			"display_name": "test-token",
			"policies":     []string{"default"},
			"expire_time":  expire,
			"renewable":    true,
			"ttl":          3600,
		},
	}
	srv := newTokenCheckerMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := vault.NewTokenChecker(srv.Client(), srv.URL, "test-token")
	info, err := checker.LookupSelf(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ID != "tok-abc" {
		t.Errorf("expected ID tok-abc, got %s", info.ID)
	}
	if info.TTL != 3600 {
		t.Errorf("expected TTL 3600, got %d", info.TTL)
	}
	if !info.Renewable {
		t.Error("expected renewable to be true")
	}
}

func TestTokenChecker_LookupSelf_ErrorOnBadStatus(t *testing.T) {
	srv := newTokenCheckerMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := vault.NewTokenChecker(srv.Client(), srv.URL, "bad-token")
	_, err := checker.LookupSelf(context.Background())
	if err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}

func TestTokenChecker_LookupSelf_EmptyExpireTime(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"id":           "tok-root",
			"display_name": "root",
			"policies":     []string{"root"},
			"expire_time":  "",
			"renewable":    false,
			"ttl":          0,
		},
	}
	srv := newTokenCheckerMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := vault.NewTokenChecker(srv.Client(), srv.URL, "root")
	info, err := checker.LookupSelf(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.ExpireTime.IsZero() {
		t.Errorf("expected zero expire time for root token, got %v", info.ExpireTime)
	}
}
