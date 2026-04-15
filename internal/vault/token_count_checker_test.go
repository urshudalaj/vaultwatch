package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/watcher/vaultwatch/internal/vault"
)

func newTokenCountMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			http.Error(w, "missing token", http.StatusForbidden)
			return
		}
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newTokenCountAPIClient(baseURL string) *vault.TokenCountChecker {
	return vault.NewTokenCountChecker(baseURL, "test-token", nil)
}

func TestGetTokenCount_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"service_tokens": 42,
			"batch_tokens":   8,
		},
	}
	srv := newTokenCountMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := newTokenCountAPIClient(srv.URL)
	info, err := checker.GetTokenCount()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ServiceTokens != 42 {
		t.Errorf("expected ServiceTokens=42, got %d", info.ServiceTokens)
	}
	if info.BatchTokens != 8 {
		t.Errorf("expected BatchTokens=8, got %d", info.BatchTokens)
	}
	if info.Total != 50 {
		t.Errorf("expected Total=50, got %d", info.Total)
	}
}

func TestGetTokenCount_ErrorOnBadStatus(t *testing.T) {
	srv := newTokenCountMockServer(t, http.StatusInternalServerError, nil)
	defer srv.Close()

	checker := newTokenCountAPIClient(srv.URL)
	_, err := checker.GetTokenCount()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetTokenCount_ErrorOnInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	checker := newTokenCountAPIClient(srv.URL)
	_, err := checker.GetTokenCount()
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
}
