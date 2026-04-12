package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newQuotaMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/sys/quotas/rate-limit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"keys": []string{"global-limit", "api-limit"},
			},
		})
	})

	mux.HandleFunc("/v1/sys/quotas/rate-limit/global-limit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"name":     "global-limit",
				"path":     "",
				"type":     "rate-limit",
				"rate":     1000.0,
				"interval": 1.0,
			},
		})
	})

	return httptest.NewServer(mux)
}

func TestListQuotas_ReturnsNames(t *testing.T) {
	srv := newQuotaMockServer(t)
	defer srv.Close()

	checker := NewQuotaChecker(srv.URL, "test-token", srv.Client())
	names, err := checker.ListQuotas(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 quota names, got %d", len(names))
	}
	if names[0] != "global-limit" {
		t.Errorf("expected global-limit, got %s", names[0])
	}
}

func TestGetQuota_ReturnsInfo(t *testing.T) {
	srv := newQuotaMockServer(t)
	defer srv.Close()

	checker := NewQuotaChecker(srv.URL, "test-token", srv.Client())
	info, err := checker.GetQuota(context.Background(), "global-limit")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name != "global-limit" {
		t.Errorf("expected global-limit, got %s", info.Name)
	}
	if info.MaxRequests != 1000.0 {
		t.Errorf("expected rate 1000, got %f", info.MaxRequests)
	}
}

func TestGetQuota_ErrorOnEmptyName(t *testing.T) {
	checker := NewQuotaChecker("http://localhost", "tok", nil)
	_, err := checker.GetQuota(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestListQuotas_ErrorOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	checker := NewQuotaChecker(srv.URL, "bad-token", srv.Client())
	_, err := checker.ListQuotas(context.Background())
	if err == nil {
		t.Fatal("expected error on 403 response")
	}
}
