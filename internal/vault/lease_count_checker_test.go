package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newLeaseCountMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestGetLeaseCount_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"lease_count": 42,
			"counts": map[string]int{
				"secret/": 20,
				"database/": 22,
			},
		},
	}
	srv := newLeaseCountMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := NewLeaseCountChecker(srv.URL, "test-token", srv.Client())
	info, err := checker.GetLeaseCount()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.LeaseCount != 42 {
		t.Errorf("expected lease_count 42, got %d", info.LeaseCount)
	}
	if info.CountPerMount["secret/"] != 20 {
		t.Errorf("expected secret/ count 20, got %d", info.CountPerMount["secret/"])
	}
}

func TestGetLeaseCount_ErrorOnBadStatus(t *testing.T) {
	srv := newLeaseCountMockServer(t, http.StatusInternalServerError, nil)
	defer srv.Close()

	checker := NewLeaseCountChecker(srv.URL, "test-token", srv.Client())
	_, err := checker.GetLeaseCount()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetLeaseCount_ErrorOnInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	checker := NewLeaseCountChecker(srv.URL, "test-token", srv.Client())
	_, err := checker.GetLeaseCount()
	if err == nil {
		t.Fatal("expected error on invalid JSON, got nil")
	}
}
