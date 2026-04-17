package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newStepDownMockServer(t *testing.T, status int, payload any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestCheckLeaderSelf_ReturnsInfo(t *testing.T) {
	payload := map[string]any{
		"cluster_id":     "abc-123",
		"cluster_name":   "vault-cluster",
		"leader_address": "https://vault.example.com",
		"is_self":        true,
	}
	srv := newStepDownMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := NewStepDownChecker(srv.URL, "test-token", srv.Client())
	info, err := checker.CheckLeaderSelf(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ClusterID != "abc-123" {
		t.Errorf("expected cluster_id abc-123, got %s", info.ClusterID)
	}
	if !info.IsSelf {
		t.Error("expected is_self to be true")
	}
}

func TestCheckLeaderSelf_ErrorOnBadStatus(t *testing.T) {
	srv := newStepDownMockServer(t, http.StatusInternalServerError, nil)
	defer srv.Close()

	checker := NewStepDownChecker(srv.URL, "test-token", srv.Client())
	_, err := checker.CheckLeaderSelf(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCheckLeaderSelf_ErrorOnInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid`))
	}))
	defer srv.Close()

	checker := NewStepDownChecker(srv.URL, "test-token", srv.Client())
	_, err := checker.CheckLeaderSelf(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
