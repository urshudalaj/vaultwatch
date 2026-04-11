package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newSnapshotMockServer(t *testing.T, status int, payload any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestCheckSnapshot_ReturnsInfo(t *testing.T) {
	body := map[string]any{
		"data": map[string]any{
			"config": map[string]any{
				"commit_index": 42,
				"term":         3,
			},
		},
	}
	srv := newSnapshotMockServer(t, http.StatusOK, body)
	defer srv.Close()

	checker := NewSnapshotChecker(srv.URL, "test-token", srv.Client())
	info, err := checker.CheckSnapshot(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Index != 42 {
		t.Errorf("expected index 42, got %d", info.Index)
	}
	if info.Term != 3 {
		t.Errorf("expected term 3, got %d", info.Term)
	}
}

func TestCheckSnapshot_ErrorOnBadStatus(t *testing.T) {
	srv := newSnapshotMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := NewSnapshotChecker(srv.URL, "bad-token", srv.Client())
	_, err := checker.CheckSnapshot(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCheckSnapshot_ErrorOnInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	checker := NewSnapshotChecker(srv.URL, "tok", srv.Client())
	_, err := checker.CheckSnapshot(context.Background())
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
}
