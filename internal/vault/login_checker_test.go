package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newLoginMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/auth/userpass/accessors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"keys": []string{"abc123", "def456"},
			},
		})
	})

	mux.HandleFunc("/v1/auth/token/lookup-accessor", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"accessor": "abc123",
				"path":     "auth/userpass/login",
				"meta":     map[string]string{"username": "alice"},
			},
		})
	})

	return httptest.NewServer(mux)
}

func newLoginAPIClient(baseURL string) *LoginChecker {
	return NewLoginChecker(http.DefaultClient, baseURL, "test-token")
}

func TestListLogins_ReturnsRecords(t *testing.T) {
	srv := newLoginMockServer(t)
	defer srv.Close()

	checker := newLoginAPIClient(srv.URL)
	records, err := checker.ListLogins(context.Background(), "userpass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 2 {
		t.Errorf("expected 2 records, got %d", len(records))
	}
	if records[0].Path != "auth/userpass/login" {
		t.Errorf("unexpected path: %q", records[0].Path)
	}
}

func TestListLogins_ErrorOnBadMount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	checker := newLoginAPIClient(srv.URL)
	_, err := checker.ListLogins(context.Background(), "badmount")
	if err == nil {
		t.Fatal("expected error for forbidden mount, got nil")
	}
}

func TestListLogins_EmptyAccessors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"keys": []string{}},
		})
	}))
	defer srv.Close()

	checker := newLoginAPIClient(srv.URL)
	records, err := checker.ListLogins(context.Background(), "userpass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}
