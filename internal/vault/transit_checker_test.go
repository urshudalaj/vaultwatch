package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTransitMockServer(t *testing.T, status int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestGetTransitKey_ReturnsInfo(t *testing.T) {
	body := map[string]interface{}{
		"data": map[string]interface{}{
			"name":                "my-key",
			"type":                "aes256-gcm96",
			"deletion_allowed":    false,
			"exportable":          true,
			"min_decryption_version": 1,
			"latest_version":      3,
		},
	}
	srv := newTransitMockServer(t, http.StatusOK, body)
	defer srv.Close()

	checker := NewTransitChecker(srv.Client(), srv.URL, "test-token")
	info, err := checker.GetKey(context.Background(), "transit", "my-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name != "my-key" {
		t.Errorf("expected name my-key, got %s", info.Name)
	}
	if info.Type != "aes256-gcm96" {
		t.Errorf("expected type aes256-gcm96, got %s", info.Type)
	}
	if info.LatestVersion != 3 {
		t.Errorf("expected latest version 3, got %d", info.LatestVersion)
	}
	if !info.Exportable {
		t.Error("expected exportable to be true")
	}
}

func TestGetTransitKey_ErrorOnEmptyMountOrKey(t *testing.T) {
	checker := NewTransitChecker(http.DefaultClient, "http://localhost", "tok")
	_, err := checker.GetKey(context.Background(), "", "my-key")
	if err == nil {
		t.Error("expected error for empty mount")
	}
	_, err = checker.GetKey(context.Background(), "transit", "")
	if err == nil {
		t.Error("expected error for empty key name")
	}
}

func TestGetTransitKey_ErrorOnBadStatus(t *testing.T) {
	srv := newTransitMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := NewTransitChecker(srv.Client(), srv.URL, "bad-token")
	_, err := checker.GetKey(context.Background(), "transit", "my-key")
	if err == nil {
		t.Error("expected error on non-200 status")
	}
}
