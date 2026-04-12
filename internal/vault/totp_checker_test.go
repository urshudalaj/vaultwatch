package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTOTPMockServer(t *testing.T, status int, payload any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newTOTPAPIClient(srv *httptest.Server) *TOTPChecker {
	return NewTOTPChecker(srv.URL, "test-token", srv.Client())
}

func TestGetTOTPKey_ReturnsInfo(t *testing.T) {
	payload := map[string]any{
		"data": map[string]any{
			"account_name": "user@example.com",
			"issuer":       "MyApp",
			"period":       30,
			"digits":       6,
			"algorithm":    "SHA1",
		},
	}
	srv := newTOTPMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := newTOTPAPIClient(srv)
	key, err := checker.GetKey("totp", "mykey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key.AccountName != "user@example.com" {
		t.Errorf("expected account_name 'user@example.com', got %q", key.AccountName)
	}
	if key.Period != 30 {
		t.Errorf("expected period 30, got %d", key.Period)
	}
	if key.Algorithm != "SHA1" {
		t.Errorf("expected algorithm 'SHA1', got %q", key.Algorithm)
	}
}

func TestGetTOTPKey_ErrorOnEmptyMountOrKey(t *testing.T) {
	checker := NewTOTPChecker("http://localhost", "tok", nil)
	if _, err := checker.GetKey("", "key"); err == nil {
		t.Error("expected error for empty mount")
	}
	if _, err := checker.GetKey("totp", ""); err == nil {
		t.Error("expected error for empty keyName")
	}
}

func TestGetTOTPKey_ErrorOnBadStatus(t *testing.T) {
	srv := newTOTPMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := newTOTPAPIClient(srv)
	if _, err := checker.GetKey("totp", "mykey"); err == nil {
		t.Error("expected error on 403 status")
	}
}
