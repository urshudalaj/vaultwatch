package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newAuthMethodMockServer(t *testing.T, status int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func newAuthMethodAPIClient(srv *httptest.Server) *AuthMethodChecker {
	return NewAuthMethodChecker(srv.URL, "test-token", srv.Client())
}

func TestListAuthMethods_ReturnsMethods(t *testing.T) {
	body := map[string]interface{}{
		"data": map[string]interface{}{
			"token/": map[string]interface{}{
				"type":        "token",
				"description": "token based credentials",
				"accessor":    "auth_token_abc123",
				"local":       false,
				"seal_wrap":   false,
			},
			"approle/": map[string]interface{}{
				"type":        "approle",
				"description": "approle auth",
				"accessor":    "auth_approle_xyz",
				"local":       false,
				"seal_wrap":   false,
			},
		},
	}
	srv := newAuthMethodMockServer(t, http.StatusOK, body)
	defer srv.Close()

	checker := newAuthMethodAPIClient(srv)
	methods, err := checker.ListAuthMethods()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(methods))
	}
	if methods["token/"].Type != "token" {
		t.Errorf("expected token type, got %q", methods["token/"].Type)
	}
	if methods["approle/"].Accessor != "auth_approle_xyz" {
		t.Errorf("expected accessor auth_approle_xyz, got %q", methods["approle/"].Accessor)
	}
}

func TestListAuthMethods_ErrorOnBadStatus(t *testing.T) {
	srv := newAuthMethodMockServer(t, http.StatusInternalServerError, nil)
	defer srv.Close()

	checker := newAuthMethodAPIClient(srv)
	_, err := checker.ListAuthMethods()
	if err == nil {
		t.Fatal("expected error on bad status, got nil")
	}
}

func TestListAuthMethods_EmptyData(t *testing.T) {
	body := map[string]interface{}{"data": nil}
	srv := newAuthMethodMockServer(t, http.StatusOK, body)
	defer srv.Close()

	checker := newAuthMethodAPIClient(srv)
	methods, err := checker.ListAuthMethods()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 0 {
		t.Errorf("expected empty map, got %d entries", len(methods))
	}
}
