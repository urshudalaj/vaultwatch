package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newGCPMockServer(t *testing.T, status int, payload any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newGCPAPIClient(base string) *GCPChecker {
	return NewGCPChecker(base, "test-token", nil)
}

func TestGetRoleset_ReturnsInfo(t *testing.T) {
	payload := map[string]any{
		"data": map[string]any{
			"name":        "my-roleset",
			"secret_type": "access_token",
			"project":     "my-gcp-project",
			"ttl":         "1h",
			"max_ttl":     "24h",
		},
	}
	srv := newGCPMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	checker := newGCPAPIClient(srv.URL)
	info, err := checker.GetRoleset("gcp", "my-roleset")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name != "my-roleset" {
		t.Errorf("expected name 'my-roleset', got %q", info.Name)
	}
	if info.Project != "my-gcp-project" {
		t.Errorf("expected project 'my-gcp-project', got %q", info.Project)
	}
	if info.TTL != "1h" {
		t.Errorf("expected TTL '1h', got %q", info.TTL)
	}
}

func TestGetRoleset_ErrorOnEmptyMountOrRole(t *testing.T) {
	checker := newGCPAPIClient("http://localhost")

	if _, err := checker.GetRoleset("", "role"); err == nil {
		t.Error("expected error for empty mount")
	}
	if _, err := checker.GetRoleset("gcp", ""); err == nil {
		t.Error("expected error for empty roleset")
	}
}

func TestGetRoleset_ErrorOnBadStatus(t *testing.T) {
	srv := newGCPMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := newGCPAPIClient(srv.URL)
	_, err := checker.GetRoleset("gcp", "my-roleset")
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
}
