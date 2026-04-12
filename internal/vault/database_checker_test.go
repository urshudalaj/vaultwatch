package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newDatabaseMockServer(t *testing.T, mount, role string, payload interface{}, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/v1/" + mount + "/roles/" + role
		if r.URL.Path != expected {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestGetRole_Database_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"default_ttl":        3600,
			"max_ttl":            86400,
			"creation_statements": []string{"CREATE USER ..."},
		},
	}
	srv := newDatabaseMockServer(t, "database", "readonly", payload, http.StatusOK)
	defer srv.Close()

	checker := NewDatabaseChecker(srv.URL, "test-token", nil)
	role, err := checker.GetRole("database", "readonly")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.DefaultTTL != 3600 {
		t.Errorf("expected DefaultTTL 3600, got %d", role.DefaultTTL)
	}
	if role.MaxTTL != 86400 {
		t.Errorf("expected MaxTTL 86400, got %d", role.MaxTTL)
	}
	if role.Mount != "database" || role.Role != "readonly" {
		t.Errorf("mount/role not populated correctly: %s/%s", role.Mount, role.Role)
	}
}

func TestGetRole_Database_ErrorOnEmptyMountOrRole(t *testing.T) {
	checker := NewDatabaseChecker("http://localhost", "tok", nil)
	if _, err := checker.GetRole("", "readonly"); err == nil {
		t.Error("expected error for empty mount")
	}
	if _, err := checker.GetRole("database", ""); err == nil {
		t.Error("expected error for empty role")
	}
}

func TestGetRole_Database_ErrorOnBadStatus(t *testing.T) {
	srv := newDatabaseMockServer(t, "database", "readonly", nil, http.StatusForbidden)
	defer srv.Close()

	checker := NewDatabaseChecker(srv.URL, "bad-token", nil)
	if _, err := checker.GetRole("database", "readonly"); err == nil {
		t.Error("expected error on 403 status")
	}
}
