package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newSSHMockServer(t *testing.T, mount, role string, payload interface{}, status int) *httptest.Server {
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

func TestGetRole_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]string{
			"key_type":      "ca",
			"ttl":           "30m",
			"max_ttl":       "1h",
			"allowed_users": "ubuntu",
		},
	}
	srv := newSSHMockServer(t, "ssh", "my-role", payload, http.StatusOK)
	defer srv.Close()

	checker := NewSSHChecker(srv.URL, "test-token", srv.Client())
	info, err := checker.GetRole("ssh", "my-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.KeyType != "ca" {
		t.Errorf("expected key_type=ca, got %s", info.KeyType)
	}
	if info.TTL != "30m" {
		t.Errorf("expected ttl=30m, got %s", info.TTL)
	}
	if info.Mount != "ssh" {
		t.Errorf("expected mount=ssh, got %s", info.Mount)
	}
	if info.Role != "my-role" {
		t.Errorf("expected role=my-role, got %s", info.Role)
	}
}

func TestGetRole_ErrorOnEmptyMountOrRole(t *testing.T) {
	checker := NewSSHChecker("http://localhost", "tok", nil)
	if _, err := checker.GetRole("", "role"); err == nil {
		t.Error("expected error on empty mount")
	}
	if _, err := checker.GetRole("mount", ""); err == nil {
		t.Error("expected error on empty role")
	}
}

func TestGetRole_ErrorOnBadStatus(t *testing.T) {
	srv := newSSHMockServer(t, "ssh", "bad-role", nil, http.StatusForbidden)
	defer srv.Close()

	checker := NewSSHChecker(srv.URL, "tok", srv.Client())
	_, err := checker.GetRole("ssh", "bad-role")
	if err == nil {
		t.Error("expected error on non-200 status")
	}
}
