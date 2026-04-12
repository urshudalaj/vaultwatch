package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newOktaMockServer(t *testing.T, mount, role string, payload interface{}, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/v1/auth/" + mount + "/groups/" + role
		if r.URL.Path != expected {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func newOktaAPIClient(t *testing.T, base string) *OktaChecker {
	t.Helper()
	return NewOktaChecker(base, "test-token", nil)
}

func TestGetOktaRole_ReturnsInfo(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"policies": []string{"default"},
			"ttl":      "1h",
			"max_ttl":  "24h",
		},
	}
	ts := newOktaMockServer(t, "okta", "dev-team", payload, http.StatusOK)
	defer ts.Close()

	checker := newOktaAPIClient(t, ts.URL)
	role, err := checker.GetOktaRole("okta", "dev-team")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.TTL != "1h" {
		t.Errorf("expected TTL '1h', got %q", role.TTL)
	}
	if role.MaxTTL != "24h" {
		t.Errorf("expected MaxTTL '24h', got %q", role.MaxTTL)
	}
	if role.Mount != "okta" || role.Name != "dev-team" {
		t.Errorf("mount/name not populated correctly")
	}
}

func TestGetOktaRole_ErrorOnEmptyMountOrRole(t *testing.T) {
	checker := NewOktaChecker("http://localhost", "tok", nil)
	if _, err := checker.GetOktaRole("", "role"); err == nil {
		t.Error("expected error for empty mount")
	}
	if _, err := checker.GetOktaRole("mount", ""); err == nil {
		t.Error("expected error for empty role")
	}
}

func TestGetOktaRole_ErrorOnBadStatus(t *testing.T) {
	ts := newOktaMockServer(t, "okta", "bad-role", nil, http.StatusForbidden)
	defer ts.Close()

	checker := newOktaAPIClient(t, ts.URL)
	if _, err := checker.GetOktaRole("okta", "bad-role"); err == nil {
		t.Error("expected error for non-200 status")
	}
}
