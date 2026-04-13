package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newRGPMockServer(t *testing.T, name string, policy RGPPolicy, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		if statusCode == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": policy})
		}
	}))
}

func newRGPAPIClient(base string) *RGPChecker {
	return NewRGPChecker(base, "test-token", nil)
}

func TestGetRGP_ReturnsInfo(t *testing.T) {
	expected := RGPPolicy{
		Name:             "prod-policy",
		Policy:           `main = rule { true }`,
		EnforcementLevel: "hard-mandatory",
	}
	srv := newRGPMockServer(t, "prod-policy", expected, http.StatusOK)
	defer srv.Close()

	checker := newRGPAPIClient(srv.URL)
	got, err := checker.GetRGP("prod-policy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != expected.Name {
		t.Errorf("name: got %q, want %q", got.Name, expected.Name)
	}
	if got.EnforcementLevel != expected.EnforcementLevel {
		t.Errorf("enforcement_level: got %q, want %q", got.EnforcementLevel, expected.EnforcementLevel)
	}
}

func TestGetRGP_ErrorOnEmptyName(t *testing.T) {
	checker := newRGPAPIClient("http://localhost")
	_, err := checker.GetRGP("")
	if err == nil {
		t.Fatal("expected error for empty name, got nil")
	}
}

func TestGetRGP_ErrorOnBadStatus(t *testing.T) {
	srv := newRGPMockServer(t, "missing", RGPPolicy{}, http.StatusForbidden)
	defer srv.Close()

	checker := newRGPAPIClient(srv.URL)
	_, err := checker.GetRGP("missing")
	if err == nil {
		t.Fatal("expected error for non-200 status, got nil")
	}
}
