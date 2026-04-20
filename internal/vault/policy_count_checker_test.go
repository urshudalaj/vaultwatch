package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newPolicyCountMockServer(t *testing.T, status int, keys []string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": keys,
			},
		})
	}))
}

func newPolicyCountAPIClient(srv *httptest.Server) *PolicyCountChecker {
	return NewPolicyCountChecker(srv.URL, "test-token", srv.Client())
}

func TestCountPolicies_ReturnsInfo(t *testing.T) {
	keys := []string{"default", "root", "admin"}
	srv := newPolicyCountMockServer(t, http.StatusOK, keys)
	defer srv.Close()

	checker := newPolicyCountAPIClient(srv)
	info, err := checker.CountPolicies()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Count != 3 {
		t.Errorf("expected count 3, got %d", info.Count)
	}
	if len(info.Names) != 3 {
		t.Errorf("expected 3 names, got %d", len(info.Names))
	}
}

func TestCountPolicies_ErrorOnBadStatus(t *testing.T) {
	srv := newPolicyCountMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	checker := newPolicyCountAPIClient(srv)
	_, err := checker.CountPolicies()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCountPolicies_EmptyKeys(t *testing.T) {
	srv := newPolicyCountMockServer(t, http.StatusOK, []string{})
	defer srv.Close()

	checker := newPolicyCountAPIClient(srv)
	info, err := checker.CountPolicies()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Count != 0 {
		t.Errorf("expected count 0, got %d", info.Count)
	}
}
