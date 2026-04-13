package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newEnginesMockServer(t *testing.T, status int, body interface{}) *httptest.Server {
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

func newEnginesAPIClient(srv *httptest.Server) *EnginesChecker {
	return NewEnginesChecker(srv.URL, "test-token", srv.Client())
}

func TestListEngines_ReturnsEngines(t *testing.T) {
	body := map[string]interface{}{
		"secret/": map[string]interface{}{
			"type":        "kv",
			"description": "key/value store",
			"options":     map[string]string{"version": "2"},
		},
		"pki/": map[string]interface{}{
			"type":        "pki",
			"description": "PKI engine",
			"options":     map[string]string{},
		},
	}
	srv := newEnginesMockServer(t, http.StatusOK, body)
	defer srv.Close()

	checker := newEnginesAPIClient(srv)
	engines, err := checker.ListEngines()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(engines) != 2 {
		t.Fatalf("expected 2 engines, got %d", len(engines))
	}
}

func TestListEngines_ErrorOnBadStatus(t *testing.T) {
	srv := newEnginesMockServer(t, http.StatusInternalServerError, nil)
	defer srv.Close()

	checker := newEnginesAPIClient(srv)
	_, err := checker.ListEngines()
	if err == nil {
		t.Fatal("expected error on bad status, got nil")
	}
}

func TestListEngines_SkipsEntriesWithoutType(t *testing.T) {
	body := map[string]interface{}{
		"secret/": map[string]interface{}{
			"type":        "kv",
			"description": "key/value store",
		},
		"empty/": map[string]interface{}{
			"type":        "",
			"description": "no type",
		},
	}
	srv := newEnginesMockServer(t, http.StatusOK, body)
	defer srv.Close()

	checker := newEnginesAPIClient(srv)
	engines, err := checker.ListEngines()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(engines) != 1 {
		t.Fatalf("expected 1 engine after skipping empty type, got %d", len(engines))
	}
	if engines[0].Type != "kv" {
		t.Errorf("expected type kv, got %s", engines[0].Type)
	}
}
