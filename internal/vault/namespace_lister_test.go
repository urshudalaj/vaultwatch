package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

func newNamespaceMockServer(t *testing.T, status int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/namespaces" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func TestListNamespaces_ReturnsNamespaces(t *testing.T) {
	body := map[string]interface{}{
		"data": map[string]interface{}{
			"ns1/": map[string]string{"id": "abc123"},
			"ns2/": map[string]string{"id": "def456"},
		},
	}
	srv := newNamespaceMockServer(t, http.StatusOK, body)
	defer srv.Close()

	lister := vault.NewNamespaceLister(srv.Client(), srv.URL, "test-token")
	namespaces, err := lister.ListNamespaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(namespaces) != 2 {
		t.Errorf("expected 2 namespaces, got %d", len(namespaces))
	}
	paths := make(map[string]string)
	for _, ns := range namespaces {
		paths[ns.Path] = ns.ID
	}
	if paths["ns1/"] != "abc123" {
		t.Errorf("expected ns1/ id abc123, got %s", paths["ns1/"])
	}
	if paths["ns2/"] != "def456" {
		t.Errorf("expected ns2/ id def456, got %s", paths["ns2/"])
	}
}

func TestListNamespaces_ErrorOnBadStatus(t *testing.T) {
	srv := newNamespaceMockServer(t, http.StatusForbidden, map[string]string{"errors": "permission denied"})
	defer srv.Close()

	lister := vault.NewNamespaceLister(srv.Client(), srv.URL, "bad-token")
	_, err := lister.ListNamespaces()
	if err == nil {
		t.Fatal("expected error on forbidden status, got nil")
	}
}

func TestListNamespaces_EmptyData(t *testing.T) {
	body := map[string]interface{}{"data": map[string]interface{}{}}
	srv := newNamespaceMockServer(t, http.StatusOK, body)
	defer srv.Close()

	lister := vault.NewNamespaceLister(srv.Client(), srv.URL, "test-token")
	namespaces, err := lister.ListNamespaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(namespaces) != 0 {
		t.Errorf("expected 0 namespaces, got %d", len(namespaces))
	}
}
